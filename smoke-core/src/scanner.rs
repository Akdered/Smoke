use crate::desync::{send_desync, SplitStrategy};
use crate::dns::DnsResolver;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Автоматически тестирует стратегии параллельно и возвращает самую быструю рабочую
pub async fn auto_select_strategy(dns: &DnsResolver) -> SplitStrategy {
    let test_domains = ["www.youtube.com", "googlevideo.com", "discord.com"];

    let mut target_info = None;
    for &domain in &test_domains {
        info!("Автоподбор: проверка DNS для {}...", domain);
        if let Ok(addr) = dns.resolve(domain, 443).await {
            target_info = Some((domain, addr));
            break;
        }
    }

    let (test_domain, target_addr) = match target_info {
        Some(info) => info,
        None => {
            warn!("Не удалось разрешить тестовые домены — включен агрессивный режим TlsRecordFrag");
            return SplitStrategy::TlsRecordFrag;
        }
    };

    info!("Тестируем стратегии на {} ({})...", test_domain, target_addr);

    // Порядок кандидатов: от самого агрессивного к простому.
    // FakeTtl ИСКЛЮЧЕНА — она ломает TCP-поток (retransmit доставляет фейк серверу).
    let candidates = [
        ("TlsRecordFrag", SplitStrategy::TlsRecordFrag),
        ("TlsRecordFrag2", SplitStrategy::TlsRecordFrag2),
        ("Disorder1", SplitStrategy::Disorder1),
        ("TcpSplitSni", SplitStrategy::TcpSplitSni),
        ("OobSni", SplitStrategy::OobSni),
        ("TlsRecordFragSni", SplitStrategy::TlsRecordFragSni),
        ("Combo", SplitStrategy::Combo),
        ("TcpSplit2", SplitStrategy::TcpSplit2),
    ];

    let client_hello = build_test_client_hello(test_domain);
    let mut set = JoinSet::new();

    for (label, strat) in candidates {
        let packet = client_hello.clone();
        let label = label.to_string();
        set.spawn(async move {
            let start = Instant::now();
            match timeout(
                Duration::from_millis(3000),
                probe_strategy(target_addr, &packet, strat),
            )
            .await
            {
                Ok(Ok(())) => {
                    let elapsed = start.elapsed();
                    debug!("✓ Стратегия {} прошла за {:?}", label, elapsed);
                    Some((strat, elapsed))
                }
                Ok(Err(e)) => {
                    debug!("✗ Стратегия {} не прошла: {}", label, e);
                    None
                }
                Err(_) => {
                    debug!("✗ Стратегия {} — таймаут", label);
                    None
                }
            }
        });
    }

    let mut best: Option<(SplitStrategy, Duration)> = None;
    while let Some(Ok(result)) = set.join_next().await {
        if let Some((strat, elapsed)) = result {
            if best.map_or(true, |(_, best_time)| elapsed < best_time) {
                best = Some((strat, elapsed));
            }
        }
    }

    match best {
        Some((winner, time)) => {
            info!("✓ Выбрана лучшая стратегия: {:?} (отклик {:?})", winner, time);
            winner
        }
        None => {
            warn!(
                "Ни одна стратегия не прошла зонд на {} — ТСПУ блокирует жёстко. \
                 Включен режим TlsRecordFrag (максимальная фрагментация).",
                test_domain
            );
            SplitStrategy::TlsRecordFrag
        }
    }
}

async fn probe_strategy(
    addr: SocketAddr,
    hello_packet: &[u8],
    strategy: SplitStrategy,
) -> std::io::Result<()> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(10035) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }

    let mut stream = TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    if let Some(err) = stream.take_error()? {
        return Err(err);
    }

    send_desync(&mut stream, hello_packet, strategy).await?;

    // Читаем первые 5 байт ответа: если сервер вернул TLS Handshake (0x16 0x03) — DPI пробит!
    let mut resp = [0u8; 5];
    stream.read_exact(&mut resp).await?;

    if *resp.first().unwrap_or(&0) == 0x16 && *resp.get(1).unwrap_or(&0) == 0x03 {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Ответ не является TLS ServerHello",
        ))
    }
}

/// Собирает компактный валидный пакет TLS 1.2 ClientHello с расширением SNI и ECDHE шифрами
pub fn build_test_client_hello(domain: &str) -> Vec<u8> {
    let name_bytes = domain.as_bytes();
    let name_len = name_bytes.len() as u16;

    // 1. Расширение SNI (0x0000)
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
    sni_ext.extend_from_slice(&(name_len + 5).to_be_bytes());
    sni_ext.extend_from_slice(&(name_len + 3).to_be_bytes());
    sni_ext.push(0x00); // HostName
    sni_ext.extend_from_slice(&name_len.to_be_bytes());
    sni_ext.extend_from_slice(name_bytes);

    // 2. Расширение Supported Groups (0x000a): X25519 (0x001d), secp256r1 (0x0017)
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&0x000au16.to_be_bytes());
    groups_ext.extend_from_slice(&6u16.to_be_bytes()); // ext len
    groups_ext.extend_from_slice(&4u16.to_be_bytes()); // list len
    groups_ext.extend_from_slice(&[0x00, 0x1d, 0x00, 0x17]);

    // 3. Расширение EC Point Formats (0x000b): uncompressed (0x00)
    let mut ec_points_ext = Vec::new();
    ec_points_ext.extend_from_slice(&0x000bu16.to_be_bytes());
    ec_points_ext.extend_from_slice(&2u16.to_be_bytes()); // ext len
    ec_points_ext.extend_from_slice(&[0x01, 0x00]);

    // 4. Расширение Signature Algorithms (0x000d)
    let mut sig_ext = Vec::new();
    sig_ext.extend_from_slice(&0x000du16.to_be_bytes());
    sig_ext.extend_from_slice(&8u16.to_be_bytes()); // ext len
    sig_ext.extend_from_slice(&6u16.to_be_bytes()); // list len
    sig_ext.extend_from_slice(&[0x08, 0x04, 0x04, 0x03, 0x04, 0x01]);

    // Все расширения
    let mut all_exts = Vec::new();
    all_exts.extend_from_slice(&sni_ext);
    all_exts.extend_from_slice(&groups_ext);
    all_exts.extend_from_slice(&ec_points_ext);
    all_exts.extend_from_slice(&sig_ext);

    // Тело ClientHello
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    body.extend_from_slice(&[0x42; 32]); // Random 32 байта
    body.push(0x00); // Session ID length = 0

    // Стандартные шифрокомплекты ECDHE TLS 1.2 (поддерживаются всеми серверами Google/Cloudflare):
    // 0xc02b: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    // 0xc02f: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    // 0xc030: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    // 0x009c: TLS_RSA_WITH_AES_128_GCM_SHA256
    let ciphers = [
        0xc0, 0x2b,
        0xc0, 0x2f,
        0xc0, 0x30,
        0x00, 0x9c,
    ];
    body.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    body.extend_from_slice(&ciphers);

    body.extend_from_slice(&[0x01, 0x00]); // Compression: null

    body.extend_from_slice(&(all_exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&all_exts);

    // Заголовок Handshake (ClientHello = 0x01)
    let body_len = body.len() as u32;
    let body_len_be = body_len.to_be_bytes();
    let mut handshake = Vec::new();
    handshake.push(0x01);
    if let Some(len24) = body_len_be.get(1..4) {
        handshake.extend_from_slice(len24);
    }
    handshake.extend_from_slice(&body);

    // Заголовок TLS Record (0x16 = Handshake, 0x03, 0x01 = TLS 1.0 для совместимости)
    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}
