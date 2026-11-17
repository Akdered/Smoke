use crate::desync::{send_desync, SplitStrategy};
use crate::dns::DnsResolver;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info};

/// Автоматически тестирует стратегии параллельно и возвращает самую быструю рабочую
pub async fn auto_select_strategy(dns: &DnsResolver) -> SplitStrategy {
    let test_domain = "www.youtube.com";
    info!("Автоподбор оптимальной стратегии для сети ({})...", test_domain);

    let target_addr = match dns.resolve(test_domain, 443).await {
        Ok(addr) => addr,
        Err(_) => {
            info!("Не удалось разрешить тестовый домен, выбран режим TlsRecordAndSni");
            return SplitStrategy::TlsRecordAndSni;
        }
    };

    let candidates = [
        SplitStrategy::TlsRecordAndSni,
        SplitStrategy::SniMiddle { fallback_pos: 2 },
        SplitStrategy::SniMiddle { fallback_pos: 1 },
    ];

    let client_hello = build_test_client_hello(test_domain);
    let mut set = JoinSet::new();

    for strat in candidates {
        let packet = client_hello.clone();
        set.spawn(async move {
            let start = Instant::now();
            match timeout(
                Duration::from_millis(1800),
                probe_strategy(target_addr, &packet, strat),
            )
            .await
            {
                Ok(Ok(())) => Some((strat, start.elapsed())),
                _ => None,
            }
        });
    }

    let mut best: Option<(SplitStrategy, Duration)> = None;
    while let Some(Ok(Some((strat, elapsed)))) = set.join_next().await {
        debug!("Стратегия {:?} прошла проверку за {:?}", strat, elapsed);
        if best.map_or(true, |(_, best_time)| elapsed < best_time) {
            best = Some((strat, elapsed));
        }
    }

    match best {
        Some((winner, time)) => {
            info!("Выбрана лучшая стратегия: {:?} (отклик {:?})", winner, time);
            winner
        }
        None => {
            info!("Автоподбор не выявил фаворита, включен усиленный режим TlsRecordAndSni");
            SplitStrategy::TlsRecordAndSni
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

/// Собирает компактный валидный пакет TLS 1.2 ClientHello с расширением SNI для проверки сети
fn build_test_client_hello(domain: &str) -> Vec<u8> {
    let name_bytes = domain.as_bytes();
    let name_len = name_bytes.len() as u16;

    // Расширение SNI (0x0000)
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
    sni_ext.extend_from_slice(&(name_len + 5).to_be_bytes());
    sni_ext.extend_from_slice(&(name_len + 3).to_be_bytes());
    sni_ext.push(0x00); // HostName
    sni_ext.extend_from_slice(&name_len.to_be_bytes());
    sni_ext.extend_from_slice(name_bytes);

    // Тело ClientHello
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    body.extend_from_slice(&[0x42; 32]); // Random 32 байта
    body.push(0x00); // Session ID length = 0
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // Cipher Suite: TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x01, 0x00]); // Compression: null
    body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&sni_ext);

    // Заголовок Handshake (ClientHello = 0x01)
    let body_len = body.len() as u32;
    let body_len_be = body_len.to_be_bytes();
    let mut handshake = Vec::new();
    handshake.push(0x01);
    if let Some(len24) = body_len_be.get(1..4) {
        handshake.extend_from_slice(len24);
    }
    handshake.extend_from_slice(&body);

    // Заголовок TLS Record (0x16 = Handshake)
    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}
