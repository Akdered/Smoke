use crate::adaptive::{is_fast_direct_domain, AdaptiveEngine};
use crate::desync::{find_sni_range, is_tls_handshake, send_desync, SplitStrategy};
use crate::dns::DnsResolver;
use crate::error::{Result, SmokeError};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

const SOCKS_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub async fn run_server(
    bind_addr: SocketAddr,
    dns: DnsResolver,
    fixed_strategy: Option<SplitStrategy>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let engine = Arc::new(AdaptiveEngine::new());

    if let Some(strat) = fixed_strategy {
        info!(
            "Smoke прокси (SOCKS5 + HTTP) запущен на {} | Фиксированный режим: {:?}",
            bind_addr, strat
        );
    } else {
        info!(
            "Smoke прокси (SOCKS5 + HTTP) запущен на {} | Smart Adaptive v0.6 (Direct-First + Anti-Flapping)",
            bind_addr
        );
    }

    loop {
        let (client_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("Ошибка принятия подключения: {}", e);
                continue;
            }
        };

        let _ = client_stream.set_nodelay(true);
        let dns_clone = dns.clone();
        let engine_clone = engine.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(client_stream, dns_clone, engine_clone, fixed_strategy).await
            {
                debug!("Сессия {} завершена: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_connection(
    client: TcpStream,
    dns: DnsResolver,
    engine: Arc<AdaptiveEngine>,
    fixed_strategy: Option<SplitStrategy>,
) -> Result<()> {
    let mut peek_buf = [0u8; 1];
    let n = client.peek(&mut peek_buf).await?;
    if n == 0 {
        return Ok(());
    }

    if *peek_buf.first().unwrap_or(&0) == SOCKS_VERSION {
        handle_socks5(client, dns, engine, fixed_strategy).await
    } else {
        handle_http_proxy(client, dns, engine, fixed_strategy).await
    }
}

async fn handle_http_proxy(
    mut client: TcpStream,
    dns: DnsResolver,
    engine: Arc<AdaptiveEngine>,
    fixed_strategy: Option<SplitStrategy>,
) -> Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];

    let header_end = loop {
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);

        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }

        if buf.len() > 65536 {
            return Err(SmokeError::InvalidDomain);
        }
    };

    let req_bytes = buf.get(..header_end).ok_or(SmokeError::InvalidDomain)?;
    let req_str = std::str::from_utf8(req_bytes).map_err(|_| SmokeError::InvalidDomain)?;
    let first_line = req_str.lines().next().ok_or(SmokeError::InvalidDomain)?;

    let mut parts = first_line.split_whitespace();
    let method = parts.next().ok_or(SmokeError::InvalidDomain)?;
    let target = parts.next().ok_or(SmokeError::InvalidDomain)?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(target, 443)?;
        let target_addrs = dns.resolve_all(&host, port).await?;

        let (remote, connected_addr) = match connect_any_optimized(&target_addrs).await {
            Ok(res) => res,
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(SmokeError::Io(e));
            }
        };

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let leftover = &buf[header_end..];
        relay_with_desync(
            client,
            remote,
            connected_addr,
            &target_addrs,
            &host,
            engine,
            fixed_strategy,
            leftover,
        )
        .await
    } else {
        let host_line = req_str
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("host:"))
            .ok_or(SmokeError::InvalidDomain)?;

        let host_val = host_line.get(5..).unwrap_or("").trim();
        let (host, port) = parse_host_port(host_val, 80)?;
        let target_addrs = dns.resolve_all(&host, port).await?;

        let (mut remote, connected_addr) = connect_any_optimized(&target_addrs).await?;
        let active_strategy = if is_private_ip(connected_addr.ip()) || is_fast_direct_domain(&host) {
            SplitStrategy::None
        } else {
            fixed_strategy.unwrap_or_else(|| engine.get_strategy(&host))
        };

        send_desync(&mut remote, &buf, active_strategy).await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
        Ok(())
    }
}

fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let clean = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s);

    let host_and_port = clean.split('/').next().unwrap_or(clean);

    if let Some((h, p)) = host_and_port.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            let clean_host = h.trim_matches(|c| c == '[' || c == ']');
            return Ok((clean_host.to_string(), port));
        }
    }
    let clean_host = host_and_port.trim_matches(|c| c == '[' || c == ']');
    Ok((clean_host.to_string(), default_port))
}

async fn handle_socks5(
    mut client: TcpStream,
    dns: DnsResolver,
    engine: Arc<AdaptiveEngine>,
    fixed_strategy: Option<SplitStrategy>,
) -> Result<()> {
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;

    let ver = *header.first().unwrap_or(&0);
    if ver != SOCKS_VERSION {
        return Err(SmokeError::UnsupportedVersion(ver));
    }

    let nmethods = *header.get(1).unwrap_or(&0) as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    client.write_all(&[SOCKS_VERSION, NO_AUTH]).await?;

    let mut req_head = [0u8; 4];
    client.read_exact(&mut req_head).await?;

    let req_ver = *req_head.first().unwrap_or(&0);
    if req_ver != SOCKS_VERSION {
        return Err(SmokeError::UnsupportedVersion(req_ver));
    }

    let cmd = *req_head.get(1).unwrap_or(&0);
    if cmd != CMD_CONNECT {
        let _ = client
            .write_all(&[SOCKS_VERSION, 0x07, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await;
        return Err(SmokeError::UnsupportedCommand(cmd));
    }

    let atyp = *req_head.get(3).unwrap_or(&0);

    let (target_addrs, parsed_host) = match atyp {
        ATYP_IPV4 => {
            let mut ip_bytes = [0u8; 4];
            client.read_exact(&mut ip_bytes).await?;
            let port = client.read_u16().await?;
            let ip = Ipv4Addr::from(ip_bytes);
            (vec![SocketAddr::new(IpAddr::V4(ip), port)], ip.to_string())
        }
        ATYP_DOMAIN => {
            let len = client.read_u8().await? as usize;
            let mut domain_bytes = vec![0u8; len];
            client.read_exact(&mut domain_bytes).await?;
            let domain =
                std::str::from_utf8(&domain_bytes).map_err(|_| SmokeError::InvalidDomain)?;
            let port = client.read_u16().await?;
            let host_str = domain.to_string();
            let addrs = dns.resolve_all(domain, port).await?;
            (addrs, host_str)
        }
        ATYP_IPV6 => {
            let mut ip_bytes = [0u8; 16];
            client.read_exact(&mut ip_bytes).await?;
            let port = client.read_u16().await?;
            let ip = Ipv6Addr::from(ip_bytes);
            (vec![SocketAddr::new(IpAddr::V6(ip), port)], ip.to_string())
        }
        other => return Err(SmokeError::UnsupportedAddressType(other)),
    };

    let (remote, connected_addr) = match connect_any_optimized(&target_addrs).await {
        Ok(res) => res,
        Err(e) => {
            let _ = client
                .write_all(&[SOCKS_VERSION, 0x04, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(SmokeError::Io(e));
        }
    };

    let reply = [SOCKS_VERSION, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    client.write_all(&reply).await?;

    relay_with_desync(
        client,
        remote,
        connected_addr,
        &target_addrs,
        &parsed_host,
        engine,
        fixed_strategy,
        &[],
    )
    .await
}

async fn relay_with_desync(
    mut client: TcpStream,
    mut remote: TcpStream,
    target_addr: SocketAddr,
    target_addrs: &[SocketAddr],
    host: &str,
    engine: Arc<AdaptiveEngine>,
    fixed_strategy: Option<SplitStrategy>,
    leftover_data: &[u8],
) -> Result<()> {
    let mut first_buf = [0u8; 16384];
    let n = if !leftover_data.is_empty() {
        let copy_len = leftover_data.len().min(first_buf.len());
        first_buf[..copy_len].copy_from_slice(&leftover_data[..copy_len]);
        copy_len
    } else {
        match timeout(Duration::from_secs(10), client.read(&mut first_buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(SmokeError::Io(e)),
            Err(_) => return Ok(()),
        }
    };

    let slice = &first_buf[..n];

    let resolved_host = if let Some(sni_info) = find_sni_range(slice) {
        if let Some(sni_bytes) = slice.get(sni_info.start..sni_info.end) {
            std::str::from_utf8(sni_bytes).unwrap_or(host)
        } else {
            host
        }
    } else {
        host
    };

    let is_private = is_private_ip(target_addr.ip());
    let is_fast_direct = is_fast_direct_domain(resolved_host);
    let is_tls = is_tls_handshake(slice);

    // 1. Быстрый прямой путь для .ru / локальных IP / не-TLS трафика или жестко заданного ключа --strategy
    if fixed_strategy.is_some() || is_private || is_fast_direct || !is_tls {
        let active_strategy = if is_private || is_fast_direct {
            SplitStrategy::None
        } else {
            fixed_strategy.unwrap_or_else(|| engine.get_strategy(resolved_host))
        };

        send_desync(&mut remote, slice, active_strategy).await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
        return Ok(());
    }

    // 2. Интеллектуальный режим:
    // - Если домен УЖЕ ПОДТВЕРЖДЕН и у него всего 1 IP (например, кэш-сервер rr1---sn-*.googlevideo.com),
    //   делаем ровно 1 попытку (1400 мс)! Если кэш-сервер GGC мертв — быстро закрываем сокет за 1.4 сек,
    //   чтобы плеер YouTube / YouTube Music мгновенно переключился на живой rr2 без 10-секундных зависаний!
    // - Если домен еще НЕ подтвержден — тестируем до 5 стратегий подряд внутри одного соединения!
    let domain_confirmed = engine.is_confirmed(resolved_host);
    let max_attempts = if domain_confirmed {
        if target_addrs.len() > 1 { 2 } else { 1 }
    } else {
        5
    };

    let mut current_remote = Some(remote);
    let initial_strategy = engine.get_strategy(resolved_host);

    for attempt in 0..max_attempts {
        let active_strategy = if domain_confirmed {
            // На подтвержденном домене при ротации запасного IP сохраняем проверенную стратегию
            initial_strategy
        } else {
            engine.get_strategy_for_attempt(resolved_host, attempt)
        };

        let addr_to_try = if !target_addrs.is_empty() {
            target_addrs[attempt % target_addrs.len()]
        } else {
            target_addr
        };

        let mut stream = match current_remote.take() {
            Some(s) => s,
            None => match connect_optimized(addr_to_try).await {
                Ok(s) => s,
                Err(_) => match connect_any_optimized(target_addrs).await {
                    Ok((s, _)) => s,
                    Err(e) => {
                        debug!("Не удалось переподключиться к {}: {}", addr_to_try, e);
                        return Err(SmokeError::Io(e));
                    }
                },
            },
        };

        if let Err(e) = send_desync(&mut stream, slice, active_strategy).await {
            debug!("Ошибка send_desync ({:?}): {}", active_strategy, e);
            continue;
        }

        // Для холостой проверки None ждем максимум 650 мс; для подтвержденных узлов — 1400 мс; при поиске — 1700 мс
        let wait_ms = if active_strategy == SplitStrategy::None && !domain_confirmed {
            650
        } else if domain_confirmed {
            1400
        } else {
            1700
        };

        let mut resp_first = [0u8; 1];
        match timeout(Duration::from_millis(wait_ms), stream.read(&mut resp_first)).await {
            Ok(Ok(n)) if n > 0 && resp_first[0] == 0x16 => {
                // Подтвержден настоящий TLS ServerHello (ContentType = 0x16) — сразу фиксируем успех для параллельных потоков!
                engine.record_success(resolved_host, active_strategy);
                let handshake_at = Instant::now();
                client.write_all(&resp_first[..n]).await?;

                let (mut cr, mut cw) = client.split();
                let (mut sr, mut sw) = stream.split();

                let c2s = tokio::io::copy(&mut cr, &mut sw);
                let s2c = async {
                    let mut total_s2c: u64 = n as u64;
                    let mut buf = [0u8; 16384];
                    loop {
                        match sr.read(&mut buf).await {
                            Ok(0) => return Ok(total_s2c),
                            Ok(read_n) => {
                                total_s2c += read_n as u64;
                                if cw.write_all(&buf[..read_n]).await.is_err() {
                                    // Клиент (браузер/curl) сам закрыл вкладку или запрос — это НЕ блок ТСПУ!
                                    return Ok(total_s2c);
                                }
                            }
                            Err(e) => return Err((e, total_s2c)),
                        }
                    }
                };

                tokio::select! {
                    _ = c2s => {}
                    res = s2c => {
                        if let Err((e, bytes_from_server)) = res {
                            // Истинный 16KB-блок ТСПУ: именно УДАЛЕННАЯ сторона прислала TCP RST до 24 КБ в первые 3.5 сек!
                            let is_remote_dpi_rst = bytes_from_server < 24_576
                                && handshake_at.elapsed() < Duration::from_millis(3500)
                                && matches!(
                                    e.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionAborted
                                );

                            if is_remote_dpi_rst && active_strategy == SplitStrategy::None {
                                engine.record_post_handshake_freeze(resolved_host, active_strategy);
                            }
                        }
                    }
                }
                return Ok(());
            }
            Ok(Ok(n)) if n > 0 => {
                debug!(
                    "Отклонен не-ServerHello ответ (0x{:02x}) на попытке {}/{} ({:?}) для {}",
                    resp_first[0],
                    attempt + 1,
                    max_attempts,
                    active_strategy,
                    resolved_host
                );
            }
            Ok(Ok(_)) | Err(_) => {
                debug!(
                    "Таймаут/EOF на попытке {}/{} ({:?}) для {}",
                    attempt + 1,
                    max_attempts,
                    active_strategy,
                    resolved_host
                );
            }
            Ok(Err(e)) => {
                debug!(
                    "Сброс сокета на попытке {}/{} ({:?}) для {}: {}",
                    attempt + 1,
                    max_attempts,
                    active_strategy,
                    resolved_host,
                    e
                );
            }
        }
    }

    engine.record_failure(resolved_host, initial_strategy);
    Ok(())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

async fn connect_any_optimized(addrs: &[SocketAddr]) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut last_err = None;
    for &addr in addrs {
        match connect_optimized(addr).await {
            Ok(stream) => return Ok((stream, addr)),
            Err(e) => {
                debug!("Узел {} недоступен ({}), пробуем следующий IP...", addr, e);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Нет доступных IP-адресов")
    }))
}

async fn connect_optimized(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(err) if err.raw_os_error() == Some(10035) => {}
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(err) => return Err(err),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let tokio_stream = TcpStream::from_std(std_stream)?;

    // Быстрый 2-секундный таймаут на TCP SYN, чтобы мгновенно переходить к следующему IP при blackhole
    match timeout(Duration::from_millis(2000), tokio_stream.writable()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Таймаут TCP подключения к удаленному узлу",
            ))
        }
    }

    if let Some(err) = tokio_stream.take_error()? {
        return Err(err);
    }

    Ok(tokio_stream)
}
