use crate::adaptive::AdaptiveEngine;
use crate::desync::{find_sni_range, is_tls_handshake, send_desync, SplitStrategy};
use crate::dns::DnsResolver;
use crate::error::{Result, SmokeError};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
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
            "Smoke универсальный прокси (SOCKS5 + HTTP) запущен на {} | Фиксированный режим: {:?}",
            bind_addr, strat
        );
    } else {
        info!(
            "Smoke универсальный прокси (SOCKS5 + HTTP) запущен на {} | Режим: Smart Adaptive (автоподбор и самообучение на лету)",
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
            if let Err(e) = handle_connection(client_stream, dns_clone, engine_clone, fixed_strategy).await {
                debug!("Сессия {} завершена: {}", peer_addr, e);
            }
        });
    }
}

/// Автоматически определяет протокол (SOCKS5 или системный HTTP CONNECT Windows)
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

    // Читаем HTTP-заголовок до пустой строки \r\n\r\n (динамически до 64 КБ)
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
        // HTTPS туннель (например, CONNECT youtube.com:443 HTTP/1.1)
        let (host, port) = parse_host_port(target, 443)?;
        let target_addr = dns.resolve(&host, port).await?;

        let remote = match connect_optimized(target_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(SmokeError::Io(e));
            }
        };

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let leftover = &buf[header_end..];
        relay_with_desync(client, remote, target_addr, &host, engine, fixed_strategy, leftover).await
    } else {
        // Обычный незашифрованный HTTP-запрос
        let host_line = req_str
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("host:"))
            .ok_or(SmokeError::InvalidDomain)?;

        let host_val = host_line.get(5..).unwrap_or("").trim();
        let (host, port) = parse_host_port(host_val, 80)?;
        let target_addr = dns.resolve(&host, port).await?;

        let mut remote = connect_optimized(target_addr).await?;
        let active_strategy = if is_private_ip(target_addr.ip()) {
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

    let (target_addr, parsed_host) = match atyp {
        ATYP_IPV4 => {
            let mut ip_bytes = [0u8; 4];
            client.read_exact(&mut ip_bytes).await?;
            let port = client.read_u16().await?;
            let ip = Ipv4Addr::from(ip_bytes);
            (SocketAddr::new(IpAddr::V4(ip), port), ip.to_string())
        }
        ATYP_DOMAIN => {
            let len = client.read_u8().await? as usize;
            let mut domain_bytes = vec![0u8; len];
            client.read_exact(&mut domain_bytes).await?;
            let domain =
                std::str::from_utf8(&domain_bytes).map_err(|_| SmokeError::InvalidDomain)?;
            let port = client.read_u16().await?;
            let host_str = domain.to_string();
            let addr = dns.resolve(domain, port).await?;
            (addr, host_str)
        }
        ATYP_IPV6 => {
            let mut ip_bytes = [0u8; 16];
            client.read_exact(&mut ip_bytes).await?;
            let port = client.read_u16().await?;
            let ip = Ipv6Addr::from(ip_bytes);
            (SocketAddr::new(IpAddr::V6(ip), port), ip.to_string())
        }
        other => return Err(SmokeError::UnsupportedAddressType(other)),
    };

    let remote = match connect_optimized(target_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            let _ = client
                .write_all(&[SOCKS_VERSION, 0x04, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(SmokeError::Io(e));
        }
    };

    let reply = [SOCKS_VERSION, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    client.write_all(&reply).await?;

    relay_with_desync(client, remote, target_addr, &parsed_host, engine, fixed_strategy, &[]).await
}

async fn relay_with_desync(
    mut client: TcpStream,
    mut remote: TcpStream,
    target_addr: SocketAddr,
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

    // Извлекаем точный SNI из TLS ClientHello (если есть), чтобы знать истинный домен даже при запросах по IP
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
    let is_tls = is_tls_handshake(slice);

    // Если стратегия жестко зафиксирована ключом CLI или IP локальный или не TLS:
    if fixed_strategy.is_some() || is_private || !is_tls {
        let active_strategy = if is_private {
            SplitStrategy::None
        } else {
            fixed_strategy.unwrap_or_else(|| engine.get_strategy(resolved_host))
        };

        send_desync(&mut remote, slice, active_strategy).await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
        return Ok(());
    }

    // Smart In-Flight Fast Failover:
    // Если первая стратегия заблокирована ТСПУ (RST или таймаут 1200 мс),
    // мы НЕ закрываем соединение клиента (Discord / браузера)!
    // Мы на лету открываем новый сокет к серверу, берем следующую стратегию из арсенала и шлем ClientHello снова.
    // Клиент получает ServerHello без ошибок обновления и без разрывов связи!
    let max_attempts = 4;
    let mut current_remote = Some(remote);

    for attempt in 0..max_attempts {
        let active_strategy = engine.get_strategy(resolved_host);
        let mut stream = match current_remote.take() {
            Some(s) => s,
            None => match connect_optimized(target_addr).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("Не удалось переподключиться к {}: {}", target_addr, e);
                    return Err(SmokeError::Io(e));
                }
            },
        };

        if let Err(e) = send_desync(&mut stream, slice, active_strategy).await {
            debug!("Ошибка send_desync ({:?}): {}", active_strategy, e);
            engine.record_failure(resolved_host, active_strategy);
            continue;
        }

        let mut resp_first = [0u8; 1];
        match timeout(Duration::from_millis(1200), stream.read(&mut resp_first)).await {
            Ok(Ok(n)) if n > 0 => {
                engine.record_success(resolved_host, active_strategy);
                client.write_all(&resp_first[..n]).await?;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut stream).await;
                return Ok(());
            }
            Ok(Ok(_)) | Err(_) => {
                debug!(
                    "Попытка {}/{} ({:?}) заблокирована ТСПУ для {}",
                    attempt + 1,
                    max_attempts,
                    active_strategy,
                    resolved_host
                );
                engine.record_failure(resolved_host, active_strategy);
            }
            Ok(Err(e)) => {
                debug!(
                    "Ошибка сокета на попытке {} ({:?}): {}",
                    attempt + 1,
                    active_strategy,
                    e
                );
                engine.record_failure(resolved_host, active_strategy);
            }
        }
    }

    Ok(())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
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

    // Ограничиваем ожидание соединения 3 секундами для быстрого сброса мёртвых IP
    match timeout(Duration::from_millis(3000), tokio_stream.writable()).await {
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
