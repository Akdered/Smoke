use crate::desync::{send_desync, SplitStrategy};
use crate::dns::DnsResolver;
use crate::error::{Result, SmokeError};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    strategy: SplitStrategy,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;

    info!(
        "Smoke универсальный прокси (SOCKS5 + HTTP) запущен на {} | Режим: {:?}",
        bind_addr, strategy
    );

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

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, dns_clone, strategy).await {
                debug!("Сессия {} завершена: {}", peer_addr, e);
            }
        });
    }
}

/// Автоматически определяет протокол (SOCKS5 или системный HTTP CONNECT Windows)
async fn handle_connection(
    client: TcpStream,
    dns: DnsResolver,
    strategy: SplitStrategy,
) -> Result<()> {
    let mut peek_buf = [0u8; 1];
    let n = client.peek(&mut peek_buf).await?;
    if n == 0 {
        return Ok(());
    }

    if *peek_buf.first().unwrap_or(&0) == SOCKS_VERSION {
        handle_socks5(client, dns, strategy).await
    } else {
        handle_http_proxy(client, dns, strategy).await
    }
}

async fn handle_http_proxy(
    mut client: TcpStream,
    dns: DnsResolver,
    strategy: SplitStrategy,
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

        relay_with_desync(client, remote, target_addr, strategy).await
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
            strategy
        };

        send_desync(&mut remote, &buf, active_strategy).await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
        Ok(())
    }
}

fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    // Убираем протокольные префиксы, если передан абсолютный URI
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
    strategy: SplitStrategy,
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
    let target_addr = match atyp {
        ATYP_IPV4 => {
            let mut ip_bytes = [0u8; 4];
            client.read_exact(&mut ip_bytes).await?;
            let port = client.read_u16().await?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port)
        }
        ATYP_DOMAIN => {
            let len = client.read_u8().await? as usize;
            let mut domain_bytes = vec![0u8; len];
            client.read_exact(&mut domain_bytes).await?;
            let domain =
                std::str::from_utf8(&domain_bytes).map_err(|_| SmokeError::InvalidDomain)?;
            let port = client.read_u16().await?;

            dns.resolve(domain, port).await?
        }
        ATYP_IPV6 => {
            let mut ip_bytes = [0u8; 16];
            client.read_exact(&mut ip_bytes).await?;
            let port = client.read_u16().await?;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port)
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

    relay_with_desync(client, remote, target_addr, strategy).await
}

async fn relay_with_desync(
    mut client: TcpStream,
    mut remote: TcpStream,
    target_addr: SocketAddr,
    strategy: SplitStrategy,
) -> Result<()> {
    let active_strategy = if is_private_ip(target_addr.ip()) {
        SplitStrategy::None
    } else {
        strategy
    };

    let mut first_buf = [0u8; 16384];
    // Ожидаем первый пакет от клиента с надежным таймаутом (до 10 секунд)
    match timeout(Duration::from_secs(10), client.read(&mut first_buf)).await {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(n)) => {
            if let Some(slice) = first_buf.get(..n) {
                send_desync(&mut remote, slice, active_strategy).await?;
            }
        }
        Ok(Err(e)) => return Err(SmokeError::Io(e)),
        Err(_) => {
            // Клиент подключился, но ничего не прислал за 10 секунд
            return Ok(());
        }
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
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
