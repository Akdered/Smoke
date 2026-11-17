use std::time::Duration;
use tokio::io::{AsyncWriteExt, Result};
use tokio::net::TcpStream;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitStrategy {
    /// Отправка без изменений
    None,
    /// Разрез ровно посередине имени домена (SNI), иначе на заданном байте
    SniMiddle { fallback_pos: usize },
    /// Двойной разрез: после 2-го байта TLS заголовка + посередине SNI (мощный режим)
    TlsRecordAndSni,
    /// Трюк с Fake TTL: сначала шлем фейковый пакет с низким TTL (долетит только до ТСПУ),
    /// затем восстанавливаем нормальный TTL и шлем реальный пакет со сплитом SNI
    FakeTtl { fake_ttl: u32, fallback_pos: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SniInfo {
    pub start: usize,
    pub end: usize,
}

impl SniInfo {
    #[inline]
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    #[inline]
    pub fn middle(&self) -> usize {
        self.start + (self.len() / 2)
    }
}

/// Отправляет первый пакет соединения согласно выбранной стратегии десинхронизации
pub async fn send_desync(
    remote: &mut TcpStream,
    buf: &[u8],
    strategy: SplitStrategy,
) -> Result<()> {
    if buf.len() < 6 {
        return remote.write_all(buf).await;
    }

    match strategy {
        SplitStrategy::None => remote.write_all(buf).await,

        SplitStrategy::SniMiddle { fallback_pos } => {
            let split_pos = find_sni_middle(buf)
                .or_else(|| find_http_host_split(buf))
                .unwrap_or_else(|| fallback_pos.min(buf.len() - 1));

            let (first, second) = buf.split_at(split_pos);
            debug!("SniMiddle split пакета ({} байт) в точке {}", buf.len(), split_pos);
            write_split_2(remote, first, second).await
        }

        SplitStrategy::TlsRecordAndSni => {
            if let Some(sni_info) = find_sni_range(buf) {
                let sni_mid = sni_info.middle();
                if sni_mid > 2 {
                    let (head, rest) = buf.split_at(2);
                    let (mid, tail) = rest.split_at(sni_mid - 2);

                    debug!("Двойной Split пакета: [2, {}, {}]", sni_mid, buf.len());
                    return write_split_3(remote, head, mid, tail).await;
                }
            }

            // Фолбэк для HTTP или нестандартного TLS
            if let Some(http_pos) = find_http_host_split(buf) {
                let (first, second) = buf.split_at(http_pos);
                debug!("HTTP Host split в точке {}", http_pos);
                return write_split_2(remote, first, second).await;
            }

            let pos = 2.min(buf.len() - 1);
            let (first, second) = buf.split_at(pos);
            write_split_2(remote, first, second).await
        }

        SplitStrategy::FakeTtl { fake_ttl, fallback_pos } => {
            // 1. Пытаемся получить текущий TTL сокета
            let orig_ttl = get_socket_ttl(remote).unwrap_or(128);

            // 2. Отправляем фейковый пакет с малым TTL (долетает только до локального ТСПУ)
            if set_socket_ttl(remote, fake_ttl).is_ok() {
                debug!("Отправка Fake-пакета с TTL={}", fake_ttl);
                let fake_packet = generate_fake_payload(buf);
                let _ = remote.write_all(&fake_packet).await;
                let _ = remote.flush().await;
                tokio::time::sleep(Duration::from_millis(2)).await;

                // Восстанавливаем оригинальный TTL сокета
                let _ = set_socket_ttl(remote, orig_ttl);
            }

            // 3. Отправляем настоящий пакет со сплитом SNI
            let split_pos = find_sni_middle(buf)
                .or_else(|| find_http_host_split(buf))
                .unwrap_or_else(|| fallback_pos.min(buf.len() - 1));

            let (first, second) = buf.split_at(split_pos);
            write_split_2(remote, first, second).await
        }
    }
}

async fn write_split_2(remote: &mut TcpStream, first: &[u8], second: &[u8]) -> Result<()> {
    remote.write_all(first).await?;
    remote.flush().await?;
    // Микропауза гарантирует, что стек TCP и сетевая карта отправят первый сегмент отдельным кадром
    tokio::time::sleep(Duration::from_millis(2)).await;
    remote.write_all(second).await?;
    remote.flush().await
}

async fn write_split_3(remote: &mut TcpStream, first: &[u8], second: &[u8], third: &[u8]) -> Result<()> {
    remote.write_all(first).await?;
    remote.flush().await?;
    tokio::time::sleep(Duration::from_millis(2)).await;
    remote.write_all(second).await?;
    remote.flush().await?;
    tokio::time::sleep(Duration::from_millis(2)).await;
    remote.write_all(third).await?;
    remote.flush().await
}

fn set_socket_ttl(stream: &TcpStream, ttl: u32) -> std::io::Result<()> {
    let sock = socket2::SockRef::from(stream);
    sock.set_ttl(ttl)
}

fn get_socket_ttl(stream: &TcpStream) -> std::io::Result<u32> {
    let sock = socket2::SockRef::from(stream);
    sock.ttl()
}

/// Генерирует безопасную фейковую нагрузку для сбивания ТСПУ с толку
fn generate_fake_payload(buf: &[u8]) -> Vec<u8> {
    if buf.starts_with(&[0x16, 0x03]) {
        // Для TLS шлем компактный фейковый заголовок TLS ClientHello с нейтральным доменом
        let mut fake = Vec::with_capacity(64);
        fake.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x3b]); // TLS Record
        fake.extend_from_slice(&[0x01, 0x00, 0x00, 0x37]);       // ClientHello
        fake.extend_from_slice(&[0x03, 0x03]);                   // TLS 1.2
        fake.extend_from_slice(&[0x55; 32]);                     // Dummy Random
        fake.push(0x00);                                         // Session ID
        fake.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);       // Cipher
        fake.extend_from_slice(&[0x01, 0x00]);                   // Compression
        fake.extend_from_slice(&[0x00, 0x0c]);                   // Ext length
        // Fake SNI: iana.org (длина 8)
        fake.extend_from_slice(&[0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00]);
        fake.extend_from_slice(b"iana.org");
        fake
    } else {
        // Для HTTP шлем безобидный фейковый GET запрос
        b"GET / HTTP/1.1\r\nHost: iana.org\r\n\r\n".to_vec()
    }
}

/// Zero-copy поиск диапазона доменного имени (SNI) в пакете TLS ClientHello
pub fn find_sni_range(buf: &[u8]) -> Option<SniInfo> {
    // 0x16 = Handshake, 0x03 = TLS, тип сообщения 0x01 = ClientHello (на смещении 5)
    if *buf.first()? != 0x16 || *buf.get(1)? != 0x03 || *buf.get(5)? != 0x01 {
        return None;
    }

    // Record Header (5) + Handshake Header (4) + Version (2) + Random (32) = 43 байта
    let mut pos = 43;

    // Session ID
    let session_id_len = *buf.get(pos)? as usize;
    pos += 1 + session_id_len;

    // Cipher Suites
    let cipher_len = read_u16_be(buf, pos)? as usize;
    pos += 2 + cipher_len;

    // Compression Methods
    let comp_len = *buf.get(pos)? as usize;
    pos += 1 + comp_len;

    // Extensions Length
    let ext_total_len = read_u16_be(buf, pos)? as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(buf.len());

    // Перебираем расширения TLS в поисках SNI (тип 0x0000)
    while pos + 4 <= ext_end {
        let ext_type = read_u16_be(buf, pos)?;
        let ext_len = read_u16_be(buf, pos + 2)? as usize;
        pos += 4;

        if ext_type == 0x0000 && pos + 5 <= ext_end {
            // Внутри SNI: Server Name List Length (2) + Type HostName 0x00 (1) + Name Length (2)
            let name_type = *buf.get(pos + 2)?;
            let name_len = read_u16_be(buf, pos + 3)? as usize;
            let name_start = pos + 5;
            let name_end = name_start + name_len;

            if name_type == 0x00 && name_len > 0 && name_end <= buf.len() {
                return Some(SniInfo {
                    start: name_start,
                    end: name_end,
                });
            }
        }
        pos += ext_len;
    }

    None
}

/// Zero-copy поиск середины доменного имени (SNI) в пакете TLS ClientHello
#[inline]
pub fn find_sni_middle(buf: &[u8]) -> Option<usize> {
    find_sni_range(buf).map(|s| s.middle())
}

/// Ищет позицию для разрезания HTTP-запроса (внутри или перед заголовком Host)
pub fn find_http_host_split(buf: &[u8]) -> Option<usize> {
    if !buf.starts_with(b"GET ")
        && !buf.starts_with(b"POST ")
        && !buf.starts_with(b"HEAD ")
        && !buf.starts_with(b"OPTIONS ")
        && !buf.starts_with(b"PUT ")
    {
        return None;
    }

    // Ищем "\r\nHost:" или "\r\nhost:"
    let lower_window = buf.windows(7);
    for (i, window) in lower_window.enumerate() {
        if window.eq_ignore_ascii_case(b"\r\nhost:") {
            // Разрезаем прямо внутри слова "Host" -> "Ho" и "st:"
            return Some(i + 4);
        }
    }

    // Если Host не найден, разрезаем после первого пробела ("GET " | "/path...")
    if let Some(space_pos) = buf.iter().position(|&b| b == b' ') {
        return Some(space_pos + 1);
    }

    None
}

#[inline]
fn read_u16_be(buf: &[u8], offset: usize) -> Option<u16> {
    let hi = *buf.get(offset)?;
    let lo = *buf.get(offset + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_http_host_split() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let split_pos = find_http_host_split(req);
        assert!(split_pos.is_some());
        let pos = split_pos.unwrap();
        let (first, second) = req.split_at(pos);
        assert!(first.ends_with(b"\r\nHo") || first.ends_with(b"\r\nho"));
        assert!(second.starts_with(b"st: example.com"));
    }

    #[test]
    fn test_find_sni_range_and_middle() {
        let domain = "www.youtube.com";
        let hello = crate::scanner::build_test_client_hello(domain);
        let sni_info = find_sni_range(&hello);
        assert!(sni_info.is_some());
        let info = sni_info.unwrap();
        assert_eq!(&hello[info.start..info.end], domain.as_bytes());
        let mid = info.middle();
        assert!(mid > info.start && mid < info.end);
        assert_eq!(find_sni_middle(&hello), Some(mid));
    }
}
