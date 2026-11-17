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
    /// Фрагментация TLS-записи: один ClientHello разбивается на 3-4 TLS Record'а
    TlsRecordFrag,
    /// Двухзвенная фрагментация: 1-й TLS Record несет ровно 1 байт handshake, 2-й — остаток.
    /// Максимально совместимый и устойчивый режим: скрывает SNI от DPI при 100% совместимости с серверами.
    TlsRecordFrag2,
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
                .unwrap_or_else(|| fallback_pos.min(buf.len() - 1).max(1));

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
                    debug!("Двойной Split: [2, {}, {}]", sni_mid, buf.len());
                    return write_split_3(remote, head, mid, tail).await;
                }
            }

            if let Some(http_pos) = find_http_host_split(buf) {
                let (first, second) = buf.split_at(http_pos);
                debug!("HTTP Host split в точке {}", http_pos);
                return write_split_2(remote, first, second).await;
            }

            let pos = 2.min(buf.len() - 1).max(1);
            let (first, second) = buf.split_at(pos);
            write_split_2(remote, first, second).await
        }

        SplitStrategy::TlsRecordFrag => {
            if is_tls_handshake(buf) {
                return send_tls_record_fragmented(remote, buf).await;
            }

            if let Some(http_pos) = find_http_host_split(buf) {
                let (first, second) = buf.split_at(http_pos);
                debug!("HTTP Host split в точке {}", http_pos);
                return write_split_2(remote, first, second).await;
            }

            let pos = 2.min(buf.len() - 1).max(1);
            let (first, second) = buf.split_at(pos);
            write_split_2(remote, first, second).await
        }

        SplitStrategy::TlsRecordFrag2 => {
            if is_tls_handshake(buf) {
                return send_tls_record_frag_2(remote, buf).await;
            }

            if let Some(http_pos) = find_http_host_split(buf) {
                let (first, second) = buf.split_at(http_pos);
                debug!("HTTP Host split в точке {}", http_pos);
                return write_split_2(remote, first, second).await;
            }

            let pos = 2.min(buf.len() - 1).max(1);
            let (first, second) = buf.split_at(pos);
            write_split_2(remote, first, second).await
        }
    }
}

/// Разбивает один TLS Record (ClientHello) на несколько маленьких TLS Record'ов.
///
/// Идея: ТСПУ ожидает один Record с полным ClientHello внутри.
/// Если мы разобьём handshake payload на 3-4 отдельных TLS Record'а (каждый с
/// собственным 5-байтным заголовком 0x16 0x03 0x01 LEN), парсер ТСПУ не сможет
/// реассемблировать SNI, т.к. большинство DPI-коробок не реализуют TLS record reassembly.
///
/// Это ВАЛИДНЫЙ TLS: RFC 8446 §5.1 разрешает фрагментировать Handshake-сообщения
/// по границам Record'ов, и все серверы обязаны это поддерживать.
async fn send_tls_record_fragmented(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    // buf = [ContentType(1) | Version(2) | Length(2) | handshake_payload...]
    if buf.len() < 6 {
        return remote.write_all(buf).await;
    }

    let content_type = buf[0];       // 0x16
    let version_hi = buf[1];         // 0x03
    let version_lo = buf[2];         // 0x01 или 0x03

    let handshake_payload = &buf[5..]; // всё после 5-байтного Record Header

    if handshake_payload.is_empty() {
        return remote.write_all(buf).await;
    }

    // Определяем точки разреза: хотим, чтобы SNI оказался разбит между Record'ами
    let split_points = compute_record_split_points(buf, handshake_payload.len());

    debug!(
        "TLS Record Fragmentation: {} байт payload -> {} фрагментов, точки: {:?}",
        handshake_payload.len(),
        split_points.len() + 1,
        split_points
    );

    let mut start = 0;
    for (i, &split) in split_points.iter().enumerate() {
        let end = split.min(handshake_payload.len());
        if end <= start {
            continue;
        }

        let fragment = &handshake_payload[start..end];
        let frag_len = fragment.len() as u16;

        // Собираем TLS Record Header для этого фрагмента
        let mut record = Vec::with_capacity(5 + fragment.len());
        record.push(content_type);
        record.push(version_hi);
        record.push(version_lo);
        record.extend_from_slice(&frag_len.to_be_bytes());
        record.extend_from_slice(fragment);

        remote.write_all(&record).await?;
        remote.flush().await?;

        // Микропауза между фрагментами (гарантирует раздельные TCP-сегменты)
        if i < split_points.len() - 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        start = end;
    }

    // Последний фрагмент (остаток)
    if start < handshake_payload.len() {
        let fragment = &handshake_payload[start..];
        let frag_len = fragment.len() as u16;
        let mut record = Vec::with_capacity(5 + fragment.len());
        record.push(content_type);
        record.push(version_hi);
        record.push(version_lo);
        record.extend_from_slice(&frag_len.to_be_bytes());
        record.extend_from_slice(fragment);

        remote.write_all(&record).await?;
        remote.flush().await?;
    }

    Ok(())
}

/// Фрагментирует ClientHello ровно на 2 TLS Record:
/// Record 1: ровно 1 байт handshake (0x01 ClientHello)
/// Record 2: весь остальной handshake payload (содержит SNI)
///
/// ТСПУ не находит SNI в 1-м рекорде (так как длина всего 1 байт),
/// а 2-й рекорд воспринимает как продолжение и не сканирует заголовок ClientHello.
async fn send_tls_record_frag_2(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    if buf.len() < 6 {
        return remote.write_all(buf).await;
    }

    let content_type = buf[0];
    let version_hi = buf[1];
    let version_lo = buf[2];
    let handshake_payload = &buf[5..];

    if handshake_payload.len() <= 1 {
        return remote.write_all(buf).await;
    }

    let frag1 = &handshake_payload[..1];
    let frag2 = &handshake_payload[1..];

    // Record 1
    let mut rec1 = Vec::with_capacity(6);
    rec1.push(content_type);
    rec1.push(version_hi);
    rec1.push(version_lo);
    rec1.extend_from_slice(&1u16.to_be_bytes());
    rec1.extend_from_slice(frag1);

    // Record 2
    let mut rec2 = Vec::with_capacity(5 + frag2.len());
    rec2.push(content_type);
    rec2.push(version_hi);
    rec2.push(version_lo);
    rec2.extend_from_slice(&(frag2.len() as u16).to_be_bytes());
    rec2.extend_from_slice(frag2);

    debug!(
        "TLS Record Frag2: Record 1 (6 байт) + Record 2 ({} байт)",
        rec2.len()
    );

    remote.write_all(&rec1).await?;
    remote.flush().await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    remote.write_all(&rec2).await?;
    remote.flush().await
}

/// Вычисляет оптимальные точки разреза payload для TLS Record Fragmentation.
/// Старается разрезать так, чтобы SNI-расширение оказалось разнесено между Record'ами.
fn compute_record_split_points(full_buf: &[u8], payload_len: usize) -> Vec<usize> {
    let mut points = Vec::new();

    // Если мы знаем, где SNI — разрезаем прямо перед ним, посередине и после
    if let Some(sni_info) = find_sni_range(full_buf) {
        // Смещение SNI внутри payload (SNI start в buf минус 5 байт Record Header)
        let sni_start_in_payload = sni_info.start.saturating_sub(5);
        let sni_mid_in_payload = sni_info.middle().saturating_sub(5);

        // Первый разрез: 1 байт (сбивает парсер ТСПУ, который ожидает полный Handshake header)
        if payload_len > 1 {
            points.push(1);
        }

        // Второй разрез: перед началом SNI (если это дальше первого разреза)
        if sni_start_in_payload > 2 {
            points.push(sni_start_in_payload);
        }

        // Третий разрез: посередине имени хоста в SNI
        if sni_mid_in_payload > sni_start_in_payload + 1 {
            points.push(sni_mid_in_payload);
        }
    } else {
        // Если SNI не найден — равномерная фрагментация
        if payload_len > 10 {
            points.push(1);
            points.push(payload_len / 3);
            points.push(2 * payload_len / 3);
        } else if payload_len > 2 {
            points.push(1);
        }
    }

    points.sort();
    points.dedup();
    // Убираем нулевые и выходящие за границы
    points.retain(|&p| p > 0 && p < payload_len);

    points
}

#[inline]
fn is_tls_handshake(buf: &[u8]) -> bool {
    buf.len() >= 6 && buf[0] == 0x16 && buf[1] == 0x03
}

async fn write_split_2(remote: &mut TcpStream, first: &[u8], second: &[u8]) -> Result<()> {
    remote.write_all(first).await?;
    remote.flush().await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    remote.write_all(second).await?;
    remote.flush().await
}

async fn write_split_3(remote: &mut TcpStream, first: &[u8], second: &[u8], third: &[u8]) -> Result<()> {
    remote.write_all(first).await?;
    remote.flush().await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    remote.write_all(second).await?;
    remote.flush().await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    remote.write_all(third).await?;
    remote.flush().await
}

/// Zero-copy поиск диапазона доменного имени (SNI) в пакете TLS ClientHello
pub fn find_sni_range(buf: &[u8]) -> Option<SniInfo> {
    if *buf.first()? != 0x16 || *buf.get(1)? != 0x03 || *buf.get(5)? != 0x01 {
        return None;
    }

    let mut pos = 43;

    let session_id_len = *buf.get(pos)? as usize;
    pos += 1 + session_id_len;

    let cipher_len = read_u16_be(buf, pos)? as usize;
    pos += 2 + cipher_len;

    let comp_len = *buf.get(pos)? as usize;
    pos += 1 + comp_len;

    let ext_total_len = read_u16_be(buf, pos)? as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(buf.len());

    while pos + 4 <= ext_end {
        let ext_type = read_u16_be(buf, pos)?;
        let ext_len = read_u16_be(buf, pos + 2)? as usize;
        pos += 4;

        if ext_type == 0x0000 && pos + 5 <= ext_end {
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

#[inline]
pub fn find_sni_middle(buf: &[u8]) -> Option<usize> {
    find_sni_range(buf).map(|s| s.middle())
}

/// Ищет позицию для разрезания HTTP-запроса (внутри заголовка Host)
pub fn find_http_host_split(buf: &[u8]) -> Option<usize> {
    if !buf.starts_with(b"GET ")
        && !buf.starts_with(b"POST ")
        && !buf.starts_with(b"HEAD ")
        && !buf.starts_with(b"OPTIONS ")
        && !buf.starts_with(b"PUT ")
        && !buf.starts_with(b"DELETE ")
        && !buf.starts_with(b"PATCH ")
    {
        return None;
    }

    let lower_window = buf.windows(7);
    for (i, window) in lower_window.enumerate() {
        if window.eq_ignore_ascii_case(b"\r\nhost:") {
            return Some(i + 4);
        }
    }

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

    #[test]
    fn test_tls_record_frag_split_points() {
        let domain = "www.youtube.com";
        let hello = crate::scanner::build_test_client_hello(domain);
        let payload_len = hello.len() - 5;
        let points = compute_record_split_points(&hello, payload_len);
        // Должно быть несколько точек разреза
        assert!(!points.is_empty());
        // Все точки в пределах payload
        for &p in &points {
            assert!(p > 0 && p < payload_len);
        }
    }
}
