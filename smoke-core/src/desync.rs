use tokio::io::{AsyncWriteExt, Result};
use tokio::net::TcpStream;
use tracing::debug;

#[derive(Debug, Clone, Copy)]
pub enum SplitStrategy {
    /// Отправка без изменений
    None,
    /// Разрез ровно посередине имени домена (SNI), иначе на заданном байте
    SniMiddle { fallback_pos: usize },
    /// Двойной разрез: после 2-го байта TLS заголовка + посередине SNI (мощный режим)
    TlsRecordAndSni,
}

/// Отправляет первый пакет соединения согласно выбранной стратегии фрагментации
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
            let split_pos = find_sni_middle(buf).unwrap_or_else(|| fallback_pos.min(buf.len() - 1));
            let (first, second) = buf.split_at(split_pos);

            debug!("Split пакета ({} байт) в точке {}", buf.len(), split_pos);
            remote.write_all(first).await?;
            remote.flush().await?;
            remote.write_all(second).await
        }

        SplitStrategy::TlsRecordAndSni => {
            if let Some(sni_pos) = find_sni_middle(buf) {
                if sni_pos > 2 {
                    let (head, rest) = buf.split_at(2);
                    let (mid, tail) = rest.split_at(sni_pos - 2);

                    debug!("Двойной Split пакета: [2, {}, {}]", sni_pos, buf.len());
                    remote.write_all(head).await?;
                    remote.flush().await?;
                    remote.write_all(mid).await?;
                    remote.flush().await?;
                    return remote.write_all(tail).await;
                }
            }
            // Фолбэк, если это не TLS или пакет нестандартный
            let pos = 2.min(buf.len() - 1);
            let (first, second) = buf.split_at(pos);
            remote.write_all(first).await?;
            remote.flush().await?;
            remote.write_all(second).await
        }
    }
}

/// Zero-copy поиск середины доменного имени (SNI) в пакете TLS ClientHello
pub fn find_sni_middle(buf: &[u8]) -> Option<usize> {
    // 0x16 = Handshake, 0x03 = TLS, тип сообщения 0x01 = ClientHello (на смещении 5)
    if *buf.first()? != 0x16 || *buf.get(1)? != 0x03 || *buf.get(5)? != 0x01 {
        return None;
    }

    // Пропускаем Record Header (5) + Handshake Header (4) + Version (2) + Random (32) = 43 байта
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

            if name_type == 0x00 && name_len > 1 && name_start + name_len <= buf.len() {
                return Some(name_start + (name_len / 2));
            }
        }
        pos += ext_len;
    }

    None
}

#[inline]
fn read_u16_be(buf: &[u8], offset: usize) -> Option<u16> {
    let hi = *buf.get(offset)?;
    let lo = *buf.get(offset + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}
