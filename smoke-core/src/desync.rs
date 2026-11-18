use std::time::Duration;
use tokio::io::{AsyncWriteExt, Result};
use tokio::net::TcpStream;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SplitStrategy {
    /// Отправка без изменений
    None,
    /// 1. TlsRecordFrag: разбиение на 3-4 TLS Record (заголовок, до SNI, центр SNI, остаток)
    TlsRecordFrag,
    /// 2. TlsRecordFrag2: двухзвенная фрагментация (1 байт в 1-м рекорде, остаток во 2-м)
    TlsRecordFrag2,
    /// 3. TlsRecordFragSni: разрез TLS Record ровно перед началом расширения SNI
    TlsRecordFragSni,
    /// 4. Disorder1: отправка 1-го байта с TTL=1 (умирает на 1-м узле), ретрансмит через SACK
    Disorder1,
    /// 4b. Disorder2: отправка 1-го байта с TTL=2 (для роутеров и GPON-модемов)
    Disorder2,
    /// 4c. Disorder3: отправка 1-го байта с TTL=3 (для глубоких сетей)
    Disorder3,
    /// 5. DisorderSni: отправка заголовка до середины SNI с TTL=1, ретрансмит через SACK
    DisorderSni,
    /// 5b. DisorderSni2: отправка заголовка до середины SNI с TTL=2, ретрансмит через SACK
    DisorderSni2,
    /// 6. OobSni: инъекция Out-of-band (TCP Urgent Pointer) байта в середину SNI
    OobSni,
    /// 7. TcpSplit1: чистый TCP-сплит после 1-го байта
    TcpSplit1,
    /// 8. TcpSplit2: чистый TCP-сплит после 2-го байта (0x16 0x03)
    TcpSplit2,
    /// 9. TcpSplitSni: чистый TCP-сплит в середине домена
    TcpSplitSni,
    /// 10. Combo: 2-рекордная фрагментация + TCP Disorder на 1-м рекорде
    Combo,

    // Совместимость со старыми вызовами
    SniMiddle { fallback_pos: usize },
    TlsRecordAndSni,
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

        SplitStrategy::TlsRecordFrag => {
            if is_tls_handshake(buf) {
                return send_tls_record_fragmented(remote, buf).await;
            }
            fallback_http_or_split(remote, buf, 2).await
        }

        SplitStrategy::TlsRecordFrag2 => {
            if is_tls_handshake(buf) {
                return send_tls_record_frag_2(remote, buf).await;
            }
            fallback_http_or_split(remote, buf, 1).await
        }

        SplitStrategy::TlsRecordFragSni => {
            if is_tls_handshake(buf) {
                return send_tls_record_frag_sni(remote, buf).await;
            }
            fallback_http_or_split(remote, buf, 2).await
        }

        SplitStrategy::Disorder1 => {
            send_disorder(remote, buf, 1, 1).await
        }

        SplitStrategy::Disorder2 => {
            send_disorder(remote, buf, 1, 2).await
        }

        SplitStrategy::Disorder3 => {
            send_disorder(remote, buf, 1, 3).await
        }

        SplitStrategy::DisorderSni => {
            let pos = find_sni_middle(buf)
                .or_else(|| find_http_host_split(buf))
                .unwrap_or(2.min(buf.len() - 1).max(1));
            send_disorder(remote, buf, pos, 1).await
        }

        SplitStrategy::DisorderSni2 => {
            let pos = find_sni_middle(buf)
                .or_else(|| find_http_host_split(buf))
                .unwrap_or(2.min(buf.len() - 1).max(1));
            send_disorder(remote, buf, pos, 2).await
        }

        SplitStrategy::OobSni => {
            send_oob_at_sni(remote, buf).await
        }

        SplitStrategy::TcpSplit1 => {
            write_split_2(remote, &buf[..1], &buf[1..]).await
        }

        SplitStrategy::TcpSplit2 => {
            if let Some(sni_mid) = find_sni_middle(buf) {
                if sni_mid > 2 && sni_mid < buf.len() {
                    return write_split_3(remote, &buf[..2], &buf[2..sni_mid], &buf[sni_mid..]).await;
                }
            }
            let pos = 2.min(buf.len() - 1).max(1);
            write_split_2(remote, &buf[..pos], &buf[pos..]).await
        }

        SplitStrategy::TcpSplitSni => {
            let pos = find_sni_middle(buf)
                .or_else(|| find_http_host_split(buf))
                .unwrap_or(2.min(buf.len() - 1).max(1));
            write_split_2(remote, &buf[..pos], &buf[pos..]).await
        }

        SplitStrategy::Combo => {
            send_combo(remote, buf).await
        }

        SplitStrategy::SniMiddle { fallback_pos } => {
            let split_pos = find_sni_middle(buf)
                .or_else(|| find_http_host_split(buf))
                .unwrap_or_else(|| fallback_pos.min(buf.len() - 1).max(1));

            let (first, second) = buf.split_at(split_pos);
            debug!("SniMiddle split в точке {}", split_pos);
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
                return write_split_2(remote, first, second).await;
            }

            let pos = 2.min(buf.len() - 1).max(1);
            let (first, second) = buf.split_at(pos);
            write_split_2(remote, first, second).await
        }
    }
}

async fn fallback_http_or_split(remote: &mut TcpStream, buf: &[u8], default_pos: usize) -> Result<()> {
    if let Some(http_pos) = find_http_host_split(buf) {
        // Разрезаем одновременно и заголовок "Ho|st:", и середину самого домена в Host
        let rest = &buf[http_pos..];
        if let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
            if line_end > 6 {
                let host_mid = http_pos + 4 + (line_end - 4) / 2;
                if host_mid > http_pos && host_mid < buf.len() {
                    return write_split_3(
                        remote,
                        &buf[..http_pos],
                        &buf[http_pos..host_mid],
                        &buf[host_mid..],
                    )
                    .await;
                }
            }
        }
        let (first, second) = buf.split_at(http_pos);
        return write_split_2(remote, first, second).await;
    }
    let pos = default_pos.min(buf.len() - 1).max(1);
    let (first, second) = buf.split_at(pos);
    write_split_2(remote, first, second).await
}

fn set_stream_ttl(stream: &TcpStream, ttl: u32) {
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_ttl(ttl);
}

fn get_stream_ttl(stream: &TcpStream) -> u32 {
    let sock = socket2::SockRef::from(stream);
    sock.ttl().unwrap_or(128)
}

fn send_stream_oob(stream: &TcpStream, byte: u8) {
    let sock = socket2::SockRef::from(stream);
    let _ = sock.send_out_of_band(&[byte]);
}

/// Усовершенствованный Disorder (Fast-Retransmit RFC 5681 + SNI Multi-Slicing):
/// 1. 1-й сегмент уходит с малым TTL (1/2/3) и умирает на маршрутизаторе до ТСПУ.
/// 2. Остаток делится на 3 отдельных сегмента (с разрезом ровно по середине и концу SNI) и уходит с нормальным TTL.
/// 3. Получение 3 внеочередных сегментов гарантированно вызывает 3 Dup ACK (SACK) от сервера,
///    что включает мгновенный TCP Fast Retransmit в ядре Windows за 1 RTT (~30 мс) вместо ожидания RTO (500+ мс),
///    при этом сам домен SNI никогда не передается целым куском!
async fn send_disorder(
    remote: &mut TcpStream,
    buf: &[u8],
    split_pos: usize,
    low_ttl: u32,
) -> Result<()> {
    if split_pos == 0 || split_pos >= buf.len() {
        return remote.write_all(buf).await;
    }

    let (first, second) = buf.split_at(split_pos);
    let orig_ttl = get_stream_ttl(remote);

    debug!(
        "Disorder (Fast-Retransmit): 1-я часть ({} байт) с TTL={}, остаток ({} байт) в 3 сегмента",
        first.len(),
        low_ttl,
        second.len()
    );

    // 1. Посылаем 1-ю часть с умирающим TTL
    set_stream_ttl(remote, low_ttl);
    remote.write_all(first).await?;
    remote.flush().await?;

    // Пауза, чтобы пакет гарантированно ушел с низким TTL отдельным IP-пакетом
    tokio::time::sleep(Duration::from_millis(1)).await;

    // 2. Восстанавливаем оригинальный TTL
    set_stream_ttl(remote, orig_ttl);

    // 3. Делим вторую часть на 3 сегмента (разрезая SNI пополам, если он внутри second),
    // чтобы сервер прислал ровно 3 Dup ACK и мгновенно сработал TCP Fast Retransmit!
    if second.len() >= 6 {
        let (p1, p2) = if let Some(sni) = find_sni_range(buf) {
            let mid = sni.middle();
            let end = sni.end;
            if mid > split_pos && end > mid && end < buf.len() {
                (mid - split_pos, end - split_pos)
            } else {
                (1, 2)
            }
        } else {
            (1, 2)
        };

        let p1 = p1.clamp(1, second.len() - 2);
        let p2 = p2.clamp(p1 + 1, second.len() - 1);

        let s1 = &second[..p1];
        let s2 = &second[p1..p2];
        let s3 = &second[p2..];
        write_split_3(remote, s1, s2, s3).await
    } else {
        remote.write_all(second).await?;
        remote.flush().await
    }
}

/// Инъекция Out-of-Band байта (TCP Urgent Pointer) + дополнительный сплит хвоста SNI:
/// Посылается 1 OOB-байт между половинами SNI. ТСПУ включает его в сигнатуру и не узнает домен,
/// а веб-сервер игнорирует OOB-данные, сохраняя чистоту TLS-потока.
async fn send_oob_at_sni(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    let split_pos = find_sni_middle(buf)
        .or_else(|| find_http_host_split(buf))
        .unwrap_or(2.min(buf.len() - 1).max(1));

    let (first, second) = buf.split_at(split_pos);
    debug!("OOB injection: split в точке {}", split_pos);

    remote.write_all(first).await?;
    remote.flush().await?;

    // Отправляем OOB байт с флагом MSG_OOB (Urgent Pointer)
    send_stream_oob(remote, b'a');
    tokio::time::sleep(Duration::from_millis(1)).await;

    remote.write_all(second).await?;
    remote.flush().await
}

/// Ультимативный Комбо-метод:
/// Мульти-рекордная TLS-фрагментация (с внедрением 5-байтного TLS-заголовка прямо в середину SNI)
/// + TCP Disorder на 1-м рекорде + 3-сегментный Fast Retransmit!
async fn send_combo(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    if is_tls_handshake(buf) && buf.len() > 6 {
        let content_type = buf[0];
        let version_hi = buf[1];
        let version_lo = buf[2];
        let handshake_payload = &buf[5..];

        let split_points = compute_record_split_points(buf, handshake_payload.len());
        let mut records: Vec<Vec<u8>> = Vec::new();
        let mut start = 0;

        for &split in &split_points {
            let end = split.min(handshake_payload.len());
            if end <= start {
                continue;
            }
            let frag = &handshake_payload[start..end];
            let mut rec = Vec::with_capacity(5 + frag.len());
            rec.push(content_type);
            rec.push(version_hi);
            rec.push(version_lo);
            rec.extend_from_slice(&(frag.len() as u16).to_be_bytes());
            rec.extend_from_slice(frag);
            records.push(rec);
            start = end;
        }

        if start < handshake_payload.len() {
            let frag = &handshake_payload[start..];
            let mut rec = Vec::with_capacity(5 + frag.len());
            rec.push(content_type);
            rec.push(version_hi);
            rec.push(version_lo);
            rec.extend_from_slice(&(frag.len() as u16).to_be_bytes());
            rec.extend_from_slice(frag);
            records.push(rec);
        }

        if records.len() >= 2 {
            let orig_ttl = get_stream_ttl(remote);
            debug!(
                "Combo: {} TLS-рекордов (разрез внутри SNI) + Disorder TTL=1",
                records.len()
            );

            // 1-й TLS-рекорд отправляем с TTL=1
            set_stream_ttl(remote, 1);
            remote.write_all(&records[0]).await?;
            remote.flush().await?;
            tokio::time::sleep(Duration::from_millis(1)).await;

            // Остальные TLS-рекорды (с разрезанным SNI) отправляем с нормальным TTL отдельными сегментами
            set_stream_ttl(remote, orig_ttl);
            for (i, rec) in records[1..].iter().enumerate() {
                remote.write_all(rec).await?;
                remote.flush().await?;
                if i + 2 < records.len() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            return Ok(());
        }
    }
    write_split_2(remote, &buf[..1], &buf[1..]).await
}

/// Разноуровневая (Cross-Layer) фрагментация TLS-рекорда ровно посередине SNI + смещенный TCP-сплит:
/// Внедряет 5-байтный заголовок второго TLS-рекорда [0x16, 0x03, 0x01, len_hi, len_lo] прямо внутрь имени домена
/// (например, "www.you" + [TLS Header] + "tube.com"), а границу TCP-сегментов делает со смещением!
async fn send_tls_record_frag_sni(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    if buf.len() < 6 {
        return remote.write_all(buf).await;
    }
    let content_type = buf[0];
    let version_hi = buf[1];
    let version_lo = buf[2];
    let handshake_payload = &buf[5..];

    if let Some(sni_info) = find_sni_range(buf) {
        // Режем TLS Record прямо по центру имени домена SNI (а не перед ним),
        // чтобы ни в одном TLS-рекорде и ни в одном пакете не было целой строки домена!
        let split_in_payload = sni_info.middle().saturating_sub(5);
        if split_in_payload > 0 && split_in_payload < handshake_payload.len() {
            let frag1 = &handshake_payload[..split_in_payload];
            let frag2 = &handshake_payload[split_in_payload..];

            let mut rec1 = Vec::with_capacity(5 + frag1.len());
            rec1.push(content_type);
            rec1.push(version_hi);
            rec1.push(version_lo);
            rec1.extend_from_slice(&(frag1.len() as u16).to_be_bytes());
            rec1.extend_from_slice(frag1);

            let mut rec2 = Vec::with_capacity(5 + frag2.len());
            rec2.push(content_type);
            rec2.push(version_hi);
            rec2.push(version_lo);
            rec2.extend_from_slice(&(frag2.len() as u16).to_be_bytes());
            rec2.extend_from_slice(frag2);

            // Склеиваем оба TLS-рекорда и режем TCP-поток со смещением относительно границ TLS-рекордов
            // (TCP-разрез на 2-м байте и на 2-м байте заголовка второго TLS-рекорда)
            let mut combined = Vec::with_capacity(rec1.len() + rec2.len());
            combined.extend_from_slice(&rec1);
            combined.extend_from_slice(&rec2);

            let tcp_split_1 = 2.min(combined.len() - 2);
            let tcp_split_2 = (rec1.len() + 2).min(combined.len() - 1);

            debug!(
                "Cross-Layer TLS Record Frag SNI: TLS split @ {}, TCP splits @ [{}, {}]",
                rec1.len(),
                tcp_split_1,
                tcp_split_2
            );

            if tcp_split_1 < tcp_split_2 && tcp_split_2 < combined.len() {
                return write_split_3(
                    remote,
                    &combined[..tcp_split_1],
                    &combined[tcp_split_1..tcp_split_2],
                    &combined[tcp_split_2..],
                )
                .await;
            }

            remote.write_all(&rec1).await?;
            remote.flush().await?;
            tokio::time::sleep(Duration::from_millis(1)).await;
            remote.write_all(&rec2).await?;
            return remote.flush().await;
        }
    }
    send_tls_record_frag_2(remote, buf).await
}

/// Разбивает один TLS Record (ClientHello) на несколько маленьких TLS Record'ов
async fn send_tls_record_fragmented(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    if buf.len() < 6 {
        return remote.write_all(buf).await;
    }

    let content_type = buf[0];
    let version_hi = buf[1];
    let version_lo = buf[2];
    let handshake_payload = &buf[5..];

    if handshake_payload.is_empty() {
        return remote.write_all(buf).await;
    }

    let split_points = compute_record_split_points(buf, handshake_payload.len());

    let mut start = 0;
    for (i, &split) in split_points.iter().enumerate() {
        let end = split.min(handshake_payload.len());
        if end <= start {
            continue;
        }

        let fragment = &handshake_payload[start..end];
        let frag_len = fragment.len() as u16;

        let mut record = Vec::with_capacity(5 + fragment.len());
        record.push(content_type);
        record.push(version_hi);
        record.push(version_lo);
        record.extend_from_slice(&frag_len.to_be_bytes());
        record.extend_from_slice(fragment);

        remote.write_all(&record).await?;
        remote.flush().await?;

        if i < split_points.len() - 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        start = end;
    }

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

/// Фрагментирует ClientHello ровно на 2 TLS Record
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

    let mut rec1 = Vec::with_capacity(6);
    rec1.push(content_type);
    rec1.push(version_hi);
    rec1.push(version_lo);
    rec1.extend_from_slice(&1u16.to_be_bytes());
    rec1.extend_from_slice(frag1);

    let mut rec2 = Vec::with_capacity(5 + frag2.len());
    rec2.push(content_type);
    rec2.push(version_hi);
    rec2.push(version_lo);
    rec2.extend_from_slice(&(frag2.len() as u16).to_be_bytes());
    rec2.extend_from_slice(frag2);

    debug!("TLS Record Frag2: Rec 1 (6 байт) + Rec 2 ({} байт) со сплитом SNI", rec2.len());

    if let Some(sni_mid) = find_sni_middle(buf) {
        // В rec2 позиция sni_mid смещена на +4 байта (т.к. 1 байт ушел в rec1, но добавился 5-байтный заголовок rec2)
        let rec2_sni_mid = (sni_mid.saturating_sub(6)) + 5;
        if rec2_sni_mid > 5 && rec2_sni_mid < rec2.len() {
            return write_split_3(remote, &rec1, &rec2[..rec2_sni_mid], &rec2[rec2_sni_mid..]).await;
        }
    }

    remote.write_all(&rec1).await?;
    remote.flush().await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    remote.write_all(&rec2).await?;
    remote.flush().await
}

fn compute_record_split_points(full_buf: &[u8], payload_len: usize) -> Vec<usize> {
    let mut points = Vec::new();

    if let Some(sni_info) = find_sni_range(full_buf) {
        let sni_start_in_payload = sni_info.start.saturating_sub(5);
        let sni_mid_in_payload = sni_info.middle().saturating_sub(5);

        if payload_len > 1 {
            points.push(1);
        }

        if sni_start_in_payload > 2 {
            points.push(sni_start_in_payload);
        }

        if sni_mid_in_payload > sni_start_in_payload + 1 {
            points.push(sni_mid_in_payload);
        }
    } else {
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
    points.retain(|&p| p > 0 && p < payload_len);
    points
}

#[inline]
pub fn is_tls_handshake(buf: &[u8]) -> bool {
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
        assert!(!points.is_empty());
        for &p in &points {
            assert!(p > 0 && p < payload_len);
        }
    }
}
