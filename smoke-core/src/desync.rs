use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, Result};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SplitStrategy {
    /// 0. Прямая передача без модификации (принцип «Не навреди» / Direct-First)
    None,
    /// 1. TlsRecMicroSni: 4 TLS-рекорда с вырезанием 1-байтного микро-рекорда в центре SNI + смещенный TCP-сплит
    TlsRecMicroSni,
    /// 2. TlsRecOobSni: фрагментация TLS-рекорда + односегментный TCP Urgent (MSG_OOB) байт внутри SNI
    TlsRecOobSni,
    /// 3. FakeTls4: фальшивый TLS ClientHello (SNI=www.vk.com) с TTL=4 через TransmitFile + 3-сегментный Fast Retransmit
    FakeTls4,
    /// 4. FakeTls6: фальшивый TLS ClientHello (SNI=www.vk.com) с TTL=6 (для глубоких сетей и двойного NAT)
    FakeTls6,
    /// 5. TlsRecordFrag: разбиение на 3-4 TLS Record (заголовок, до SNI, центр SNI, остаток)
    TlsRecordFrag,
    /// 6. TlsRecordFrag2: двухзвенная фрагментация (1 байт в 1-м рекорде + TCP-сплит SNI во 2-м)
    TlsRecordFrag2,
    /// 7. TlsRecordFragSni: разноуровневый разрез TLS Record по центру SNI + смещенный TCP-сплит
    TlsRecordFragSni,
    /// 8. OobSni: односегментная инъекция Out-of-Band (MSG_OOB) байта прямо в конец первой половины SNI
    OobSni,
    /// 9. TcpSplitSni: чистый TCP-сплит ровно посередине имени домена
    TcpSplitSni,
    /// 10. Disorder3: отправка 1-го байта с TTL=3 (проходит домашний роутер и BRAS) + 3-сегментный Fast Retransmit
    Disorder3,
    /// 11. Disorder2: отправка 1-го байта с TTL=2 + 3-сегментный Fast Retransmit
    Disorder2,
    /// 12. Disorder1: отправка 1-го байта с TTL=1 + 3-сегментный Fast Retransmit
    Disorder1,
    /// 13. DisorderSni: отправка заголовка до середины SNI с TTL=1 + Fast Retransmit
    DisorderSni,
    /// 14. DisorderSni2: отправка заголовка до середины SNI с TTL=2 + Fast Retransmit
    DisorderSni2,
    /// 15. TcpSplit2: двойной TCP-сплит после 2-го байта (0x16 0x03) и посередине SNI
    TcpSplit2,
    /// 16. TcpSplit1: чистый TCP-сплит после 1-го байта
    TcpSplit1,
    /// 17. Combo: мульти-рекордная фрагментация SNI + TCP Disorder
    Combo,

    // Совместимость
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

        SplitStrategy::TlsRecMicroSni => {
            if is_tls_handshake(buf) {
                return send_tls_rec_micro_sni(remote, buf).await;
            }
            fallback_http_or_split(remote, buf, 2).await
        }

        SplitStrategy::TlsRecOobSni => {
            if is_tls_handshake(buf) {
                return send_tls_rec_oob_sni(remote, buf).await;
            }
            send_oob_at_sni(remote, buf).await
        }

        SplitStrategy::FakeTls4 => {
            if is_tls_handshake(buf) {
                return send_fake_tls(remote, buf, 3).await;
            }
            fallback_http_or_split(remote, buf, 2).await
        }

        SplitStrategy::FakeTls6 => {
            if is_tls_handshake(buf) {
                return send_fake_tls(remote, buf, 5).await;
            }
            fallback_http_or_split(remote, buf, 2).await
        }

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

        SplitStrategy::Disorder1 => send_disorder(remote, buf, 1, 1).await,
        SplitStrategy::Disorder2 => send_disorder(remote, buf, 1, 2).await,
        SplitStrategy::Disorder3 => send_disorder(remote, buf, 1, 3).await,

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

        SplitStrategy::OobSni => send_oob_at_sni(remote, buf).await,

        SplitStrategy::TcpSplit1 => write_split_2(remote, &buf[..1], &buf[1..]).await,

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

        SplitStrategy::Combo => send_combo(remote, buf).await,

        SplitStrategy::SniMiddle { fallback_pos } => {
            let split_pos = find_sni_middle(buf)
                .or_else(|| find_http_host_split(buf))
                .unwrap_or_else(|| fallback_pos.min(buf.len() - 1).max(1));

            let (first, second) = buf.split_at(split_pos);
            write_split_2(remote, first, second).await
        }

        SplitStrategy::TlsRecordAndSni => {
            if let Some(sni_info) = find_sni_range(buf) {
                let sni_mid = sni_info.middle();
                if sni_mid > 2 {
                    let (head, rest) = buf.split_at(2);
                    let (mid, tail) = rest.split_at(sni_mid - 2);
                    return write_split_3(remote, head, mid, tail).await;
                }
            }
            fallback_http_or_split(remote, buf, 2).await
        }
    }
}

async fn fallback_http_or_split(remote: &mut TcpStream, buf: &[u8], default_pos: usize) -> Result<()> {
    if let Some(http_pos) = find_http_host_split(buf) {
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

/// Односегментная отправка буфера с помеченным последним байтом как Out-of-Band (MSG_OOB):
/// В одном TCP-пакете уходят обычные данные + 1 срочный байт в конце (URG=1).
/// ТСПУ склеивает срочный байт прямо внутрь строки SNI, а целевой веб-сервер отбрасывает его на уровне сокета!
fn send_chunk_with_oob(stream: &TcpStream, data: &[u8], urgent_byte: u8) -> Result<()> {
    let sock = socket2::SockRef::from(stream);
    let mut oob_buf = Vec::with_capacity(data.len() + 1);
    oob_buf.extend_from_slice(data);
    oob_buf.push(urgent_byte);

    match sock.send_out_of_band(&oob_buf) {
        Ok(sent) if sent == oob_buf.len() => Ok(()),
        Ok(_) | Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Не удалось отправить односегментный MSG_OOB буфер",
        )),
    }
}

/// 1. TlsRecMicroSni:
/// Дробит ClientHello на 4 TLS-рекорда, вырезая 1-байтный микро-рекорд прямо из центра имени домена SNI
/// (даже 5-буквенный домен "x.com" разрывается двумя 5-байтными бинарными заголовками TLS!),
/// и отправляет их со смещенными границами TCP-сегментов (Cross-Layer). Не зависит от TTL и роутеров!
async fn send_tls_rec_micro_sni(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    if buf.len() < 10 {
        return remote.write_all(buf).await;
    }

    let content_type = buf[0];
    let ver_hi = buf[1];
    let ver_lo = buf[2];
    let payload = &buf[5..];

    if let Some(sni) = find_sni_range(buf) {
        let mid_in_payload = sni.middle().saturating_sub(5);
        if mid_in_payload > 2 && mid_in_payload + 1 < payload.len() {
            // 4 части payload: [0..1], [1..mid-1], [mid-1..mid] (1 байт центра SNI!), [mid..end]
            let p1 = 1;
            let p2 = mid_in_payload - 1;
            let p3 = mid_in_payload;

            let slices = [
                &payload[..p1],
                &payload[p1..p2],
                &payload[p2..p3],
                &payload[p3..],
            ];

            let mut combined = Vec::with_capacity(payload.len() + 20);
            let mut rec2_end = 0;
            for (idx, frag) in slices.iter().enumerate() {
                combined.push(content_type);
                combined.push(ver_hi);
                // Чередуем совместимую версию TLS Record (0x03 0x01 / 0x03 0x03) в рамках RFC 8446
                combined.push(if idx == 0 { ver_lo } else { 0x03 });
                combined.extend_from_slice(&(frag.len() as u16).to_be_bytes());
                combined.extend_from_slice(frag);
                if idx == 1 {
                    rec2_end = combined.len();
                }
            }

            // Режем TCP-поток со смещением относительно заголовков микро-рекордов
            let tcp_s1 = 2.min(combined.len() - 2);
            let tcp_s2 = (rec2_end + 3).min(combined.len() - 1);

            debug!(
                "TlsRecMicroSni: 4 TLS-рекорда (1-байтный разрез SNI), TCP splits @ [{}, {}]",
                tcp_s1, tcp_s2
            );

            if tcp_s1 < tcp_s2 && tcp_s2 < combined.len() {
                return write_split_3(
                    remote,
                    &combined[..tcp_s1],
                    &combined[tcp_s1..tcp_s2],
                    &combined[tcp_s2..],
                )
                .await;
            }

            return remote.write_all(&combined).await;
        }
    }

    send_tls_record_fragmented(remote, buf).await
}

/// 2. TlsRecOobSni:
/// Комбинация фрагментации TLS-рекорда по центру SNI + односегментный TCP Urgent (MSG_OOB) байт '!'.
/// Сбивает одновременно парсер TLS-рекордов и потоковый TCP-сборщик ТСПУ на 1 байт без привязки к TTL!
async fn send_tls_rec_oob_sni(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    if buf.len() < 10 {
        return remote.write_all(buf).await;
    }

    let content_type = buf[0];
    let ver_hi = buf[1];
    let ver_lo = buf[2];
    let payload = &buf[5..];

    if let Some(sni) = find_sni_range(buf) {
        let mid_in_payload = sni.middle().saturating_sub(5);
        if mid_in_payload > 1 && mid_in_payload < payload.len() {
            let frag1 = &payload[..mid_in_payload];
            let frag2 = &payload[mid_in_payload..];

            let mut rec1 = Vec::with_capacity(5 + frag1.len());
            rec1.push(content_type);
            rec1.push(ver_hi);
            rec1.push(ver_lo);
            rec1.extend_from_slice(&(frag1.len() as u16).to_be_bytes());
            rec1.extend_from_slice(frag1);

            let mut rec2 = Vec::with_capacity(5 + frag2.len());
            rec2.push(content_type);
            rec2.push(ver_hi);
            rec2.push(0x03);
            rec2.extend_from_slice(&(frag2.len() as u16).to_be_bytes());
            rec2.extend_from_slice(frag2);

            debug!(
                "TlsRecOobSni: Rec1 ({} байт) + MSG_OOB '!', Rec2 ({} байт)",
                rec1.len(),
                rec2.len()
            );

            // Если весь Rec1 помещается в один неблокирующий send_out_of_band, шлем с '!' на конце
            if send_chunk_with_oob(remote, &rec1, b'!').is_ok() {
                tokio::time::sleep(Duration::from_millis(1)).await;
                remote.write_all(&rec2).await?;
                return remote.flush().await;
            }
        }
    }

    send_oob_at_sni(remote, buf).await
}

/// Односегментная инъекция Out-of-Band байта (TCP Urgent Pointer) прямо внутрь SNI:
async fn send_oob_at_sni(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    let split_pos = find_sni_middle(buf)
        .or_else(|| find_http_host_split(buf))
        .unwrap_or(2.min(buf.len() - 1).max(1));

    let (first, second) = buf.split_at(split_pos);
    debug!("OobSni: односегментный MSG_OOB в точке {}", split_pos);

    if send_chunk_with_oob(remote, first, b'!').is_ok() {
        tokio::time::sleep(Duration::from_millis(1)).await;
        remote.write_all(second).await?;
        return remote.flush().await;
    }

    // Резерв, если буфер слишком велик для одного атомарного send_out_of_band
    let head_split = split_pos.saturating_sub(8).max(1);
    remote.write_all(&first[..head_split]).await?;
    send_chunk_with_oob(remote, &first[head_split..], b'!')?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    remote.write_all(second).await?;
    remote.flush().await
}

/// Собирает фальшивый заголовок TLS ClientHello ровно заданной длины `target_len` с белым доменом `www.vk.com`,
/// чтобы ТСПУ принял соединение за разрешенный российский ресурс и прекратил инспекцию потока!
fn build_fake_prefix(target_len: usize) -> Vec<u8> {
    let mut fake = crate::scanner::build_test_client_hello("www.vk.com");
    if fake.len() >= target_len {
        fake.truncate(target_len);
        // Корректируем длину TLS-рекорда под обрезанный размер, чтобы парсер ТСПУ считал заголовок валидным
        if target_len >= 5 {
            let rec_len = (target_len - 5) as u16;
            let be = rec_len.to_be_bytes();
            fake[3] = be[0];
            fake[4] = be[1];
        }
        fake
    } else {
        fake.resize(target_len, 0x00);
        if target_len >= 5 {
            let rec_len = (target_len - 5) as u16;
            let be = rec_len.to_be_bytes();
            fake[3] = be[0];
            fake[4] = be[1];
        }
        fake
    }
}

/// Семафор на 2 одновременных вызова TransmitFile (лимит клиентских версий Windows 10/11)
fn transmit_file_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(2))
}

/// 3 & 4. FakeTls (ByeDPI-style User-Space Fake через zero-copy буфер TransmitFile в Windows):
/// 1. Записывает фальшивый ClientHello (`www.vk.com`) во временный страничный буфер и отправляет с `TTL = fake_ttl` (4 или 6).
///    Фейк проходит домашний роутер, долетает до ТСПУ провайдера (хоп 3–5), обеляет сессию и сгорает до целевого сервера!
/// 2. Через 2 мс перезаписывает ту же страницу памяти реальным заголовком ClientHello и возвращает `TTL = 128`.
/// 3. Шлет хвост реального ClientHello в 3 сегментах -> сервер шлет 3x Dup ACK -> ядро Windows ретранслирует уже РЕАЛЬНЫЙ заголовок!
#[cfg(target_os = "windows")]
async fn send_fake_tls(remote: &mut TcpStream, buf: &[u8], fake_ttl: u32) -> Result<()> {
    use std::os::windows::io::{AsRawHandle, AsRawSocket};

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        h_event: usize,
    }

    #[link(name = "mswsock")]
    extern "system" {
        fn TransmitFile(
            hSocket: usize,
            hFile: *mut core::ffi::c_void,
            nNumberOfBytesToWrite: u32,
            nNumberOfBytesPerSend: u32,
            lpOverlapped: *mut Overlapped,
            lpTransmitBuffers: *const core::ffi::c_void,
            dwReserved: u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateEventW(
            lpEventAttributes: *const core::ffi::c_void,
            bManualReset: i32,
            bInitialState: i32,
            lpName: *const u16,
        ) -> *mut core::ffi::c_void;
        fn CreateFileMappingW(
            hFile: *mut core::ffi::c_void,
            lpFileMappingAttributes: *const core::ffi::c_void,
            flProtect: u32,
            dwMaximumSizeHigh: u32,
            dwMaximumSizeLow: u32,
            lpName: *const u16,
        ) -> *mut core::ffi::c_void;
        fn MapViewOfFile(
            hFileMappingObject: *mut core::ffi::c_void,
            dwDesiredAccess: u32,
            dwFileOffsetHigh: u32,
            dwFileOffsetLow: u32,
            dwNumberOfBytesToMap: usize,
        ) -> *mut u8;
        fn UnmapViewOfFile(lpBaseAddress: *const core::ffi::c_void) -> i32;
        fn WaitForSingleObject(hHandle: *mut core::ffi::c_void, dwMilliseconds: u32) -> u32;
        fn CloseHandle(hObject: *mut core::ffi::c_void) -> i32;
        fn WSAGetLastError() -> i32;
    }

    // Точка разреза — сразу после конца SNI (чтобы фейк полностью перекрыл область SNI для ТСПУ)
    let split_pos = if let Some(sni) = find_sni_range(buf) {
        sni.end.min(buf.len().saturating_sub(6)).max(6)
    } else {
        buf.len().min(120).min(buf.len().saturating_sub(6)).max(6)
    };

    if split_pos >= buf.len() {
        return send_tls_rec_micro_sni(remote, buf).await;
    }

    let (real_first, real_second) = buf.split_at(split_pos);
    let fake_first = build_fake_prefix(split_pos);

    // Соблюдаем системный лимит Windows Workstation (не более 2 параллельных TransmitFile)
    let _permit = transmit_file_semaphore().acquire().await.ok();

    let temp_dir = std::env::temp_dir();
    let unique_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = temp_dir.join(format!("smk_fk_{}_{}.tmp", std::process::id(), unique_id));

    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
        const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x04000000;
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE)
            .open(&temp_path)
        {
            Ok(f) => f,
            Err(_) => return send_tls_rec_micro_sni(remote, buf).await,
        }
    };

    if file.set_len(split_pos as u64).is_err() {
        return send_tls_rec_micro_sni(remote, buf).await;
    }

    let orig_ttl = get_stream_ttl(remote);
    let raw_sock = remote.as_raw_socket() as usize;
    let raw_file_usize = file.as_raw_handle() as usize;

    const PAGE_READWRITE: u32 = 0x04;
    const FILE_MAP_ALL_ACCESS: u32 = 0x000F001F;

    let (mapping_usize, view_usize, event_usize) = unsafe {
        let m = CreateFileMappingW(
            raw_file_usize as *mut core::ffi::c_void,
            core::ptr::null(),
            PAGE_READWRITE,
            0,
            split_pos as u32,
            core::ptr::null(),
        );
        if m.is_null() {
            return send_tls_rec_micro_sni(remote, buf).await;
        }
        let v = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, split_pos);
        if v.is_null() {
            CloseHandle(m);
            return send_tls_rec_micro_sni(remote, buf).await;
        }
        let ev = CreateEventW(core::ptr::null(), 1, 0, core::ptr::null());
        if ev.is_null() {
            UnmapViewOfFile(v as *const core::ffi::c_void);
            CloseHandle(m);
            return send_tls_rec_micro_sni(remote, buf).await;
        }
        // Записываем фейковый ClientHello напрямую в физическую страницу памяти!
        core::ptr::copy_nonoverlapping(fake_first.as_ptr(), v, split_pos);
        (m as usize, v as usize, ev as usize)
    };

    // ВАЖНО: младший бит h_event | 1 запрещает ядру Windows отправлять чужой пакет завершения в IOCP Tokio!
    let tagged_event = event_usize | 1;
    let mut ov = Box::new(Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        h_event: tagged_event,
    });

    debug!(
        "FakeTls: отправка фейка www.vk.com ({} байт) с TTL={}, хвост {} байт",
        split_pos,
        fake_ttl,
        real_second.len()
    );

    set_stream_ttl(remote, fake_ttl);

    const WSA_IO_PENDING: i32 = 997;
    const TF_USE_KERNEL_APC: u32 = 0x20;
    let tf_ok = unsafe {
        let ok = TransmitFile(
            raw_sock,
            raw_file_usize as *mut core::ffi::c_void,
            split_pos as u32,
            split_pos as u32,
            &mut *ov,
            core::ptr::null(),
            TF_USE_KERNEL_APC,
        );
        if ok != 0 {
            true
        } else {
            WSAGetLastError() == WSA_IO_PENDING
        }
    };

    if !tf_ok {
        set_stream_ttl(remote, orig_ttl);
        unsafe {
            UnmapViewOfFile(view_usize as *const core::ffi::c_void);
            CloseHandle(mapping_usize as *mut core::ffi::c_void);
            CloseHandle(event_usize as *mut core::ffi::c_void);
        }
        return send_tls_rec_micro_sni(remote, buf).await;
    }

    // Даем сетевой карте 3 мс выплюнуть фейковый IP-пакет с малым TTL в провод
    tokio::time::sleep(Duration::from_millis(3)).await;

    // Мгновенно подменяем физическую страницу памяти реальными байтами ClientHello и восстанавливаем штатный TTL!
    unsafe {
        core::ptr::copy_nonoverlapping(real_first.as_ptr(), view_usize as *mut u8, split_pos);
    }
    set_stream_ttl(remote, orig_ttl);

    // Отправляем хвост ClientHello в 3 отдельных сегментах, чтобы вызвать 3x Dup ACK (Fast Retransmit) от сервера!
    let write_res = if real_second.len() >= 6 {
        let p1 = 2;
        let p2 = (real_second.len() / 2).max(3);
        write_split_3(
            remote,
            &real_second[..p1],
            &real_second[p1..p2],
            &real_second[p2..],
        )
        .await
    } else {
        remote.write_all(real_second).await
    };

    // Освобождаем дескрипторы строго ПОСЛЕ завершения TransmitFile (ACK от сервера или закрытие сокета)
    tokio::task::spawn_blocking(move || {
        unsafe {
            WaitForSingleObject(event_usize as *mut core::ffi::c_void, 3500);
            UnmapViewOfFile(view_usize as *const core::ffi::c_void);
            CloseHandle(mapping_usize as *mut core::ffi::c_void);
            CloseHandle(event_usize as *mut core::ffi::c_void);
        }
        drop(ov);
        drop(file);
    });

    write_res
}

#[cfg(not(target_os = "windows"))]
async fn send_fake_tls(remote: &mut TcpStream, buf: &[u8], _fake_ttl: u32) -> Result<()> {
    send_tls_rec_micro_sni(remote, buf).await
}

/// Усовершенствованный Disorder (Fast-Retransmit RFC 5681 + SNI Multi-Slicing):
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

    set_stream_ttl(remote, low_ttl);
    remote.write_all(first).await?;
    remote.flush().await?;

    tokio::time::sleep(Duration::from_millis(1)).await;

    set_stream_ttl(remote, orig_ttl);

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

        write_split_3(remote, &second[..p1], &second[p1..p2], &second[p2..]).await
    } else {
        remote.write_all(second).await?;
        remote.flush().await
    }
}

/// Ультимативный Комбо-метод:
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
            set_stream_ttl(remote, 3);
            remote.write_all(&records[0]).await?;
            remote.flush().await?;
            tokio::time::sleep(Duration::from_millis(1)).await;

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
async fn send_tls_record_frag_sni(remote: &mut TcpStream, buf: &[u8]) -> Result<()> {
    if buf.len() < 6 {
        return remote.write_all(buf).await;
    }
    let content_type = buf[0];
    let version_hi = buf[1];
    let version_lo = buf[2];
    let handshake_payload = &buf[5..];

    if let Some(sni_info) = find_sni_range(buf) {
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

            let mut combined = Vec::with_capacity(rec1.len() + rec2.len());
            combined.extend_from_slice(&rec1);
            combined.extend_from_slice(&rec2);

            let tcp_split_1 = 2.min(combined.len() - 2);
            let tcp_split_2 = (rec1.len() + 2).min(combined.len() - 1);

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

    if let Some(sni_mid) = find_sni_middle(buf) {
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
    } else if payload_len > 10 {
        points.push(1);
        points.push(payload_len / 3);
        points.push(2 * payload_len / 3);
    } else if payload_len > 2 {
        points.push(1);
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
    fn test_fake_prefix_exact_length() {
        let fake_50 = build_fake_prefix(50);
        assert_eq!(fake_50.len(), 50);
        assert_eq!(fake_50[0], 0x16);
        assert_eq!(u16::from_be_bytes([fake_50[3], fake_50[4]]), 45);

        let fake_300 = build_fake_prefix(300);
        assert_eq!(fake_300.len(), 300);
        assert_eq!(u16::from_be_bytes([fake_300[3], fake_300[4]]), 295);
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
