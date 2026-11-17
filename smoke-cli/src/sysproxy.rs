use anyhow::Result;
use tracing::{info, warn};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const DEFAULT_BYPASS: &str = "localhost;127.*;10.*;192.168.*;172.16.*;<local>";

const BROWSER_POLICY_KEYS: &[&str] = &[
    r"Software\Policies\Google\Chrome",
    r"Software\Policies\Microsoft\Edge",
    r"Software\Policies\Yandex\YandexBrowser",
    r"Software\Policies\BraveSoftware\Brave",
];

pub struct ProxyGuard {
    active: bool,
    original_enable: Option<u32>,
    original_server: Option<String>,
    original_override: Option<String>,
    original_quic: Vec<(&'static str, Option<u32>)>,
}

impl ProxyGuard {
    /// Включает системный прокси Windows через нативный Win32 API реестра,
    /// а также отключает UDP QUIC (HTTP/3) в Chromium-браузерах, принуждая YouTube к стабильному 4K TCP.
    /// Сохраняет исходные настройки пользователя и гарантированно восстанавливает их (RAII).
    pub fn enable(proxy_addr: &str, block_quic: bool) -> Result<Self> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        // 1. Считываем и сохраняем исходное состояние сети пользователя
        let (original_enable, original_server, original_override) = match hkcu.open_subkey_with_flags(SUBKEY, KEY_READ) {
            Ok(key) => {
                let enable = key.get_value("ProxyEnable").ok();
                let server = key.get_value("ProxyServer").ok();
                let override_list = key.get_value("ProxyOverride").ok();
                (enable, server, override_list)
            }
            Err(e) => {
                warn!("Не удалось прочитать исходные настройки прокси: {}", e);
                (None, None, None)
            }
        };

        // 2. Записываем настройки нашего локального прокси
        let (key, _) = hkcu.create_subkey_with_flags(SUBKEY, KEY_WRITE)?;
        key.set_value("ProxyServer", &proxy_addr)?;
        key.set_value("ProxyOverride", &DEFAULT_BYPASS)?;
        key.set_value("ProxyEnable", &1u32)?;

        // 3. Блокируем проблемный UDP QUIC (Chrome, Edge, Yandex) без необходимости прав админа
        let original_quic = if block_quic {
            enable_quic_block()
        } else {
            Vec::new()
        };

        notify_windows_inet();
        info!("Системный прокси Windows активирован -> {}", proxy_addr);

        Ok(Self {
            active: true,
            original_enable,
            original_server,
            original_override,
            original_quic,
        })
    }

    pub fn disable(&mut self) {
        if self.active {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            if let Ok((key, _)) = hkcu.create_subkey_with_flags(SUBKEY, KEY_WRITE) {
                // Восстанавливаем ProxyEnable
                let orig_enable = self.original_enable.unwrap_or(0);
                let _ = key.set_value("ProxyEnable", &orig_enable);

                // Восстанавливаем ProxyServer
                if let Some(ref server) = self.original_server {
                    let _ = key.set_value("ProxyServer", server);
                } else {
                    let _ = key.delete_value("ProxyServer");
                }

                // Восстанавливаем ProxyOverride
                if let Some(ref override_list) = self.original_override {
                    let _ = key.set_value("ProxyOverride", override_list);
                } else {
                    let _ = key.delete_value("ProxyOverride");
                }
            }

            // Восстанавливаем исходные политики браузеров
            restore_quic_block(&self.original_quic);

            notify_windows_inet();
            self.active = false;
            info!("Системный прокси Windows отключен. Исходные настройки сети восстановлены.");
        }
    }
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        self.disable();
    }
}

fn enable_quic_block() -> Vec<(&'static str, Option<u32>)> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let mut original = Vec::new();

    for &subkey in BROWSER_POLICY_KEYS {
        let orig = hkcu.open_subkey_with_flags(subkey, KEY_READ)
            .ok()
            .and_then(|k| k.get_value::<u32, _>("QuicAllowed").ok());
        original.push((subkey, orig));

        if let Ok((key, _)) = hkcu.create_subkey_with_flags(subkey, KEY_WRITE) {
            let _ = key.set_value("QuicAllowed", &0u32);
        }
    }

    info!("✓ Блокировка QUIC (HTTP/3 UDP) активирована для Chrome, Edge, Yandex (YouTube переключен на стабильный TCP)");
    original
}

fn restore_quic_block(original: &[(&'static str, Option<u32>)]) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for &(subkey, orig_val) in original {
        if let Ok((key, _)) = hkcu.create_subkey_with_flags(subkey, KEY_WRITE) {
            if let Some(val) = orig_val {
                let _ = key.set_value("QuicAllowed", &val);
            } else {
                let _ = key.delete_value("QuicAllowed");
            }
        }
    }
}

/// Аварийное отключение прокси и сброс политик (используется в panic hook и close handler)
pub fn disable_raw() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey_with_flags(SUBKEY, KEY_WRITE) {
        let _ = key.set_value("ProxyEnable", &0u32);
    }

    // Чистим политики браузеров при аварийном выходе
    for &subkey in BROWSER_POLICY_KEYS {
        if let Ok((key, _)) = hkcu.create_subkey_with_flags(subkey, KEY_WRITE) {
            let _ = key.delete_value("QuicAllowed");
        }
    }

    notify_windows_inet();
}

/// Уведомляет браузеры (Chrome, Edge, Яндекс), чтобы они подхватили настройки мгновенно
#[cfg(target_os = "windows")]
fn notify_windows_inet() {
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            hInternet: *mut core::ffi::c_void,
            dwOption: u32,
            lpBuffer: *mut core::ffi::c_void,
            dwBufferLength: u32,
        ) -> i32;
    }

    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const INTERNET_OPTION_REFRESH: u32 = 37;

    unsafe {
        InternetSetOptionW(
            core::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            core::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            core::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            core::ptr::null_mut(),
            0,
        );
    }
}

#[cfg(not(target_os = "windows"))]
fn notify_windows_inet() {}
