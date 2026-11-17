use anyhow::Result;
use tracing::{info, warn};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const DEFAULT_BYPASS: &str = "localhost;127.*;10.*;192.168.*;172.16.*;<local>";

pub struct ProxyGuard {
    active: bool,
    original_enable: Option<u32>,
    original_server: Option<String>,
    original_override: Option<String>,
}

impl ProxyGuard {
    /// Включает системный прокси Windows через нативный Win32 API реестра.
    /// Сохраняет исходные настройки пользователя и гарантированно восстанавливает их (RAII).
    pub fn enable(proxy_addr: &str) -> Result<Self> {
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

        notify_windows_inet();
        info!("Системный прокси Windows активирован -> {}", proxy_addr);

        Ok(Self {
            active: true,
            original_enable,
            original_server,
            original_override,
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

/// Аварийное отключение прокси (используется в panic hook)
pub fn disable_raw() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey_with_flags(SUBKEY, KEY_WRITE) {
        let _ = key.set_value("ProxyEnable", &0u32);
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
