use anyhow::Result;
use std::process::Command;
use tracing::{info, warn};

const REG_PATH: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const BYPASS_LIST: &str = "localhost;127.*;10.*;192.168.*;172.16.*;<local>";

pub struct ProxyGuard {
    active: bool,
}

impl ProxyGuard {
    /// Включает системный прокси Windows и возвращает сторожевой объект (RAII),
    /// который гарантированно выключит прокси при выходе или панике.
    pub fn enable(proxy_addr: &str) -> Result<Self> {
        run_reg(&["add", REG_PATH, "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxy_addr, "/f"])?;
        run_reg(&["add", REG_PATH, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", BYPASS_LIST, "/f"])?;
        run_reg(&["add", REG_PATH, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"])?;

        notify_windows_inet();
        info!("Системный прокси Windows включен -> {}", proxy_addr);

        Ok(Self { active: true })
    }

    pub fn disable(&mut self) {
        if self.active {
            disable_raw();
            self.active = false;
            info!("Системный прокси Windows отключен. Настройки сети восстановлены.");
        }
    }
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        self.disable();
    }
}

/// Аварийное отключение прокси (используется также в panic hook)
pub fn disable_raw() {
    let _ = run_reg(&["add", REG_PATH, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"]);
    notify_windows_inet();
}

fn run_reg(args: &[&str]) -> Result<()> {
    let status = Command::new("reg").args(args).output()?;
    if !status.status.success() {
        warn!("Команда reg вернула предупреждение");
    }
    Ok(())
}

/// Уведомляет браузеры (Chrome, Edge, Яндекс), чтобы они подхватили прокси мгновенно без перезапуска
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
        InternetSetOptionW(core::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, core::ptr::null_mut(), 0);
        InternetSetOptionW(core::ptr::null_mut(), INTERNET_OPTION_REFRESH, core::ptr::null_mut(), 0);
    }
}

#[cfg(not(target_os = "windows"))]
fn notify_windows_inet() {}
