use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Обход системного прокси на уровне ОС для локальных сетей, российских доменов и игровых CDN:
/// WinINet, Браузеры, Electron и Rust reqwest пускают их напрямую с нулевой задержкой.
const DEFAULT_BYPASS: &str = "localhost;127.*;10.*;192.168.*;172.16.*;*.ru;*.su;*.xn--p1ai;*.by;*.kz;vk.com;*.vk.com;*.userapi.com;*.vkuser.net;*.yandex.net;*.yastatic.net;*.steamcontent.com;<local>";

#[derive(Serialize, Deserialize, Default)]
struct ProxyBackup {
    enable: Option<u32>,
    server: Option<String>,
    override_list: Option<String>,
}

pub struct ProxyGuard {
    active: bool,
}

impl ProxyGuard {
    /// Включает системный прокси Windows, сохраняет резервную копию исходных настроек на диск
    /// и запускает фонового сторожа (`--watchdog`), который гарантированно очистит реестр даже при убийстве процесса через Диспетчер задач!
    pub fn enable(proxy_addr: &str) -> Result<Self> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        // Сохраняем исходные настройки ТОЛЬКО если нет невосстановленного бэкапа от аварийного падения
        // и текущий ProxyServer не указывает на наш же локальный порт!
        if get_backup_path().map_or(true, |p| !p.exists()) {
            let backup = match hkcu.open_subkey_with_flags(SUBKEY, KEY_READ) {
                Ok(key) => {
                    let enable: Option<u32> = key.get_value("ProxyEnable").ok();
                    let server: Option<String> = key.get_value("ProxyServer").ok();
                    let override_list: Option<String> = key.get_value("ProxyOverride").ok();

                    // Защита от самозацикливания: если в реестре остался наш же адрес 127.0.0.1:1080 — считаем исходным чистую сеть
                    let is_our_leftover = server
                        .as_deref()
                        .map(|s| s.contains(proxy_addr) || s.contains("127.0.0.1:1080"))
                        .unwrap_or(false);

                    if is_our_leftover {
                        ProxyBackup {
                            enable: Some(0),
                            server: None,
                            override_list: None,
                        }
                    } else {
                        ProxyBackup {
                            enable,
                            server,
                            override_list,
                        }
                    }
                }
                Err(e) => {
                    warn!("Не удалось прочитать исходные настройки прокси: {}", e);
                    ProxyBackup::default()
                }
            };
            save_backup(&backup);
        }

        let (key, _) = hkcu.create_subkey_with_flags(SUBKEY, KEY_WRITE)?;
        key.set_value("ProxyServer", &proxy_addr)?;
        key.set_value("ProxyOverride", &DEFAULT_BYPASS)?;
        key.set_value("ProxyEnable", &1u32)?;

        notify_windows_inet();
        spawn_cleanup_watchdog();

        info!("Системный прокси Windows активирован -> {} (с защитой Watchdog)", proxy_addr);

        Ok(Self { active: true })
    }

    pub fn disable(&mut self) {
        if self.active {
            restore_or_clean();
            self.active = false;
            info!("Системный прокси Windows отключен. Исходные настройки сети полностью восстановлены.");
        }
    }
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        self.disable();
    }
}

/// Полное восстановление исходных настроек реестра (или идеальная зачистка).
/// Вызывается при штатном выходе, закрытии крестиком [X], панике, `--clean` и из процесса-сторожа `--watchdog`.
pub fn restore_or_clean() {
    let backup = load_backup().unwrap_or(ProxyBackup {
        enable: Some(0),
        server: None,
        override_list: None,
    });

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey_with_flags(SUBKEY, KEY_WRITE) {
        let orig_enable = backup.enable.unwrap_or(0);
        let _ = key.set_value("ProxyEnable", &orig_enable);

        if let Some(ref server) = backup.server {
            let _ = key.set_value("ProxyServer", server);
        } else {
            let _ = key.delete_value("ProxyServer");
        }

        if let Some(ref override_list) = backup.override_list {
            let _ = key.set_value("ProxyOverride", override_list);
        } else {
            let _ = key.delete_value("ProxyOverride");
        }
    }

    delete_backup();
    notify_windows_inet();
}

fn get_backup_path() -> Option<PathBuf> {
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let dir = PathBuf::from(local_appdata).join("Smoke");
        let _ = std::fs::create_dir_all(&dir);
        Some(dir.join("proxy_backup.json"))
    } else {
        None
    }
}

fn save_backup(backup: &ProxyBackup) {
    if let Some(path) = get_backup_path() {
        if let Ok(json) = serde_json::to_string_pretty(backup) {
            let _ = std::fs::write(path, json);
        }
    }
}

fn load_backup() -> Option<ProxyBackup> {
    let path = get_backup_path()?;
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn delete_backup() {
    if let Some(path) = get_backup_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Запускает легковесный скрытый процесс-сторож (`0% CPU`), который ждет в ядре завершения основного `smoke.exe`
/// и гарантированно чистит системный прокси даже после `Диспетчер задач -> Снять задачу` (`TerminateProcess`).
#[cfg(target_os = "windows")]
fn spawn_cleanup_watchdog() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    if let Ok(exe) = std::env::current_exe() {
        let pid_str = std::process::id().to_string();
        let _ = std::process::Command::new(exe)
            .args(["--watchdog", &pid_str])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
}

#[cfg(not(target_os = "windows"))]
fn spawn_cleanup_watchdog() {}

/// Блокируется в ядре ОС с 0% потребления CPU до тех пор, пока родительский процесс `parent_pid` не завершится,
/// после чего мгновенно восстанавливает сетевые настройки Windows и завершается сам.
#[cfg(target_os = "windows")]
pub fn run_watchdog_for_pid(parent_pid: u32) {
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut core::ffi::c_void;
        fn WaitForSingleObject(hHandle: *mut core::ffi::c_void, dwMilliseconds: u32) -> u32;
        fn CloseHandle(hObject: *mut core::ffi::c_void) -> i32;
    }

    const SYNCHRONIZE: u32 = 0x00100000;
    const INFINITE: u32 = 0xFFFFFFFF;

    unsafe {
        let handle = OpenProcess(SYNCHRONIZE, 0, parent_pid);
        if !handle.is_null() {
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
        }
    }

    restore_or_clean();
}

#[cfg(not(target_os = "windows"))]
pub fn run_watchdog_for_pid(_parent_pid: u32) {
    restore_or_clean();
}

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
