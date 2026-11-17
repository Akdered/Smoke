mod sysproxy;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use smoke_core::desync::SplitStrategy;
use smoke_core::dns::DnsResolver;
use smoke_core::scanner::auto_select_strategy;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "smoke",
    about = "Высокоскоростной DPI-bypass прокси для Windows",
    version = "0.5.0"
)]
struct Args {
    /// Адрес и порт для запуска прокси
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    bind: String,

    /// Пресет обхода (по умолчанию: auto — умный самообучающийся режим)
    #[arg(short, long, value_enum, default_value = "auto")]
    preset: PresetArg,

    /// Принудительно зафиксировать конкретную стратегию (переопределяет пресет)
    #[arg(short, long, value_enum)]
    strategy: Option<StrategyArg>,

    /// Запустить предварительный бенчмарк сети перед стартом
    #[arg(long)]
    scan: bool,

    /// Разрешить протокол QUIC (HTTP/3 UDP) в браузерах (по умолчанию заблокирован для быстрого 4K видео)
    #[arg(long)]
    allow_quic: bool,

    /// Скрыть окно консоли и работать в фоновом режиме
    #[arg(short, long)]
    minimized: bool,

    /// Не включать системный прокси Windows (для ручной настройки в приложениях)
    #[arg(long)]
    no_sysproxy: bool,

    /// Экстренно отключить системный прокси Windows и выйти
    #[arg(long)]
    clean: bool,

    /// Подробный вывод логов (DEBUG)
    #[arg(short, long)]
    verbose: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum PresetArg {
    /// Умный адаптивный режим: автоматическое переключение стратегий на лету (в 1 клик для всех)
    Auto,
    /// Пресет для Ростелеком / EcoFilter (TlsRecordFrag)
    Rtk,
    /// Пресет для мобильных операторов МТС/Билайн/Мегафон (Disorder1)
    Mobile,
    /// Пресет для Discord (Disorder1)
    Discord,
    /// Ультимативный комбо-режим против жестких ТСПУ (Combo)
    Ultra,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum StrategyArg {
    /// Мульти-рекорды TLS (3-4 фрагмента)
    TlsRecordFrag,
    /// Двухзвенный TLS рекорд (1 байт в первом рекорде)
    TlsRecordFrag2,
    /// Разрез TLS рекорда перед SNI
    TlsRecordFragSni,
    /// Трюк Disorder: 1-й байт с TTL=1, ретрансмит через SACK
    Disorder1,
    /// Трюк Disorder: 1-й байт с TTL=2 (для роутеров и GPON-модемов)
    Disorder2,
    /// Трюк Disorder: 1-й байт с TTL=3 (для глубоких домашних сетей)
    Disorder3,
    /// Трюк Disorder до середины SNI с TTL=1, ретрансмит через SACK
    DisorderSni,
    /// Трюк Disorder до середины SNI с TTL=2, ретрансмит через SACK
    DisorderSni2,
    /// Инъекция TCP Urgent Pointer (OOB) байта в середине SNI
    OobSni,
    /// Чистый TCP-сплит после 1-го байта
    TcpSplit1,
    /// Чистый TCP-сплит после 2-го байта (0x16 0x03)
    TcpSplit2,
    /// Чистый TCP-сплит в середине домена
    TcpSplitSni,
    /// Комбо: 2 TLS-рекорда + TCP Disorder
    Combo,
    /// Без обработки (для диагностики)
    None,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Экстренный сброс настроек сети
    if args.clean {
        sysproxy::disable_raw();
        println!("Системный прокси Windows отключен. Настройки сети сброшены.");
        return Ok(());
    }

    if args.minimized {
        hide_console_window();
    }

    let default_filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

    // Страховка №1: при любой критической панике сбрасываем прокси Windows
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        sysproxy::disable_raw();
        default_panic(info);
    }));

    // Страховка №2: перехватываем закрытие консоли крестиком [X]
    setup_console_close_handler();

    println!(
        r#"
   _____                     __          
  / ___/ ____ ___   ____    / /__ ___    
  \__ \ / __ `__ \ / __ \  / //_// _ \   
 ___/ // / / / / // /_/ / / ,<  /  __/   
/____//_/ /_/ /_/ \____/ /_/|_| \___/    
             by Akdered
    High-Performance DPI Bypass Engine v0.5.0
"#
    );

    let bind_addr: SocketAddr = args.bind.parse()?;
    let dns = DnsResolver::new_doh();

    // Определение стратегии:
    // По умолчанию (args.preset == Auto и strategy == None) включается Smart Adaptive Engine!
    // Он стартует за 2 мс и сам адаптируется под провайдера на лету.
    let fixed_strategy: Option<SplitStrategy> = if let Some(strat) = args.strategy {
        Some(match strat {
            StrategyArg::TlsRecordFrag => SplitStrategy::TlsRecordFrag,
            StrategyArg::TlsRecordFrag2 => SplitStrategy::TlsRecordFrag2,
            StrategyArg::TlsRecordFragSni => SplitStrategy::TlsRecordFragSni,
            StrategyArg::Disorder1 => SplitStrategy::Disorder1,
            StrategyArg::Disorder2 => SplitStrategy::Disorder2,
            StrategyArg::Disorder3 => SplitStrategy::Disorder3,
            StrategyArg::DisorderSni => SplitStrategy::DisorderSni,
            StrategyArg::DisorderSni2 => SplitStrategy::DisorderSni2,
            StrategyArg::OobSni => SplitStrategy::OobSni,
            StrategyArg::TcpSplit1 => SplitStrategy::TcpSplit1,
            StrategyArg::TcpSplit2 => SplitStrategy::TcpSplit2,
            StrategyArg::TcpSplitSni => SplitStrategy::TcpSplitSni,
            StrategyArg::Combo => SplitStrategy::Combo,
            StrategyArg::None => SplitStrategy::None,
        })
    } else if args.scan {
        info!("Запущен бенчмарк стратегий для сети...");
        Some(auto_select_strategy(&dns).await)
    } else {
        match args.preset {
            PresetArg::Auto => None, // None = Smart Adaptive Engine!
            PresetArg::Rtk => Some(SplitStrategy::TlsRecordFrag),
            PresetArg::Mobile => Some(SplitStrategy::Disorder1),
            PresetArg::Discord => Some(SplitStrategy::Disorder1),
            PresetArg::Ultra => Some(SplitStrategy::Combo),
        }
    };

    if let Some(strat) = fixed_strategy {
        info!("Фиксированный режим десинхронизации: {:?}", strat);
    } else {
        info!("Режим: Smart Adaptive Engine (13 техник обхода, автосохранение на диск)");
    }

    // Включаем системный прокси Windows и блокировку UDP QUIC
    let mut proxy_guard = if !args.no_sysproxy {
        Some(sysproxy::ProxyGuard::enable(&args.bind, !args.allow_quic)?)
    } else {
        info!("Системный прокси Windows отключен флагом --no-sysproxy");
        None
    };

    info!(
        "Сервер Smoke готов к работе на http://{} и socks5://{}",
        args.bind, args.bind
    );
    info!("Для остановки нажмите Ctrl + C или закройте окно.");

    // Страховка №3: ловим Ctrl + C
    tokio::select! {
        res = smoke_core::socks5::run_server(bind_addr, dns, fixed_strategy) => {
            if let Err(e) = res {
                tracing::error!("Ошибка работы сервера: {}", e);
                eprintln!("\n[!] ОШИБКА: Не удалось запустить сервер на {}.", bind_addr);
                eprintln!("    Возможно, порт 1080 уже занят. Закройте предыдущую копию или укажите: smoke --bind 127.0.0.1:1081\n");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Получен сигнал остановки (Ctrl + C)...");
        }
    }

    if let Some(mut guard) = proxy_guard.take() {
        guard.disable();
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn hide_console_window() {
    #[link(name = "user32")]
    extern "system" {
        fn ShowWindow(hWnd: *mut core::ffi::c_void, nCmdShow: i32) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleWindow() -> *mut core::ffi::c_void;
    }

    const SW_HIDE: i32 = 0;
    unsafe {
        let hwnd = GetConsoleWindow();
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_HIDE);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn hide_console_window() {}

#[cfg(target_os = "windows")]
fn setup_console_close_handler() {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }

    unsafe extern "system" fn handler(_ctrl_type: u32) -> i32 {
        sysproxy::disable_raw();
        0
    }

    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
}

#[cfg(not(target_os = "windows"))]
fn setup_console_close_handler() {}
