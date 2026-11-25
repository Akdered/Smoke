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
    version = "0.6.0"
)]
struct Args {
    /// Адрес и порт для запуска прокси
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    bind: String,

    /// Пресет обхода (по умолчанию: auto — умный самообучающийся режим без флаппинга)
    #[arg(short, long, value_enum, default_value = "auto")]
    preset: PresetArg,

    /// Принудительно зафиксировать конкретную стратегию (переопределяет пресет)
    #[arg(short, long, value_enum)]
    strategy: Option<StrategyArg>,

    /// Запустить предварительный бенчмарк сети перед стартом
    #[arg(long)]
    scan: bool,

    /// Скрыть окно консоли и работать в фоновом режиме
    #[arg(short, long)]
    minimized: bool,

    /// Не включать системный прокси Windows (для ручной настройки в приложениях)
    #[arg(long)]
    no_sysproxy: bool,

    /// Экстренно отключить системный прокси Windows и выйти
    #[arg(long)]
    clean: bool,

    /// Внутренний режим процесса-сторожа для гарантированной очистки реестра при аварийном завершении
    #[arg(long, hide = true)]
    watchdog: Option<u32>,

    /// Подробный вывод логов (DEBUG)
    #[arg(short, long)]
    verbose: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum PresetArg {
    /// Умный адаптивный режим v0.6 (Direct-First + Anti-Flapping)
    Auto,
    /// Пресет для Ростелеком / GPON роутеров (TlsRecMicroSni)
    Rtk,
    /// Пресет с отправкой фейкового ClientHello (FakeTls4)
    Mobile,
    /// Пресет для Discord (TlsRecordFrag2)
    Discord,
    /// Ультимативный режим OOB + TLS Record (TlsRecOobSni)
    Ultra,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum StrategyArg {
    /// 4 TLS-рекорда с 1-байтным микро-разрезом центра SNI + смещенный TCP-сплит
    TlsRecMicroSni,
    /// Фрагментация TLS-рекорда + односегментный Urgent OOB байт в SNI
    TlsRecOobSni,
    /// Фальшивый ClientHello (www.vk.com) с TTL=4 через TransmitFile + Fast Retransmit
    FakeTls4,
    /// Фальшивый ClientHello (www.vk.com) с TTL=6 через TransmitFile + Fast Retransmit
    FakeTls6,
    /// Мульти-рекорды TLS (3-4 фрагмента)
    TlsRecordFrag,
    /// Двухзвенный TLS рекорд + сплит SNI
    TlsRecordFrag2,
    /// Разноуровневый разрез TLS рекорда по центру SNI
    TlsRecordFragSni,
    /// Односегментный TCP Urgent Pointer (MSG_OOB) в центре SNI
    OobSni,
    /// Чистый TCP-сплит в середине домена
    TcpSplitSni,
    /// Disorder с TTL=3 + 3-сегментный Fast Retransmit
    Disorder3,
    /// Disorder с TTL=2 + 3-сегментный Fast Retransmit
    Disorder2,
    /// Disorder с TTL=1 + 3-сегментный Fast Retransmit
    Disorder1,
    /// Disorder до середины SNI с TTL=1
    DisorderSni,
    /// Disorder до середины SNI с TTL=2
    DisorderSni2,
    /// Двойной TCP-сплит (2-й байт + центр SNI)
    TcpSplit2,
    /// Чистый TCP-сплит после 1-го байта
    TcpSplit1,
    /// Комбо: мульти-рекорды TLS + Disorder
    Combo,
    /// Без обработки (прямая передача)
    None,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Внутренний легковесный сторож (работает БЕЗ инициализации Tokio с 0% CPU и < 1.5 МБ ОЗУ)
    if let Some(parent_pid) = args.watchdog {
        sysproxy::run_watchdog_for_pid(parent_pid);
        return Ok(());
    }

    // Экстренный сброс настроек сети
    if args.clean {
        sysproxy::restore_or_clean();
        println!("Системный прокси Windows полностью очищен. Настройки сети восстановлены.");
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async_main(args))
}

async fn async_main(args: Args) -> Result<()> {
    if args.minimized {
        hide_console_window();
    }

    let default_filter = if args.verbose {
        "debug"
    } else {
        "info,hickory_proto=error,hickory_resolver=error"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

    // Страховка №1: при любой критической панике восстанавливаем прокси Windows
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        sysproxy::restore_or_clean();
        default_panic(info);
    }));

    // Страховка №2: перехватываем закрытие консоли крестиком [X] / выключение ПК
    setup_console_close_handler();

    // Высокоточный таймер ядра Windows (1 мс)
    enable_high_precision_timer();

    println!(
        r#"
   _____                     __          
  / ___/ ____ ___   ____    / /__ ___    
  \__ \ / __ `__ \ / __ \  / //_// _ \   
 ___/ // / / / / // /_/ / / ,<  /  __/   
/____//_/ /_/ /_/ \____/ /_/|_| \___/    
             by Akdered
    High-Performance DPI Bypass Engine v0.6.0
"#
    );

    let bind_addr: SocketAddr = args.bind.parse()?;
    let dns = DnsResolver::new_doh();

    let fixed_strategy: Option<SplitStrategy> = if let Some(strat) = args.strategy {
        Some(match strat {
            StrategyArg::TlsRecMicroSni => SplitStrategy::TlsRecMicroSni,
            StrategyArg::TlsRecOobSni => SplitStrategy::TlsRecOobSni,
            StrategyArg::FakeTls4 => SplitStrategy::FakeTls4,
            StrategyArg::FakeTls6 => SplitStrategy::FakeTls6,
            StrategyArg::TlsRecordFrag => SplitStrategy::TlsRecordFrag,
            StrategyArg::TlsRecordFrag2 => SplitStrategy::TlsRecordFrag2,
            StrategyArg::TlsRecordFragSni => SplitStrategy::TlsRecordFragSni,
            StrategyArg::OobSni => SplitStrategy::OobSni,
            StrategyArg::TcpSplitSni => SplitStrategy::TcpSplitSni,
            StrategyArg::Disorder3 => SplitStrategy::Disorder3,
            StrategyArg::Disorder2 => SplitStrategy::Disorder2,
            StrategyArg::Disorder1 => SplitStrategy::Disorder1,
            StrategyArg::DisorderSni => SplitStrategy::DisorderSni,
            StrategyArg::DisorderSni2 => SplitStrategy::DisorderSni2,
            StrategyArg::TcpSplit2 => SplitStrategy::TcpSplit2,
            StrategyArg::TcpSplit1 => SplitStrategy::TcpSplit1,
            StrategyArg::Combo => SplitStrategy::Combo,
            StrategyArg::None => SplitStrategy::None,
        })
    } else if args.scan {
        info!("Запущен бенчмарк стратегий для сети...");
        Some(auto_select_strategy(&dns).await)
    } else {
        match args.preset {
            PresetArg::Auto => None,
            PresetArg::Rtk => Some(SplitStrategy::TlsRecMicroSni),
            PresetArg::Mobile => Some(SplitStrategy::FakeTls4),
            PresetArg::Discord => Some(SplitStrategy::TlsRecordFrag2),
            PresetArg::Ultra => Some(SplitStrategy::TlsRecOobSni),
        }
    };

    if let Some(strat) = fixed_strategy {
        info!("Фиксированный режим десинхронизации: {:?}", strat);
    } else {
        info!("Режим: Smart Adaptive v0.6 (17 техник + FakeTls + Direct-First + защита от флаппинга)");
    }

    let mut proxy_guard = if !args.no_sysproxy {
        Some(sysproxy::ProxyGuard::enable(&args.bind)?)
    } else {
        info!("Системный прокси Windows отключен флагом --no-sysproxy");
        None
    };

    info!(
        "Сервер Smoke готов к работе на http://{} и socks5://{}",
        args.bind, args.bind
    );
    info!("Российские сайты (.ru, VK, Yandex, Ozon, Steam CDN) направляются напрямую без задержек.");
    info!("Для остановки нажмите Ctrl + C или закройте окно.");

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

    disable_high_precision_timer();
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
        sysproxy::restore_or_clean();
        disable_high_precision_timer();
        0
    }

    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
}

#[cfg(not(target_os = "windows"))]
fn setup_console_close_handler() {}

#[cfg(target_os = "windows")]
fn enable_high_precision_timer() {
    #[link(name = "winmm")]
    extern "system" {
        fn timeBeginPeriod(uPeriod: u32) -> u32;
    }
    unsafe {
        timeBeginPeriod(1);
    }
}

#[cfg(not(target_os = "windows"))]
fn enable_high_precision_timer() {}

#[cfg(target_os = "windows")]
fn disable_high_precision_timer() {
    #[link(name = "winmm")]
    extern "system" {
        fn timeEndPeriod(uPeriod: u32) -> u32;
    }
    unsafe {
        timeEndPeriod(1);
    }
}

#[cfg(not(target_os = "windows"))]
fn disable_high_precision_timer() {}
