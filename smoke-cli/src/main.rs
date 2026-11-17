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
    version = "0.3.1"
)]
struct Args {
    /// Адрес и порт для запуска прокси
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    bind: String,

    /// Стратегия десинхронизации (по умолчанию: tls-record-frag для мгновенного старта)
    #[arg(short, long, value_enum, default_value = "tls-record-frag")]
    strategy: StrategyArg,

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
enum StrategyArg {
    /// Фрагментация TLS Record Layer (разбиение на 3-4 рекорда, максимальная пробиваемость)
    TlsRecordFrag,
    /// Двухзвенная фрагментация TLS Record Layer (1 байт в первом рекорде, максимальная совместимость)
    TlsRecordFrag2,
    /// Двойной TCP-сплит: по заголовку TLS Record + по SNI
    TlsRecord,
    /// Одинарный TCP-сплит посередине SNI
    SniMiddle,
    /// Автоматический подбор стратегии через предварительный зонд сети
    Auto,
    /// Без обработки (для диагностики)
    None,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Если передан флаг --clean — просто сбрасываем системный прокси и выходим
    if args.clean {
        sysproxy::disable_raw();
        println!("Системный прокси Windows отключен. Настройки сети сброшены.");
        return Ok(());
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

    // Страховка №2: перехватываем нажатие на крестик [X], выход из системы или перезагрузку Windows
    setup_console_close_handler();

    println!(
        r#"
   _____                     __          
  / ___/ ____ ___   ____    / /__ ___    
  \__ \ / __ `__ \ / __ \  / //_// _ \   
 ___/ // / / / / // /_/ / / ,<  /  __/   
/____//_/ /_/ /_/ \____/ /_/|_| \___/    
    High-Performance DPI Bypass Engine v0.3.1
"#
    );

    let bind_addr: SocketAddr = args.bind.parse()?;
    let dns = DnsResolver::new_doh();

    // Для мгновенного старта без задержек по умолчанию используем TlsRecordFrag
    let strategy = match args.strategy {
        StrategyArg::TlsRecordFrag => SplitStrategy::TlsRecordFrag,
        StrategyArg::TlsRecordFrag2 => SplitStrategy::TlsRecordFrag2,
        StrategyArg::TlsRecord => SplitStrategy::TlsRecordAndSni,
        StrategyArg::SniMiddle => SplitStrategy::SniMiddle { fallback_pos: 2 },
        StrategyArg::Auto => {
            info!("Запущен автоподбор стратегии для сети...");
            auto_select_strategy(&dns).await
        }
        StrategyArg::None => SplitStrategy::None,
    };

    info!("Активная стратегия десинхронизации: {:?}", strategy);

    // Включаем системный прокси Windows (если не отключено флагом --no-sysproxy)
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
    info!("Для остановки и восстановления настроек нажмите Ctrl + C (или закройте окно).");

    // Страховка №3: корректно ловим Ctrl + C для чистого восстановления
    tokio::select! {
        res = smoke_core::socks5::run_server(bind_addr, dns, strategy) => {
            if let Err(e) = res {
                tracing::error!("Ошибка работы сервера: {}", e);
                eprintln!("\n[!] ОШИБКА: Не удалось запустить сервер на {}.", bind_addr);
                eprintln!("    Возможно, порт 1080 уже занят другой копией Smoke или другим прокси.");
                eprintln!("    Закройте предыдущую копию или укажите другой порт: smoke --bind 127.0.0.1:1081\n");
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

/// Регистрирует низкоуровневый Win32 обработчик закрытия окна консоли [X],
/// завершения сеанса пользователя или перезагрузки Windows
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
        // 0: CTRL_C, 1: CTRL_BREAK, 2: CTRL_CLOSE, 5: CTRL_LOGOFF, 6: CTRL_SHUTDOWN
        sysproxy::disable_raw();
        0 // Возвращаем 0 (FALSE), чтобы Windows продолжила штатный выход
    }

    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
}

#[cfg(not(target_os = "windows"))]
fn setup_console_close_handler() {}
