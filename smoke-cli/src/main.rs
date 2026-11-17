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
    version = "0.2.0"
)]
struct Args {
    /// Адрес и порт для запуска прокси
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    bind: String,

    /// Стратегия десинхронизации (auto, tls-record, sni-middle, fake-ttl, none)
    #[arg(short, long, value_enum, default_value = "auto")]
    strategy: StrategyArg,

    /// TTL для стратегии fake-ttl (по умолчанию 3)
    #[arg(long, default_value = "3")]
    fake_ttl: u32,

    /// Не включать системный прокси Windows (для ручной настройки в приложениях)
    #[arg(long)]
    no_sysproxy: bool,

    /// Подробный вывод логов (DEBUG)
    #[arg(short, long)]
    verbose: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum StrategyArg {
    Auto,
    TlsRecord,
    SniMiddle,
    FakeTtl,
    None,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    println!(
        r#"
   _____                     __          
  / ___/ ____ ___   ____    / /__ ___    
  \__ \ / __ `__ \ / __ \  / //_// _ \   
 ___/ // / / / / // /_/ / / ,<  /  __/   
/____//_/ /_/ /_/ \____/ /_/|_| \___/    
    High-Performance DPI Bypass Engine v0.2.0
"#
    );

    let bind_addr: SocketAddr = args.bind.parse()?;
    let dns = DnsResolver::new_doh();

    let strategy = match args.strategy {
        StrategyArg::Auto => auto_select_strategy(&dns).await,
        StrategyArg::TlsRecord => SplitStrategy::TlsRecordAndSni,
        StrategyArg::SniMiddle => SplitStrategy::SniMiddle { fallback_pos: 2 },
        StrategyArg::FakeTtl => SplitStrategy::FakeTtl {
            fake_ttl: args.fake_ttl,
            fallback_pos: 2,
        },
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
    info!("Для остановки и восстановления настроек нажмите Ctrl + C.");

    // Страховка №2: корректно ловим Ctrl + C для чистого восстановления
    tokio::select! {
        res = smoke_core::socks5::run_server(bind_addr, dns, strategy) => {
            if let Err(e) = res {
                tracing::error!("Ошибка работы сервера: {}", e);
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
