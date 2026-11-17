mod sysproxy;

use anyhow::Result;
use smoke_core::dns::DnsResolver;
use smoke_core::scanner::auto_select_strategy;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Страховка №1: если произойдет критическая паника — сбрасываем прокси Windows
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        sysproxy::disable_raw();
        default_panic(info);
    }));

    info!("=== Запуск Smoke ===");
    let dns = DnsResolver::new_doh();
    let best_strategy = auto_select_strategy(&dns).await;

    let bind_str = "127.0.0.1:1080";
    let bind_addr: SocketAddr = bind_str.parse()?;

    // Включаем системный прокси Windows
    let mut proxy_guard = sysproxy::ProxyGuard::enable(bind_str)?;
    info!("Все готово! Открывай браузер. Для выхода нажми Ctrl + C.");

    // Страховка №2: корректно ловим Ctrl + C, чтобы чисто восстановить сеть
    tokio::select! {
        res = smoke_core::socks5::run_server(bind_addr, dns, best_strategy) => {
            res?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Получен сигнал остановки (Ctrl + C)...");
        }
    }

    proxy_guard.disable();
    Ok(())
}
