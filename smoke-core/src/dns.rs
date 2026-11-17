use crate::error::{Result, SmokeError};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::lookup_host;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct DnsResolver {
    doh_google: Arc<TokioAsyncResolver>,
    doh_cloudflare: Arc<TokioAsyncResolver>,
    doh_quad9: Arc<TokioAsyncResolver>,
}

impl DnsResolver {
    pub fn new_doh() -> Self {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 4096;
        opts.timeout = Duration::from_millis(1500);
        opts.attempts = 1;
        opts.use_hosts_file = true;
        opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;

        // Основной шифрованный канал: Google DoH (8.8.8.8 / 8.8.4.4)
        let doh_google = TokioAsyncResolver::tokio(ResolverConfig::google_https(), opts.clone());

        // Второй шифрованный канал: Cloudflare DoH (1.1.1.1 / 1.0.0.1)
        let doh_cloudflare = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), opts.clone());

        // Резервный шифрованный канал: Quad9 DoH (9.9.9.9)
        let doh_quad9 = TokioAsyncResolver::tokio(ResolverConfig::quad9_https(), opts);

        Self {
            doh_google: Arc::new(doh_google),
            doh_cloudflare: Arc::new(doh_cloudflare),
            doh_quad9: Arc::new(doh_quad9),
        }
    }

    pub async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr> {
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        // 1. Пытаемся через Google DoH
        if let Some(ip) = Self::try_lookup(&self.doh_google, domain).await {
            debug!("Google DoH: {} -> {}", domain, ip);
            return Ok(SocketAddr::new(ip, port));
        }

        // 2. Если Google DoH блокируется — пробуем Cloudflare DoH
        if let Some(ip) = Self::try_lookup(&self.doh_cloudflare, domain).await {
            debug!("Cloudflare DoH: {} -> {}", domain, ip);
            return Ok(SocketAddr::new(ip, port));
        }

        // 3. Если Cloudflare тоже недоступен — пробуем Quad9 DoH
        if let Some(ip) = Self::try_lookup(&self.doh_quad9, domain).await {
            debug!("Quad9 DoH: {} -> {}", domain, ip);
            return Ok(SocketAddr::new(ip, port));
        }

        // 4. Резерв через системный резолвер (чтобы связь не обрывалась)
        warn!("Все DoH недоступны для {}, используем системный DNS", domain);
        let addr = lookup_host((domain, port))
            .await
            .map_err(SmokeError::Io)?
            .find(|a| a.is_ipv4())
            .ok_or_else(|| SmokeError::ResolutionFailed(domain.to_string()))?;

        debug!("Резервный DNS: {} -> {}", domain, addr.ip());
        Ok(addr)
    }

    async fn try_lookup(resolver: &TokioAsyncResolver, domain: &str) -> Option<IpAddr> {
        let lookup = resolver.lookup_ip(domain).await.ok()?;
        lookup
            .iter()
            .find(|ip| ip.is_ipv4())
            .or_else(|| lookup.iter().next())
    }
}
