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
        opts.timeout = Duration::from_millis(800);
        opts.attempts = 1;
        opts.use_hosts_file = true;
        opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;

        // Основные каналы: Google DoH и Cloudflare DoH
        let doh_google = TokioAsyncResolver::tokio(ResolverConfig::google_https(), opts.clone());
        let doh_cloudflare = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), opts.clone());
        let doh_quad9 = TokioAsyncResolver::tokio(ResolverConfig::quad9_https(), opts);

        Self {
            doh_google: Arc::new(doh_google),
            doh_cloudflare: Arc::new(doh_cloudflare),
            doh_quad9: Arc::new(doh_quad9),
        }
    }

    pub async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr> {
        let addrs = self.resolve_all(domain, port).await?;
        addrs
            .into_iter()
            .next()
            .ok_or_else(|| SmokeError::ResolutionFailed(domain.to_string()))
    }

    /// Возвращает список всех разрешенных IPv4-адресов (до 4 узлов) для автоматической ротации при недоступности одного из IP
    pub async fn resolve_all(&self, domain: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        // Параллельная гонка между Google DoH и Cloudflare DoH:
        // Если провайдер замедляет или блокирует один из них — второй отвечает за считанные миллисекунды!
        let g_res = self.doh_google.clone();
        let c_res = self.doh_cloudflare.clone();
        let d1 = domain.to_string();
        let d2 = domain.to_string();

        let race_fut = async {
            tokio::select! {
                res_g = Self::try_lookup_all(&g_res, &d1) => {
                    if let Some(ips) = res_g {
                        return Some(ips);
                    }
                    Self::try_lookup_all(&c_res, &d1).await
                }
                res_c = Self::try_lookup_all(&c_res, &d2) => {
                    if let Some(ips) = res_c {
                        return Some(ips);
                    }
                    Self::try_lookup_all(&g_res, &d2).await
                }
            }
        };

        if let Ok(Some(ips)) = tokio::time::timeout(Duration::from_millis(1200), race_fut).await {
            debug!("DoH Fast-Race: {} -> {:?} ({} IP)", domain, ips[0], ips.len());
            return Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect());
        }

        // Резерв 1: Quad9 DoH (если Google и Cloudflare одновременно недоступны)
        if let Some(ips) = Self::try_lookup_all(&self.doh_quad9, domain).await {
            debug!("Quad9 DoH: {} -> {:?}", domain, ips[0]);
            return Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect());
        }

        // Резерв 2: Системный резолвер (чтобы интернет никогда не падал)
        warn!("DoH недоступен для {}, используем системный DNS", domain);
        let addrs: Vec<SocketAddr> = lookup_host((domain, port))
            .await
            .map_err(SmokeError::Io)?
            .filter(|a| a.is_ipv4())
            .take(4)
            .collect();

        if addrs.is_empty() {
            return Err(SmokeError::ResolutionFailed(domain.to_string()));
        }

        debug!("Резервный DNS: {} -> {}", domain, addrs[0].ip());
        Ok(addrs)
    }

    async fn try_lookup_all(resolver: &TokioAsyncResolver, domain: &str) -> Option<Vec<IpAddr>> {
        let lookup = resolver.lookup_ip(domain).await.ok()?;
        let mut ips: Vec<IpAddr> = lookup.iter().filter(|ip| ip.is_ipv4()).take(4).collect();
        if ips.is_empty() {
            if let Some(first) = lookup.iter().next() {
                ips.push(first);
            }
        }
        if ips.is_empty() {
            None
        } else {
            Some(ips)
        }
    }
}
