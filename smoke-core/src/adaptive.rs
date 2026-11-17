use crate::desync::SplitStrategy;
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, info};

pub const DEFAULT_STRATEGIES: &[SplitStrategy] = &[
    SplitStrategy::TlsRecordFrag,
    SplitStrategy::TlsRecordFrag2,
    SplitStrategy::Disorder1,
    SplitStrategy::TcpSplitSni,
    SplitStrategy::OobSni,
    SplitStrategy::TlsRecordFragSni,
    SplitStrategy::DisorderSni,
    SplitStrategy::Combo,
    SplitStrategy::TcpSplit2,
    SplitStrategy::TcpSplit1,
];

/// Интеллектуальный самообучающийся движок:
/// Автоматически подбирает и запоминает рабочие стратегии для каждого домена на лету.
/// Если провайдер сбрасывает соединение — мгновенно переключается на следующую стратегию из арсенала.
#[derive(Debug)]
pub struct AdaptiveEngine {
    domain_cache: RwLock<HashMap<String, usize>>,
}

impl AdaptiveEngine {
    pub fn new() -> Self {
        Self {
            domain_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Получает текущую лучшую стратегию для указанного домена
    pub fn get_strategy(&self, domain: &str) -> SplitStrategy {
        let base = extract_base_domain(domain);
        let cache = self.domain_cache.read().unwrap();
        let idx = cache.get(base).copied().unwrap_or(0);
        DEFAULT_STRATEGIES.get(idx).copied().unwrap_or(SplitStrategy::TlsRecordFrag)
    }

    /// Закрепляет успешную стратегию при подтвержденном ответе от сервера
    pub fn record_success(&self, domain: &str, strategy: SplitStrategy) {
        let base = extract_base_domain(domain);
        if let Some(idx) = DEFAULT_STRATEGIES.iter().position(|&s| s == strategy) {
            let mut cache = self.domain_cache.write().unwrap();
            let prev = cache.insert(base.to_string(), idx);
            if prev != Some(idx) {
                info!("✓ Стратегия {:?} закреплена как успешная для {}", strategy, base);
            } else {
                debug!("Стратегия {:?} подтверждена для {}", strategy, base);
            }
        }
    }

    /// Реагирует на сброс/таймаут ТСПУ: переключает домен на следующую стратегию из арсенала
    pub fn record_failure(&self, domain: &str, failed_strategy: SplitStrategy) -> SplitStrategy {
        let base = extract_base_domain(domain);
        let mut cache = self.domain_cache.write().unwrap();
        let cur_idx = cache.get(base).copied().unwrap_or(0);
        let next_idx = (cur_idx + 1) % DEFAULT_STRATEGIES.len();
        cache.insert(base.to_string(), next_idx);
        let next_strat = DEFAULT_STRATEGIES[next_idx];
        info!(
            "⚡ ТСПУ заблокировал {:?} для {}. Адаптивно переключаем на -> {:?}",
            failed_strategy, base, next_strat
        );
        next_strat
    }
}

impl Default for AdaptiveEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Выделяет базовый домен (например, "rr3---sn-4g5lzney.googlevideo.com" -> "googlevideo.com")
pub fn extract_base_domain(host: &str) -> &str {
    let clean = host.split(':').next().unwrap_or(host).trim();
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() >= 2 {
        let n = parts.len();
        let s2 = parts[n - 2];
        let s1 = parts[n - 1];
        let len = s2.len() + 1 + s1.len();
        if clean.len() >= len {
            return &clean[clean.len() - len..];
        }
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("www.youtube.com"), "youtube.com");
        assert_eq!(extract_base_domain("rr1---sn-4g5edn6s.googlevideo.com:443"), "googlevideo.com");
        assert_eq!(extract_base_domain("discord.com"), "discord.com");
    }

    #[test]
    fn test_adaptive_failover() {
        let engine = AdaptiveEngine::new();
        let d = "googlevideo.com";
        let s0 = engine.get_strategy(d);
        assert_eq!(s0, DEFAULT_STRATEGIES[0]);

        let s1 = engine.record_failure(d, s0);
        assert_eq!(s1, DEFAULT_STRATEGIES[1]);
        assert_eq!(engine.get_strategy(d), DEFAULT_STRATEGIES[1]);

        engine.record_success(d, s1);
        assert_eq!(engine.get_strategy(d), DEFAULT_STRATEGIES[1]);
    }
}
