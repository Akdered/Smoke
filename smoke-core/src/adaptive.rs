use crate::desync::SplitStrategy;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use tracing::{debug, info};

/// Базовый порядок стратегий для большинства веб-сайтов (YouTube, Google CDN, обычные сайты)
pub const DEFAULT_STRATEGIES: &[SplitStrategy] = &[
    SplitStrategy::TlsRecordFrag,
    SplitStrategy::TlsRecordFrag2,
    SplitStrategy::Disorder1,
    SplitStrategy::Disorder2,
    SplitStrategy::TcpSplitSni,
    SplitStrategy::OobSni,
    SplitStrategy::TlsRecordFragSni,
    SplitStrategy::DisorderSni,
    SplitStrategy::DisorderSni2,
    SplitStrategy::Combo,
    SplitStrategy::Disorder3,
    SplitStrategy::TcpSplit2,
    SplitStrategy::TcpSplit1,
];

/// Специализированный порядок стратегий для Discord (API, Gateway, CDN, Updates):
/// По статистике Zapret/ByeDPI в РФ, Disorder1 и Disorder2 пробивают блокировки Discord у подавляющего большинства провайдеров!
pub const DISCORD_STRATEGIES: &[SplitStrategy] = &[
    SplitStrategy::Disorder1,
    SplitStrategy::Disorder2,
    SplitStrategy::TlsRecordFrag2,
    SplitStrategy::TcpSplitSni,
    SplitStrategy::Combo,
    SplitStrategy::DisorderSni,
    SplitStrategy::DisorderSni2,
    SplitStrategy::OobSni,
    SplitStrategy::TlsRecordFrag,
    SplitStrategy::TlsRecordFragSni,
    SplitStrategy::Disorder3,
    SplitStrategy::TcpSplit2,
    SplitStrategy::TcpSplit1,
];

/// Интеллектуальный самообучающийся движок с автосохранением на диск и защитой от флаппинга (Hysteresis):
/// Автоматически подбирает, закрепляет и сохраняет рабочие стратегии для каждого семейства доменов.
#[derive(Debug)]
pub struct AdaptiveEngine {
    domain_cache: RwLock<HashMap<String, usize>>,
    failure_counters: RwLock<HashMap<String, u32>>,
    confirmed_domains: RwLock<HashMap<String, bool>>,
    persistent: bool,
}

impl AdaptiveEngine {
    pub fn new() -> Self {
        let initial_cache = load_cache_from_disk();
        let mut confirmed = HashMap::new();
        for key in initial_cache.keys() {
            confirmed.insert(key.clone(), true);
        }

        Self {
            domain_cache: RwLock::new(initial_cache),
            failure_counters: RwLock::new(HashMap::new()),
            confirmed_domains: RwLock::new(confirmed),
            persistent: true,
        }
    }

    /// Конструктор для тестов без обращения к диску
    pub fn new_in_memory() -> Self {
        Self {
            domain_cache: RwLock::new(HashMap::new()),
            failure_counters: RwLock::new(HashMap::new()),
            confirmed_domains: RwLock::new(HashMap::new()),
            persistent: false,
        }
    }

    pub fn is_discord_family(domain: &str) -> bool {
        let clean = domain.split(':').next().unwrap_or(domain).trim().to_ascii_lowercase();
        clean.contains("discord") || clean == "dis.gd"
    }

    pub fn get_strategies_for(domain: &str) -> &'static [SplitStrategy] {
        if Self::is_discord_family(domain) {
            DISCORD_STRATEGIES
        } else {
            DEFAULT_STRATEGIES
        }
    }

    /// Получает текущую лучшую стратегию для указанного домена
    pub fn get_strategy(&self, domain: &str) -> SplitStrategy {
        let family = extract_family_domain(domain);
        let strategies = Self::get_strategies_for(domain);
        let cache = self.domain_cache.read().unwrap();
        let idx = cache.get(&family).copied().unwrap_or(0);
        strategies.get(idx).copied().unwrap_or(strategies[0])
    }

    /// Закрепляет успешную стратегию при подтвержденном ответе от сервера и сохраняет на диск
    pub fn record_success(&self, domain: &str, strategy: SplitStrategy) {
        let family = extract_family_domain(domain);
        let strategies = Self::get_strategies_for(domain);
        if let Some(idx) = strategies.iter().position(|&s| s == strategy) {
            if let Ok(mut counters) = self.failure_counters.write() {
                counters.insert(family.clone(), 0);
            }
            if let Ok(mut confirmed) = self.confirmed_domains.write() {
                confirmed.insert(family.clone(), true);
            }

            let mut cache = self.domain_cache.write().unwrap();
            let prev = cache.insert(family.clone(), idx);
            if prev != Some(idx) {
                info!("✓ Стратегия {:?} закреплена как успешная для {}", strategy, family);
                if self.persistent {
                    save_cache_to_disk(&cache);
                }
            } else {
                debug!("Стратегия {:?} подтверждена для {}", strategy, family);
            }
        }
    }

    /// Реагирует на сброс/таймаут: переключает стратегию только при подтвержденных сбоях (защита от флаппинга)
    pub fn record_failure(&self, domain: &str, failed_strategy: SplitStrategy) -> SplitStrategy {
        let family = extract_family_domain(domain);
        let strategies = Self::get_strategies_for(domain);

        let is_confirmed = self
            .confirmed_domains
            .read()
            .unwrap()
            .get(&family)
            .copied()
            .unwrap_or(false);

        let mut counters = self.failure_counters.write().unwrap();
        let count = counters.entry(family.clone()).or_insert(0);
        *count += 1;

        // Если домен уже был подтвержден рабочим (например, ютуб играет),
        // один спорадический сбой (закрытая вкладка, заблокированный adblocker'ом баннер) не должен переключать стратегию!
        if is_confirmed && *count < 2 {
            debug!(
                "Спорадический сбой для {} ({}/2). Сохраняем проверенную стратегию {:?}",
                family, *count, failed_strategy
            );
            return failed_strategy;
        }

        // Порог превышен: действительно произошла блокировка ТСПУ
        *count = 0;
        let mut cache = self.domain_cache.write().unwrap();
        let cur_idx = cache.get(&family).copied().unwrap_or(0);
        let next_idx = (cur_idx + 1) % strategies.len();
        cache.insert(family.clone(), next_idx);
        let next_strat = strategies[next_idx];
        info!(
            "⚡ ТСПУ заблокировал {:?} для {}. Адаптивно переключаем на -> {:?}",
            failed_strategy, family, next_strat
        );
        next_strat
    }
}

impl Default for AdaptiveEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn get_cache_path() -> Option<PathBuf> {
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let dir = PathBuf::from(local_appdata).join("Smoke");
        let _ = std::fs::create_dir_all(&dir);
        Some(dir.join("cache.json"))
    } else {
        Some(PathBuf::from("smoke_cache.json"))
    }
}

fn load_cache_from_disk() -> HashMap<String, usize> {
    if let Some(path) = get_cache_path() {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(map) = serde_json::from_str::<HashMap<String, usize>>(&content) {
                    info!("✓ Загружен диск-кэш стратегий ({} доменов) из {}", map.len(), path.display());
                    return map;
                }
            }
        }
    }
    HashMap::new()
}

fn save_cache_to_disk(cache: &HashMap<String, usize>) {
    if let Some(path) = get_cache_path() {
        if let Ok(json) = serde_json::to_string_pretty(cache) {
            let _ = std::fs::write(&path, json);
        }
    }
}

/// Выделяет семейство домена для сквозной оптимизации связанных сервисов
pub fn extract_family_domain(host: &str) -> String {
    let clean = host.split(':').next().unwrap_or(host).trim().to_ascii_lowercase();

    // Семейство Discord (gateway, cdn, updates, voice, dl2)
    if clean.contains("discord") || clean == "dis.gd" {
        return "discord_family".to_string();
    }

    // Семейство Google / YouTube
    if clean.contains("youtube")
        || clean.contains("googlevideo")
        || clean.contains("ytimg")
        || clean.contains("ggpht")
        || clean == "youtu.be"
    {
        return "youtube_family".to_string();
    }

    extract_base_domain(&clean).to_string()
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
    fn test_extract_family_domain() {
        assert_eq!(extract_family_domain("www.youtube.com"), "youtube_family");
        assert_eq!(extract_family_domain("rr1---sn-4g5edn6s.googlevideo.com:443"), "youtube_family");
        assert_eq!(extract_family_domain("i.ytimg.com"), "youtube_family");
        assert_eq!(extract_family_domain("discord.com"), "discord_family");
        assert_eq!(extract_family_domain("gateway.discord.gg"), "discord_family");
        assert_eq!(extract_family_domain("cdn.discordapp.com"), "discord_family");
        assert_eq!(extract_family_domain("updates.discord.com"), "discord_family");
        assert_eq!(extract_family_domain("example.com"), "example.com");
    }

    #[test]
    fn test_discord_strategies_priority() {
        let engine = AdaptiveEngine::new_in_memory();
        let strat = engine.get_strategy("discord.com");
        assert_eq!(strat, SplitStrategy::Disorder1);

        let strat_yt = engine.get_strategy("youtube.com");
        assert_eq!(strat_yt, SplitStrategy::TlsRecordFrag);
    }

    #[test]
    fn test_adaptive_failover() {
        let engine = AdaptiveEngine::new_in_memory();
        let d = "example.com";
        let s0 = engine.get_strategy(d);
        assert_eq!(s0, DEFAULT_STRATEGIES[0]);

        // Для нового (неподтвержденного) домена первое же падение переключает стратегию
        let s1 = engine.record_failure(d, s0);
        assert_eq!(s1, DEFAULT_STRATEGIES[1]);
        assert_eq!(engine.get_strategy(d), DEFAULT_STRATEGIES[1]);

        engine.record_success(d, s1);
        assert_eq!(engine.get_strategy(d), DEFAULT_STRATEGIES[1]);

        // Для подтвержденного домена 1 спорадический сбой сохраняет рабочую стратегию
        let s_stay = engine.record_failure(d, s1);
        assert_eq!(s_stay, s1);
        assert_eq!(engine.get_strategy(d), s1);

        // 2-й сбой подряд подтверждает блокировку и переключает
        let s2 = engine.record_failure(d, s1);
        assert_eq!(s2, DEFAULT_STRATEGIES[2]);
        assert_eq!(engine.get_strategy(d), DEFAULT_STRATEGIES[2]);
    }
}
