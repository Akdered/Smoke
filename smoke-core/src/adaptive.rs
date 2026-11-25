use crate::desync::SplitStrategy;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::RwLock;
use tracing::{debug, info};

/// Арсенал обхода для целевых блокируемых сервисов (YouTube, GGC, Discord, РКН-реестр):
/// Первыми идут RFC-совместимые и роутеро-независимые техники (без риска смерти TTL=1 на домашних GPON-роутерах),
/// следом — тяжелая артиллерия с OOB, TransmitFile Fake (TTL 4/6) и многоуровневым Disorder.
pub const BYPASS_STRATEGIES: &[SplitStrategy] = &[
    SplitStrategy::TlsRecMicroSni,
    SplitStrategy::TlsRecordFrag2,
    SplitStrategy::TlsRecOobSni,
    SplitStrategy::FakeTls4,
    SplitStrategy::FakeTls6,
    SplitStrategy::TlsRecordFragSni,
    SplitStrategy::OobSni,
    SplitStrategy::TcpSplitSni,
    SplitStrategy::TlsRecordFrag,
    SplitStrategy::Disorder3,
    SplitStrategy::Disorder2,
    SplitStrategy::Disorder1,
    SplitStrategy::DisorderSni2,
    SplitStrategy::DisorderSni,
    SplitStrategy::Combo,
    SplitStrategy::TcpSplit2,
    SplitStrategy::TcpSplit1,
];

/// Порог последовательных полных отказов (без единого успеха между ними),
/// после которого подтвержденная стратегия разблокируется для повторного автоподбора.
const UNLOCK_FAILURE_THRESHOLD: u32 = 6;

/// Самообучающийся движок v0.6.0 с принципом «Не навреди» (Direct-First),
/// защитой от флаппинга на мертвых GGC-серверах и детектором 16KB-фризов ТСПУ.
#[derive(Debug)]
pub struct AdaptiveEngine {
    domain_cache: RwLock<HashMap<String, SplitStrategy>>,
    failure_counters: RwLock<HashMap<String, u32>>,
    confirmed_domains: RwLock<HashSet<String>>,
    banned_none: RwLock<HashSet<String>>,
    probe_cursor: RwLock<HashMap<String, usize>>,
    persistent: bool,
}

impl AdaptiveEngine {
    pub fn new() -> Self {
        let initial_cache = load_cache_from_disk();
        let confirmed: HashSet<String> = initial_cache.keys().cloned().collect();

        Self {
            domain_cache: RwLock::new(initial_cache),
            failure_counters: RwLock::new(HashMap::new()),
            confirmed_domains: RwLock::new(confirmed),
            banned_none: RwLock::new(HashSet::new()),
            probe_cursor: RwLock::new(HashMap::new()),
            persistent: true,
        }
    }

    /// Изолированный конструктор для модульных тестов без обращения к диску
    pub fn new_in_memory() -> Self {
        Self {
            domain_cache: RwLock::new(HashMap::new()),
            failure_counters: RwLock::new(HashMap::new()),
            confirmed_domains: RwLock::new(HashSet::new()),
            banned_none: RwLock::new(HashSet::new()),
            probe_cursor: RwLock::new(HashMap::new()),
            persistent: false,
        }
    }

    /// Проверяет, имеет ли семейство домена уже подтвержденную стабильную стратегию
    pub fn is_confirmed(&self, domain: &str) -> bool {
        if is_fast_direct_domain(domain) {
            return true;
        }
        let family = extract_family_domain(domain);
        self.confirmed_domains
            .read()
            .unwrap()
            .contains(&family)
    }

    /// Возвращает текущую рабочую стратегию для домена
    pub fn get_strategy(&self, domain: &str) -> SplitStrategy {
        self.get_strategy_for_attempt(domain, 0)
    }

    /// Возвращает кандидата для конкретной попытки `attempt` внутри In-Flight автоподбора
    pub fn get_strategy_for_attempt(&self, domain: &str, attempt: usize) -> SplitStrategy {
        if is_fast_direct_domain(domain) {
            return SplitStrategy::None;
        }

        let family = extract_family_domain(domain);

        // Если домен уже подтвержден и attempt == 0, мгновенно отдаем проверенную стратегию
        if attempt == 0 {
            if let Some(&cached) = self.domain_cache.read().unwrap().get(&family) {
                if self.confirmed_domains.read().unwrap().contains(&family) {
                    return cached;
                }
            }
        }

        let none_banned = self.banned_none.read().unwrap().contains(&family);
        let cursor = self
            .probe_cursor
            .read()
            .unwrap()
            .get(&family)
            .copied()
            .unwrap_or(0);

        // Для обычных сайтов (не из явного списка целей ТСПУ), если None не забанен —
        // на первой попытке проверяем прямое соединение без модификации пакетов («Не навреди»)!
        let try_direct_first = !none_banned && !is_primary_dpi_target(domain) && cursor == 0;

        if try_direct_first {
            if attempt == 0 {
                return SplitStrategy::None;
            }
            let idx = (attempt - 1) % BYPASS_STRATEGIES.len();
            return BYPASS_STRATEGIES[idx];
        }

        let idx = (cursor + attempt) % BYPASS_STRATEGIES.len();
        BYPASS_STRATEGIES[idx]
    }

    /// Закрепляет стратегию ТОЛЬКО после реального подтверждения ответа сервера (0x16 ServerHello)
    pub fn record_success(&self, domain: &str, strategy: SplitStrategy) {
        if is_fast_direct_domain(domain) {
            return;
        }

        let family = extract_family_domain(domain);

        if let Ok(mut counters) = self.failure_counters.write() {
            counters.insert(family.clone(), 0);
        }
        if let Ok(mut cursors) = self.probe_cursor.write() {
            cursors.insert(family.clone(), 0);
        }
        if let Ok(mut confirmed) = self.confirmed_domains.write() {
            confirmed.insert(family.clone());
        }

        let mut cache = self.domain_cache.write().unwrap();
        let prev = cache.insert(family.clone(), strategy);
        if prev != Some(strategy) {
            info!(
                "✓ Стратегия {:?} подтверждена и закреплена для {}",
                strategy, family
            );
            if self.persistent {
                save_cache_to_disk(&cache);
            }
        } else {
            debug!("Стратегия {:?} стабильна для {}", strategy, family);
        }
    }

    /// Регистрирует полный отказ соединения:
    /// НЕ переключает слепо рабочую стратегию на единичных мертвых GGC-узлах!
    /// Только при серии из 6 полных отказов подряд снимает фиксацию для нового поиска.
    pub fn record_failure(&self, domain: &str, failed_strategy: SplitStrategy) -> SplitStrategy {
        if is_fast_direct_domain(domain) {
            return SplitStrategy::None;
        }

        let family = extract_family_domain(domain);
        let is_confirmed = self.confirmed_domains.read().unwrap().contains(&family);

        if is_confirmed {
            let mut counters = self.failure_counters.write().unwrap();
            let count = counters.entry(family.clone()).or_insert(0);
            *count += 1;

            if *count < UNLOCK_FAILURE_THRESHOLD {
                debug!(
                    "Игнорируем одиночный таймаут узла {} ({}/{}) — сохраняем {:?}",
                    family, *count, UNLOCK_FAILURE_THRESHOLD, failed_strategy
                );
                return failed_strategy;
            }

            // 6 полных сбоев подряд без единого успеха — провайдер реально сменил фильтрацию!
            *count = 0;
            drop(counters);

            self.confirmed_domains.write().unwrap().remove(&family);
            let next_pos = BYPASS_STRATEGIES
                .iter()
                .position(|&s| s == failed_strategy)
                .map(|i| (i + 1) % BYPASS_STRATEGIES.len())
                .unwrap_or(0);
            self.probe_cursor.write().unwrap().insert(family.clone(), next_pos);
            let next_strat = BYPASS_STRATEGIES[next_pos];

            info!(
                "⚡ Серия отказов {:?} для {}. Запущен переподбор -> {:?}",
                failed_strategy, family, next_strat
            );
            return next_strat;
        }

        // Для еще НЕ подтвержденного домена сдвигаем окно поиска дальше по арсеналу
        let mut cursors = self.probe_cursor.write().unwrap();
        let cur = cursors.get(&family).copied().unwrap_or(0);
        let next = (cur + 1) % BYPASS_STRATEGIES.len();
        cursors.insert(family, next);
        BYPASS_STRATEGIES[next]
    }

    /// Фиксирует обрыв потока на 16–32 КБ ПОСЛЕ успешного TLS-рукопожатия (stateful byte-counter блок ТСПУ)
    pub fn record_post_handshake_freeze(&self, domain: &str, frozen_strategy: SplitStrategy) {
        let family = extract_family_domain(domain);
        if frozen_strategy == SplitStrategy::None {
            self.banned_none.write().unwrap().insert(family.clone());
        }

        self.confirmed_domains.write().unwrap().remove(&family);
        let next_pos = BYPASS_STRATEGIES
            .iter()
            .position(|&s| s == frozen_strategy)
            .map(|i| (i + 1) % BYPASS_STRATEGIES.len())
            .unwrap_or(0);
        self.probe_cursor.write().unwrap().insert(family.clone(), next_pos);

        info!(
            "⚡ Обнаружен пост-хендшейк блок (16KB freeze) на {:?} для {} -> перевод на глубокий обход",
            frozen_strategy, family
        );
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
        Some(dir.join("cache_v2.json"))
    } else {
        Some(PathBuf::from("smoke_cache_v2.json"))
    }
}

fn load_cache_from_disk() -> HashMap<String, SplitStrategy> {
    if let Some(path) = get_cache_path() {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(map) = serde_json::from_str::<HashMap<String, SplitStrategy>>(&content) {
                    info!(
                        "✓ Загружен диск-кэш стратегий v2 ({} семейств) из {}",
                        map.len(),
                        path.display()
                    );
                    return map;
                }
            }
        }
    }
    HashMap::new()
}

fn save_cache_to_disk(cache: &HashMap<String, SplitStrategy>) {
    if let Some(path) = get_cache_path() {
        if let Ok(json) = serde_json::to_string_pretty(cache) {
            let _ = std::fs::write(&path, json);
        }
    }
}

/// Российские, локальные и заведомо незаблокированные ресурсы — всегда идут напрямую без задержек и нарезки!
pub fn is_fast_direct_domain(host: &str) -> bool {
    let clean = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if clean.is_empty() || clean == "localhost" {
        return true;
    }

    if clean.ends_with(".ru")
        || clean.ends_with(".su")
        || clean.ends_with(".xn--p1ai")
        || clean.ends_with(".by")
        || clean.ends_with(".kz")
        || clean.ends_with(".local")
        || clean.ends_with(".lan")
    {
        return true;
    }

    const DIRECT_SUFFIXES: &[&str] = &[
        "vk.com",
        "userapi.com",
        "vkuser.net",
        "vk-portal.net",
        "yandex.net",
        "yandex.com",
        "yastatic.net",
        "steamcontent.com",
        "steamserver.net",
    ];

    DIRECT_SUFFIXES
        .iter()
        .any(|&sfx| clean == sfx || clean.ends_with(&format!(".{}", sfx)))
}

/// Домены, гарантированно находящиеся под инспекцией/троттлингом ТСПУ (пропускают холостой шаг `None`)
pub fn is_primary_dpi_target(host: &str) -> bool {
    let clean = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();

    const EXACT_OR_SUBDOMAINS: &[&str] = &[
        "googlevideo.com",
        "youtube.com",
        "ytimg.com",
        "ggpht.com",
        "youtu.be",
        "discord.com",
        "discordapp.com",
        "discordapp.net",
        "discord.gg",
        "discord.media",
        "dis.gd",
        "rutracker.org",
        "rutracker.net",
        "instagram.com",
        "cdninstagram.com",
        "fbcdn.net",
        "facebook.com",
        "twitter.com",
        "x.com",
        "twimg.com",
        "t.co",
        "ntc.party",
        "proton.me",
        "protonmail.com",
    ];

    EXACT_OR_SUBDOMAINS
        .iter()
        .any(|&d| clean == d || clean.ends_with(&format!(".{}", d)))
}

/// Выделяет семейство домена для сквозной оптимизации связанных сервисов
pub fn extract_family_domain(host: &str) -> String {
    let clean = host.split(':').next().unwrap_or(host).trim().to_ascii_lowercase();

    if clean.contains("discord") || clean == "dis.gd" {
        return "discord_family".to_string();
    }

    if clean.contains("googlevideo") {
        return "googlevideo_family".to_string();
    }

    if clean.contains("youtube")
        || clean.contains("ytimg")
        || clean.contains("ggpht")
        || clean == "youtu.be"
    {
        return "youtube_family".to_string();
    }

    if clean.contains("instagram") || clean.contains("cdninstagram") {
        return "instagram_family".to_string();
    }

    if clean == "x.com" || clean.ends_with(".x.com") || clean.contains("twitter") || clean.contains("twimg") {
        return "twitter_family".to_string();
    }

    extract_base_domain(&clean).to_string()
}

/// Выделяет базовый домен 2-го уровня
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
    fn test_fast_direct_domains() {
        assert!(is_fast_direct_domain("ozon.ru"));
        assert!(is_fast_direct_domain("sub.vk.com"));
        assert!(is_fast_direct_domain("yastatic.net"));
        assert!(!is_fast_direct_domain("www.youtube.com"));
        assert!(!is_fast_direct_domain("rutracker.org"));
    }

    #[test]
    fn test_extract_family_domain() {
        assert_eq!(extract_family_domain("www.youtube.com"), "youtube_family");
        assert_eq!(
            extract_family_domain("rr1---sn-4g5edn6s.googlevideo.com:443"),
            "googlevideo_family"
        );
        assert_eq!(extract_family_domain("discord.com"), "discord_family");
        assert_eq!(extract_family_domain("x.com"), "twitter_family");
        assert_eq!(extract_family_domain("example.com"), "example.com");
    }

    #[test]
    fn test_direct_first_vs_dpi_target() {
        let engine = AdaptiveEngine::new_in_memory();
        // Обычный международный сайт начинает с None («Не навреди»)
        assert_eq!(engine.get_strategy("microsoft.com"), SplitStrategy::None);
        // На второй попытке внутри соединения сразу включается обход
        assert_eq!(
            engine.get_strategy_for_attempt("microsoft.com", 1),
            BYPASS_STRATEGIES[0]
        );

        // Целевые блокируемые сервисы сразу начинают с роутеро-безопасного TlsRecMicroSni
        assert_eq!(
            engine.get_strategy("discord.com"),
            SplitStrategy::TlsRecMicroSni
        );
        assert_eq!(
            engine.get_strategy("rutracker.org"),
            SplitStrategy::TlsRecMicroSni
        );
    }

    #[test]
    fn test_anti_flapping_hysteresis() {
        let engine = AdaptiveEngine::new_in_memory();
        let d = "rr1---sn-test.googlevideo.com";
        engine.record_success(d, SplitStrategy::TlsRecordFrag2);
        assert!(engine.is_confirmed(d));
        assert_eq!(engine.get_strategy(d), SplitStrategy::TlsRecordFrag2);

        // 5 спорадических отказов мертвых GGC-нод НЕ сбивают рабочую стратегию!
        for _ in 0..5 {
            let s = engine.record_failure(d, SplitStrategy::TlsRecordFrag2);
            assert_eq!(s, SplitStrategy::TlsRecordFrag2);
            assert!(engine.is_confirmed(d));
        }

        // Один успешный чанк с живой ноды обнуляет счетчик ошибок!
        engine.record_success("rr2---sn-live.googlevideo.com", SplitStrategy::TlsRecordFrag2);
        for _ in 0..5 {
            assert!(engine.is_confirmed(d));
            engine.record_failure(d, SplitStrategy::TlsRecordFrag2);
        }

        // 6-й полный отказ подряд без единого успеха разблокирует переподбор
        engine.record_failure(d, SplitStrategy::TlsRecordFrag2);
        assert!(!engine.is_confirmed(d));
    }
}
