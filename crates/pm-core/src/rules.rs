//! Compiled rule set: matches processes to actions.

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::config::{Action, Config, ProxyProfile, ValidationError};

/// An action with the proxy profile already resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedAction {
    Direct,
    Block,
    Proxy(Arc<ProxyProfile>),
}

impl ResolvedAction {
    pub fn label(&self) -> String {
        match self {
            ResolvedAction::Direct => "напрямую".to_string(),
            ResolvedAction::Block => "блокировка".to_string(),
            ResolvedAction::Proxy(p) => format!("прокси «{}»", p.name),
        }
    }
}

/// A single executable pattern.
///
/// Patterns containing a path separator are matched against the full executable path,
/// all others against the file name only. `*` matches any sequence of characters
/// (including separators) and `?` matches a single character. Matching is case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPattern {
    pattern: Vec<char>,
    full_path: bool,
}

impl AppPattern {
    pub fn new(raw: &str) -> Option<Self> {
        let normalized = normalize_path(raw.trim());
        if normalized.is_empty() {
            return None;
        }
        Some(Self {
            full_path: normalized.contains('\\'),
            pattern: normalized.chars().collect(),
        })
    }

    /// `path` and `name` must already be normalized with [`normalize_path`].
    fn matches(&self, path: &[char], name: &[char]) -> bool {
        wildcard_match(&self.pattern, if self.full_path { path } else { name })
    }
}

/// Lower-cases a path and unifies separators to `\`.
pub fn normalize_path(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

/// The file name part of a path (works with both separators).
pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Glob-style matching with `*` and `?`, iterative with single-star backtracking.
pub fn wildcard_match(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

#[derive(Debug, Clone)]
struct CompiledRule {
    name: Arc<str>,
    patterns: Vec<AppPattern>,
    action: ResolvedAction,
}

/// Result of matching a process against the rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Name of the matched rule, `None` when the default action applied.
    pub rule: Option<Arc<str>>,
    pub action: ResolvedAction,
}

/// Immutable, pre-compiled form of a [`Config`] used on the hot path.
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    default_action: ResolvedAction,
    bypass: Vec<IpNet>,
    pub block_udp: bool,
    pub allow_dns: bool,
}

impl Default for RuleSet {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_action: ResolvedAction::Direct,
            bypass: Vec::new(),
            block_udp: false,
            allow_dns: true,
        }
    }
}

impl RuleSet {
    /// Validates and compiles a config.
    pub fn compile(cfg: &Config) -> Result<Self, Vec<ValidationError>> {
        cfg.validate()?;
        let profiles: Vec<Arc<ProxyProfile>> = cfg.proxies.iter().cloned().map(Arc::new).collect();
        let resolve = |action: &Action| match action {
            Action::Direct => ResolvedAction::Direct,
            Action::Block => ResolvedAction::Block,
            Action::Proxy(name) => ResolvedAction::Proxy(
                profiles
                    .iter()
                    .find(|p| &p.name == name)
                    .cloned()
                    .expect("validated: proxy exists"),
            ),
        };
        let rules = cfg
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| CompiledRule {
                name: Arc::from(r.name.trim()),
                patterns: r.apps.iter().filter_map(|a| AppPattern::new(a)).collect(),
                action: resolve(&r.action),
            })
            .collect();
        Ok(Self {
            rules,
            default_action: resolve(&cfg.general.default_action),
            bypass: cfg.general.bypass.clone(),
            block_udp: cfg.general.block_udp,
            allow_dns: cfg.general.allow_dns,
        })
    }

    /// Finds the action for a process given its executable path.
    /// Unknown processes (`None`) get the default action.
    pub fn match_process(&self, path: Option<&str>) -> Match {
        if let Some(path) = path {
            let normalized = normalize_path(path);
            let path_chars: Vec<char> = normalized.chars().collect();
            let name_chars: Vec<char> = file_name(&normalized).chars().collect();
            for rule in &self.rules {
                if rule
                    .patterns
                    .iter()
                    .any(|p| p.matches(&path_chars, &name_chars))
                {
                    return Match {
                        rule: Some(rule.name.clone()),
                        action: rule.action.clone(),
                    };
                }
            }
        }
        Match {
            rule: None,
            action: self.default_action.clone(),
        }
    }

    /// Whether the destination must never be proxied.
    pub fn is_bypassed(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        self.bypass.iter().any(|net| net.contains(&ip))
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Converts IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to plain IPv4.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyKind, Rule};

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    fn wm(p: &str, t: &str) -> bool {
        wildcard_match(&chars(p), &chars(t))
    }

    #[test]
    fn wildcard_basics() {
        assert!(wm("chrome.exe", "chrome.exe"));
        assert!(!wm("chrome.exe", "chrome.exe2"));
        assert!(!wm("chrome.exe", "chrom.exe"));
        assert!(wm("*.exe", "chrome.exe"));
        assert!(wm("*", ""));
        assert!(wm("", ""));
        assert!(!wm("", "a"));
        assert!(wm("c?rome.exe", "chrome.exe"));
        assert!(!wm("c?rome.exe", "crome.exe"));
        assert!(wm(
            "*\\telegram\\*.exe",
            "c:\\users\\me\\telegram\\telegram.exe"
        ));
        assert!(wm("a*b*c", "axxbyyc"));
        assert!(!wm("a*b*c", "axxbyy"));
        assert!(wm("*abc", "ababc"), "needs backtracking");
        assert!(wm("**x", "yyx"));
        assert!(!wm("?", ""));
    }

    #[test]
    fn pattern_kinds() {
        assert!(AppPattern::new("  ").is_none());
        let name = AppPattern::new("Chrome.EXE").unwrap();
        assert!(!name.full_path);
        let path = AppPattern::new("C:/Program Files/App/app.exe").unwrap();
        assert!(path.full_path);
        assert_eq!(path.pattern, chars("c:\\program files\\app\\app.exe"));
    }

    #[test]
    fn helpers() {
        assert_eq!(normalize_path("C:/Dir/App.EXE"), "c:\\dir\\app.exe");
        assert_eq!(file_name("c:\\dir\\app.exe"), "app.exe");
        assert_eq!(file_name("/usr/bin/curl"), "curl");
        assert_eq!(file_name("plain"), "plain");
        assert_eq!(
            canonical_ip("::ffff:1.2.3.4".parse().unwrap()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            canonical_ip("::1".parse().unwrap()),
            "::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            canonical_ip("8.8.8.8".parse().unwrap()),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
    }

    fn config() -> Config {
        let mut cfg = Config::default();
        cfg.proxies
            .push(ProxyProfile::new("p1", ProxyKind::Socks5, "1.1.1.1", 1080));
        cfg.proxies
            .push(ProxyProfile::new("p2", ProxyKind::Http, "2.2.2.2", 8080));
        cfg.rules = vec![
            Rule::new("disabled", vec!["*".into()], Action::Block),
            Rule::new(
                "browsers",
                vec!["chrome.exe".into(), "FIREFOX.exe".into()],
                Action::Proxy("p1".into()),
            ),
            Rule::new(
                "telegram",
                vec!["*\\Telegram Desktop\\*".into()],
                Action::Proxy("p2".into()),
            ),
            Rule::new("blocked", vec!["C:\\Games\\game.exe".into()], Action::Block),
            Rule::new("direct", vec!["firefox.exe".into()], Action::Direct),
        ];
        cfg.rules[0].enabled = false;
        cfg
    }

    #[test]
    fn first_matching_enabled_rule_wins() {
        let rs = RuleSet::compile(&config()).unwrap();
        assert_eq!(rs.rule_count(), 4, "disabled rule is skipped");

        let m = rs.match_process(Some(
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        ));
        assert_eq!(m.rule.as_deref(), Some("browsers"));
        assert!(matches!(&m.action, ResolvedAction::Proxy(p) if p.name == "p1"));

        let m = rs.match_process(Some("C:\\Program Files\\Mozilla Firefox\\firefox.exe"));
        assert_eq!(
            m.rule.as_deref(),
            Some("browsers"),
            "earlier rule shadows the later one"
        );

        let m = rs.match_process(Some(
            "C:\\Users\\me\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe",
        ));
        assert!(matches!(&m.action, ResolvedAction::Proxy(p) if p.name == "p2"));

        let m = rs.match_process(Some("c:/games/GAME.exe"));
        assert_eq!(m.action, ResolvedAction::Block);

        let m = rs.match_process(Some("D:\\Games\\game.exe"));
        assert_eq!(
            m,
            Match {
                rule: None,
                action: ResolvedAction::Direct
            }
        );

        let m = rs.match_process(None);
        assert_eq!(m.rule, None);
    }

    #[test]
    fn default_action_is_resolved() {
        let mut cfg = config();
        cfg.general.default_action = Action::Proxy("p2".into());
        let rs = RuleSet::compile(&cfg).unwrap();
        let m = rs.match_process(Some("notepad.exe"));
        assert!(matches!(&m.action, ResolvedAction::Proxy(p) if p.name == "p2"));
        assert!(matches!(
            rs.match_process(None).action,
            ResolvedAction::Proxy(_)
        ));

        cfg.general.default_action = Action::Block;
        assert_eq!(
            RuleSet::compile(&cfg).unwrap().match_process(None).action,
            ResolvedAction::Block
        );
    }

    #[test]
    fn compile_rejects_invalid_config() {
        let mut cfg = config();
        cfg.rules[1].action = Action::Proxy("ghost".into());
        assert!(RuleSet::compile(&cfg).is_err());
    }

    #[test]
    fn bypass_networks() {
        let rs = RuleSet::compile(&config()).unwrap();
        for ip in [
            "127.0.0.1",
            "192.168.1.10",
            "10.1.2.3",
            "172.20.0.1",
            "::1",
            "fe80::1",
            "224.0.0.251",
            "::ffff:192.168.0.1",
        ] {
            assert!(rs.is_bypassed(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "2a00:1450::1", "::ffff:8.8.8.8"] {
            assert!(!rs.is_bypassed(ip.parse().unwrap()), "{ip}");
        }
        assert!(!RuleSet::default().is_bypassed("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn flags_are_copied() {
        let mut cfg = config();
        cfg.general.block_udp = false;
        cfg.general.allow_dns = false;
        let rs = RuleSet::compile(&cfg).unwrap();
        assert!(!rs.block_udp);
        assert!(!rs.allow_dns);
        let rs = RuleSet::default();
        assert!(!rs.block_udp && rs.allow_dns);
    }

    #[test]
    fn action_labels() {
        assert_eq!(ResolvedAction::Direct.label(), "напрямую");
        assert_eq!(ResolvedAction::Block.label(), "блокировка");
        let p = Arc::new(ProxyProfile::new("x", ProxyKind::Socks5, "h", 1));
        assert_eq!(ResolvedAction::Proxy(p).label(), "прокси «x»");
    }
}
