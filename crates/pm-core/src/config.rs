//! User configuration: proxy profiles, per-application rules and general settings.
//!
//! The config is stored as TOML. Rule actions are written as plain strings
//! (`"direct"`, `"block"`, `"proxy:<profile name>"`) to keep the file easy to edit by hand.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What to do with a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Action {
    /// Let the traffic go directly.
    Direct,
    /// Drop the traffic.
    Block,
    /// Send the traffic through the named proxy profile.
    Proxy(String),
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Direct => f.write_str("direct"),
            Action::Block => f.write_str("block"),
            Action::Proxy(name) => write!(f, "proxy:{name}"),
        }
    }
}

impl FromStr for Action {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let lower = s.to_ascii_lowercase();
        match lower.as_str() {
            "direct" => return Ok(Action::Direct),
            "block" => return Ok(Action::Block),
            _ => {}
        }
        if lower.starts_with("proxy:") {
            let name = s["proxy:".len()..].trim();
            if !name.is_empty() {
                return Ok(Action::Proxy(name.to_string()));
            }
        }
        Err(ConfigError::InvalidAction(s.to_string()))
    }
}

impl TryFrom<String> for Action {
    type Error = ConfigError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Action> for String {
    fn from(value: Action) -> Self {
        value.to_string()
    }
}

/// Upstream proxy protocol.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[default]
    Socks5,
    Http,
}

impl ProxyKind {
    pub const ALL: [ProxyKind; 2] = [ProxyKind::Socks5, ProxyKind::Http];

    pub fn label(self) -> &'static str {
        match self {
            ProxyKind::Socks5 => "SOCKS5",
            ProxyKind::Http => "HTTP CONNECT",
        }
    }
}

/// An upstream proxy server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyProfile {
    pub name: String,
    #[serde(default)]
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl ProxyProfile {
    pub fn new(
        name: impl Into<String>,
        kind: ProxyKind,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            host: host.into(),
            port,
            username: None,
            password: None,
        }
    }

    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Username and password, if authentication is configured.
    pub fn credentials(&self) -> Option<(&str, &str)> {
        match self.username.as_deref() {
            Some(user) if !user.is_empty() => Some((user, self.password.as_deref().unwrap_or(""))),
            _ => None,
        }
    }

    /// `host:port` for display and logging (IPv6 hosts are bracketed).
    pub fn endpoint(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A rule binding a set of applications to an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Executable patterns: a file name (`chrome.exe`), a full path
    /// (`C:\Program Files\App\app.exe`) or a wildcard pattern (`*\Telegram\*.exe`).
    #[serde(default)]
    pub apps: Vec<String>,
    pub action: Action,
}

impl Rule {
    pub fn new(name: impl Into<String>, apps: Vec<String>, action: Action) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            apps,
            action,
        }
    }
}

/// Global settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    /// Action for applications that match no rule.
    pub default_action: Action,
    /// Drop UDP traffic of proxied applications (UDP cannot be tunnelled yet).
    /// Browsers then fall back from QUIC to TCP, which goes through the proxy.
    pub block_udp: bool,
    /// Always let UDP port 53 (DNS) through, even for blocked applications.
    pub allow_dns: bool,
    /// Destination networks that are never proxied (LAN, loopback, multicast...).
    pub bypass: Vec<IpNet>,
    /// Timeout for establishing a tunnel through the upstream proxy.
    pub connect_timeout_secs: u64,
    /// Start proxying as soon as the application is launched.
    pub autostart: bool,
    /// Closing the window hides the application to the tray instead of exiting.
    pub close_to_tray: bool,
}

impl Default for General {
    fn default() -> Self {
        Self {
            default_action: Action::Direct,
            block_udp: true,
            allow_dns: true,
            bypass: default_bypass(),
            connect_timeout_secs: 10,
            autostart: false,
            close_to_tray: true,
        }
    }
}

/// Networks that are never proxied by default.
pub fn default_bypass() -> Vec<IpNet> {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .iter()
    .map(|s| s.parse().expect("valid built-in network"))
    .collect()
}

fn default_true() -> bool {
    true
}

/// The whole configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: General,
    #[serde(default, rename = "proxy")]
    pub proxies: Vec<ProxyProfile>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("не удалось прочитать или записать конфиг: {0}")]
    Io(#[from] io::Error),
    #[error("ошибка в конфиге: {0}")]
    Parse(String),
    #[error("неизвестное действие «{0}» (ожидается direct, block или proxy:<имя>)")]
    InvalidAction(String),
}

/// A semantic problem in an otherwise well-formed config.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("у прокси №{0} пустое имя")]
    EmptyProxyName(usize),
    #[error("прокси «{0}» объявлен несколько раз")]
    DuplicateProxy(String),
    #[error("у прокси «{0}» не указан адрес сервера")]
    EmptyProxyHost(String),
    #[error("у прокси «{0}» не указан порт")]
    ZeroProxyPort(String),
    #[error("у прокси «{0}» задан пароль, но нет логина")]
    PasswordWithoutUser(String),
    #[error("у прокси «{0}» логин или пароль длиннее 255 байт")]
    CredentialsTooLong(String),
    #[error("у правила №{0} пустое имя")]
    EmptyRuleName(usize),
    #[error("в правиле «{0}» не указано ни одного приложения")]
    RuleWithoutApps(String),
    #[error("правило «{rule}» ссылается на несуществующий прокси «{proxy}»")]
    UnknownProxy { rule: String, proxy: String },
    #[error("действие по умолчанию ссылается на несуществующий прокси «{0}»")]
    UnknownDefaultProxy(String),
    #[error("таймаут подключения должен быть от 1 до 300 секунд")]
    InvalidTimeout,
}

impl Config {
    /// Parses a config from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Serializes the config to TOML text.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Loads a config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_toml(&fs::read_to_string(path)?)
    }

    /// Loads a config file, falling back to defaults if it does not exist yet.
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Atomically writes the config file, creating parent directories as needed.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let text = self.to_toml()?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn proxy(&self, name: &str) -> Option<&ProxyProfile> {
        self.proxies.iter().find(|p| p.name == name)
    }

    /// Names of the rules that use the given proxy profile.
    pub fn proxy_usage(&self, name: &str) -> Vec<String> {
        let mut used: Vec<String> = self
            .rules
            .iter()
            .filter(|r| matches!(&r.action, Action::Proxy(p) if p == name))
            .map(|r| r.name.clone())
            .collect();
        if matches!(&self.general.default_action, Action::Proxy(p) if p == name) {
            used.insert(0, "по умолчанию".to_string());
        }
        used
    }

    /// Checks the config for semantic errors. Returns every problem found.
    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();
        let mut names = HashSet::new();

        for (i, p) in self.proxies.iter().enumerate() {
            let name = p.name.trim();
            if name.is_empty() {
                errors.push(ValidationError::EmptyProxyName(i + 1));
                continue;
            }
            if !names.insert(name) {
                errors.push(ValidationError::DuplicateProxy(name.to_string()));
            }
            if p.host.trim().is_empty() {
                errors.push(ValidationError::EmptyProxyHost(name.to_string()));
            }
            if p.port == 0 {
                errors.push(ValidationError::ZeroProxyPort(name.to_string()));
            }
            let user = p.username.as_deref().unwrap_or("");
            let pass = p.password.as_deref().unwrap_or("");
            if user.is_empty() && !pass.is_empty() {
                errors.push(ValidationError::PasswordWithoutUser(name.to_string()));
            }
            if user.len() > 255 || pass.len() > 255 {
                errors.push(ValidationError::CredentialsTooLong(name.to_string()));
            }
        }

        if let Action::Proxy(proxy) = &self.general.default_action
            && !names.contains(proxy.as_str())
        {
            errors.push(ValidationError::UnknownDefaultProxy(proxy.clone()));
        }

        for (i, r) in self.rules.iter().enumerate() {
            let name = r.name.trim();
            if name.is_empty() {
                errors.push(ValidationError::EmptyRuleName(i + 1));
            }
            let label = if name.is_empty() {
                format!("№{}", i + 1)
            } else {
                name.to_string()
            };
            if r.apps.iter().all(|a| a.trim().is_empty()) {
                errors.push(ValidationError::RuleWithoutApps(label.clone()));
            }
            if let Action::Proxy(proxy) = &r.action
                && !names.contains(proxy.as_str())
            {
                errors.push(ValidationError::UnknownProxy {
                    rule: label,
                    proxy: proxy.clone(),
                });
            }
        }

        if !(1..=300).contains(&self.general.connect_timeout_secs) {
            errors.push(ValidationError::InvalidTimeout);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            general: General::default(),
            proxies: vec![
                ProxyProfile::new("home", ProxyKind::Socks5, "10.0.0.1", 1080)
                    .with_auth("user", "pass"),
                ProxyProfile::new("work", ProxyKind::Http, "proxy.example.com", 3128),
            ],
            rules: vec![
                Rule::new(
                    "Browsers",
                    vec!["chrome.exe".into(), "firefox.exe".into()],
                    Action::Proxy("home".into()),
                ),
                Rule::new("Games", vec!["*\\Steam\\*".into()], Action::Block),
            ],
        }
    }

    #[test]
    fn action_parse_and_display_roundtrip() {
        for (text, action) in [
            ("direct", Action::Direct),
            ("block", Action::Block),
            ("proxy:home", Action::Proxy("home".into())),
            ("proxy:Мой прокси", Action::Proxy("Мой прокси".into())),
        ] {
            assert_eq!(text.parse::<Action>().unwrap(), action);
            assert_eq!(action.to_string(), text);
        }
    }

    #[test]
    fn action_parse_is_lenient_about_case_and_spaces() {
        assert_eq!(" DIRECT ".parse::<Action>().unwrap(), Action::Direct);
        assert_eq!("Block".parse::<Action>().unwrap(), Action::Block);
        assert_eq!(
            "PROXY: Home ".parse::<Action>().unwrap(),
            Action::Proxy("Home".into())
        );
    }

    #[test]
    fn action_parse_rejects_garbage() {
        for bad in ["", "proxy:", "proxy:  ", "allow", "proxyhome"] {
            assert!(
                matches!(bad.parse::<Action>(), Err(ConfigError::InvalidAction(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn toml_roundtrip_preserves_everything() {
        let cfg = sample();
        let text = cfg.to_toml().unwrap();
        assert!(text.contains("action = \"proxy:home\""));
        assert!(text.contains("[[proxy]]"));
        assert!(text.contains("[[rule]]"));
        assert_eq!(Config::from_toml(&text).unwrap(), cfg);
    }

    #[test]
    fn empty_toml_gives_defaults() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg, Config::default());
        assert!(cfg.general.block_udp);
        assert!(cfg.general.allow_dns);
        assert_eq!(cfg.general.default_action, Action::Direct);
        assert_eq!(cfg.general.bypass, default_bypass());
    }

    #[test]
    fn hand_written_toml_is_parsed() {
        let cfg = Config::from_toml(
            r#"
            [general]
            default_action = "block"
            block_udp = false

            [[proxy]]
            name = "p"
            host = "127.0.0.1"
            port = 9050

            [[rule]]
            name = "tor"
            apps = ["tor-browser.exe"]
            action = "proxy:p"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.general.default_action, Action::Block);
        assert!(!cfg.general.block_udp);
        assert!(
            cfg.general.allow_dns,
            "missing fields fall back to defaults"
        );
        assert_eq!(cfg.proxies[0].kind, ProxyKind::Socks5);
        assert!(cfg.rules[0].enabled);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn shipped_example_config_is_valid() {
        let cfg = Config::from_toml(include_str!("../../../config.example.toml")).unwrap();
        assert_eq!(cfg.validate(), Ok(()));
        assert_eq!(cfg.proxies.len(), 2);
        assert_eq!(cfg.rules.len(), 3);
        assert_eq!(cfg.general.bypass, default_bypass());
    }

    #[test]
    fn invalid_toml_reports_parse_error() {
        let err = Config::from_toml("[[rule]]\nname = \"x\"\naction = \"teleport\"").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse(ref m) if m.contains("teleport")),
            "{err}"
        );
        assert!(matches!(
            Config::from_toml("this is not toml"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn save_and_load_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        let cfg = sample();
        cfg.save(&path).unwrap();
        assert!(!path.with_extension("toml.tmp").exists());
        assert_eq!(Config::load(&path).unwrap(), cfg);
        assert_eq!(Config::load_or_default(&path).unwrap(), cfg);
    }

    #[test]
    fn load_or_default_handles_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.toml");
        assert_eq!(Config::load_or_default(&path).unwrap(), Config::default());
        assert!(matches!(Config::load(&path), Err(ConfigError::Io(_))));
    }

    #[test]
    fn load_or_default_propagates_other_errors() {
        let dir = tempfile::tempdir().unwrap();
        // A directory cannot be read as a file.
        assert!(matches!(
            Config::load_or_default(dir.path()),
            Err(ConfigError::Io(_))
        ));
    }

    #[test]
    fn credentials_and_endpoint() {
        let p = ProxyProfile::new("a", ProxyKind::Socks5, "::1", 1080);
        assert_eq!(p.credentials(), None);
        assert_eq!(p.endpoint(), "[::1]:1080");
        let p = p.with_auth("u", "p");
        assert_eq!(p.credentials(), Some(("u", "p")));
        let mut p = ProxyProfile::new("b", ProxyKind::Http, "proxy", 8080);
        p.username = Some(String::new());
        assert_eq!(p.credentials(), None);
        p.username = Some("only-user".into());
        assert_eq!(p.credentials(), Some(("only-user", "")));
        assert_eq!(p.endpoint(), "proxy:8080");
        assert_eq!(ProxyKind::Http.label(), "HTTP CONNECT");
        assert_eq!(ProxyKind::Socks5.label(), "SOCKS5");
    }

    #[test]
    fn validation_accepts_sample() {
        assert_eq!(sample().validate(), Ok(()));
    }

    #[test]
    fn validation_reports_all_problems() {
        let mut cfg = sample();
        cfg.proxies
            .push(ProxyProfile::new("home", ProxyKind::Socks5, " ", 0));
        cfg.proxies
            .push(ProxyProfile::new("", ProxyKind::Socks5, "h", 1));
        let mut bad_auth = ProxyProfile::new("auth", ProxyKind::Http, "h", 1);
        bad_auth.password = Some("secret".into());
        cfg.proxies.push(bad_auth);
        cfg.proxies.push(
            ProxyProfile::new("long", ProxyKind::Socks5, "h", 1).with_auth("u".repeat(256), "p"),
        );
        cfg.rules.push(Rule::new(
            "",
            vec![" ".into()],
            Action::Proxy("nope".into()),
        ));
        cfg.general.default_action = Action::Proxy("missing".into());
        cfg.general.connect_timeout_secs = 0;

        let errors = cfg.validate().unwrap_err();
        let expected = [
            ValidationError::DuplicateProxy("home".into()),
            ValidationError::EmptyProxyHost("home".into()),
            ValidationError::ZeroProxyPort("home".into()),
            ValidationError::EmptyProxyName(4),
            ValidationError::PasswordWithoutUser("auth".into()),
            ValidationError::CredentialsTooLong("long".into()),
            ValidationError::UnknownDefaultProxy("missing".into()),
            ValidationError::EmptyRuleName(3),
            ValidationError::RuleWithoutApps("№3".into()),
            ValidationError::UnknownProxy {
                rule: "№3".into(),
                proxy: "nope".into(),
            },
            ValidationError::InvalidTimeout,
        ];
        for e in &expected {
            assert!(errors.contains(e), "missing {e:?} in {errors:?}");
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(errors.len(), expected.len(), "{errors:?}");
    }

    #[test]
    fn proxy_lookup_and_usage() {
        let mut cfg = sample();
        assert_eq!(cfg.proxy("work").unwrap().port, 3128);
        assert!(cfg.proxy("none").is_none());
        assert_eq!(cfg.proxy_usage("home"), vec!["Browsers".to_string()]);
        assert!(cfg.proxy_usage("work").is_empty());
        cfg.general.default_action = Action::Proxy("work".into());
        assert_eq!(cfg.proxy_usage("work"), vec!["по умолчанию".to_string()]);
    }
}
