//! UI-independent editing helpers and formatting.

use std::time::Duration;

use ipnet::IpNet;
use pm_core::config::{Action, Config, ProxyKind, ProxyProfile, Rule};

/// Actions offered in drop-downs: direct, block and every proxy profile.
pub fn action_choices(cfg: &Config) -> Vec<Action> {
    let mut choices = vec![Action::Direct, Action::Block];
    choices.extend(cfg.proxies.iter().map(|p| Action::Proxy(p.name.clone())));
    choices
}

pub fn action_label(action: &Action) -> String {
    match action {
        Action::Direct => "Напрямую".to_string(),
        Action::Block => "Блокировать".to_string(),
        Action::Proxy(name) => format!("Через прокси «{name}»"),
    }
}

/// Adds an executable pattern to a rule unless it is empty or already present.
pub fn add_app(rule: &mut Rule, app: &str) -> bool {
    let app = app.trim().trim_matches('"').trim();
    if app.is_empty() || rule.apps.iter().any(|a| a.eq_ignore_ascii_case(app)) {
        return false;
    }
    rule.apps.push(app.to_string());
    true
}

/// `base`, or `base 2`, `base 3`... whichever is not taken.
pub fn unique_name<'a>(existing: impl Iterator<Item = &'a str> + Clone, base: &str) -> String {
    let taken = |name: &str| existing.clone().any(|e| e == name);
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|i| format!("{base} {i}"))
        .find(|name| !taken(name))
        .expect("infinite sequence")
}

/// A new rule routed through the first proxy (or direct if there is none).
pub fn new_rule(cfg: &Config, apps: Vec<String>) -> Rule {
    let name = unique_name(cfg.rules.iter().map(|r| r.name.as_str()), "Новое правило");
    let action = cfg
        .proxies
        .first()
        .map_or(Action::Direct, |p| Action::Proxy(p.name.clone()));
    Rule::new(name, apps, action)
}

pub fn new_proxy(cfg: &Config) -> ProxyProfile {
    let name = unique_name(cfg.proxies.iter().map(|p| p.name.as_str()), "Прокси");
    ProxyProfile::new(name, ProxyKind::Socks5, "127.0.0.1", 1080)
}

/// Renames a proxy profile and updates every reference to it.
pub fn rename_proxy(cfg: &mut Config, old: &str, new: &str) {
    if old == new {
        return;
    }
    for p in cfg.proxies.iter_mut().filter(|p| p.name == old) {
        p.name = new.to_string();
    }
    let fix = |a: &mut Action| {
        if matches!(a, Action::Proxy(n) if n == old) {
            *a = Action::Proxy(new.to_string());
        }
    };
    fix(&mut cfg.general.default_action);
    cfg.rules.iter_mut().for_each(|r| fix(&mut r.action));
}

/// Moves `items[index]` one step up or down. Returns the new index.
pub fn move_item<T>(items: &mut [T], index: usize, up: bool) -> Option<usize> {
    let target = if up { index.checked_sub(1)? } else { index + 1 };
    if target >= items.len() || index >= items.len() {
        return None;
    }
    items.swap(index, target);
    Some(target)
}

/// Parses one network per line; bare addresses become /32 or /128. `#` starts a comment.
pub fn parse_bypass(text: &str) -> Result<Vec<IpNet>, String> {
    let mut nets = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let net = line
            .parse::<IpNet>()
            .or_else(|_| line.parse::<std::net::IpAddr>().map(IpNet::from))
            .map_err(|_| format!("строка {}: «{line}» — не адрес и не подсеть", i + 1))?;
        nets.push(net);
    }
    Ok(nets)
}

pub fn bypass_to_text(nets: &[IpNet]) -> String {
    nets.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    if bytes < 1024 {
        return format!("{bytes} Б");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

pub fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s} с"),
        60..3600 => format!("{} мин {:02} с", s / 60, s % 60),
        _ => format!("{} ч {:02} мин", s / 3600, (s % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut cfg = Config::default();
        cfg.proxies
            .push(ProxyProfile::new("a", ProxyKind::Socks5, "h", 1));
        cfg.proxies
            .push(ProxyProfile::new("b", ProxyKind::Http, "h", 2));
        cfg.rules.push(Rule::new(
            "r1",
            vec!["x.exe".into()],
            Action::Proxy("a".into()),
        ));
        cfg.rules.push(Rule::new(
            "r2",
            vec!["y.exe".into()],
            Action::Proxy("b".into()),
        ));
        cfg
    }

    #[test]
    fn choices_and_labels() {
        let choices = action_choices(&cfg());
        assert_eq!(choices.len(), 4);
        assert_eq!(choices[2], Action::Proxy("a".into()));
        assert_eq!(action_label(&Action::Direct), "Напрямую");
        assert_eq!(action_label(&Action::Block), "Блокировать");
        assert_eq!(action_label(&Action::Proxy("a".into())), "Через прокси «a»");
    }

    #[test]
    fn adding_apps() {
        let mut r = Rule::new("r", vec!["chrome.exe".into()], Action::Direct);
        assert!(!add_app(&mut r, "  "));
        assert!(!add_app(&mut r, "CHROME.EXE"));
        assert!(add_app(&mut r, " \"C:\\Program Files\\App\\app.exe\" "));
        assert_eq!(
            r.apps,
            vec!["chrome.exe", "C:\\Program Files\\App\\app.exe"]
        );
    }

    #[test]
    fn names() {
        let existing = ["Прокси", "Прокси 2"];
        assert_eq!(unique_name(existing.iter().copied(), "Прокси"), "Прокси 3");
        assert_eq!(unique_name(existing.iter().copied(), "Другое"), "Другое");

        let mut c = cfg();
        let rule = new_rule(&c, vec!["z.exe".into()]);
        assert_eq!(rule.name, "Новое правило");
        assert_eq!(rule.action, Action::Proxy("a".into()));
        c.proxies.clear();
        assert_eq!(new_rule(&c, vec![]).action, Action::Direct);
        assert_eq!(new_proxy(&c).name, "Прокси");
        assert_eq!(new_proxy(&cfg()).port, 1080);
    }

    #[test]
    fn renaming_proxy_updates_references() {
        let mut c = cfg();
        c.general.default_action = Action::Proxy("a".into());
        rename_proxy(&mut c, "a", "home");
        assert_eq!(c.proxies[0].name, "home");
        assert_eq!(c.rules[0].action, Action::Proxy("home".into()));
        assert_eq!(c.rules[1].action, Action::Proxy("b".into()));
        assert_eq!(c.general.default_action, Action::Proxy("home".into()));
        let before = c.clone();
        rename_proxy(&mut c, "b", "b");
        assert_eq!(c, before);
    }

    #[test]
    fn moving_items() {
        let mut v = vec![1, 2, 3];
        assert_eq!(move_item(&mut v, 0, true), None);
        assert_eq!(move_item(&mut v, 2, false), None);
        assert_eq!(move_item(&mut v, 5, true), None);
        assert_eq!(move_item(&mut v, 0, false), Some(1));
        assert_eq!(v, vec![2, 1, 3]);
        assert_eq!(move_item(&mut v, 2, true), Some(1));
        assert_eq!(v, vec![2, 3, 1]);
    }

    #[test]
    fn bypass_text() {
        let nets =
            parse_bypass("10.0.0.0/8\n\n 192.168.1.1 # router\n::1\n# comment only").unwrap();
        assert_eq!(bypass_to_text(&nets), "10.0.0.0/8\n192.168.1.1/32\n::1/128");
        let err = parse_bypass("10.0.0.0/8\nnope").unwrap_err();
        assert!(err.contains("строка 2"), "{err}");
        assert!(parse_bypass("").unwrap().is_empty());
    }

    #[test]
    fn formatting() {
        assert_eq!(format_bytes(0), "0 Б");
        assert_eq!(format_bytes(1023), "1023 Б");
        assert_eq!(format_bytes(1536), "1.5 КБ");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 МБ");
        assert_eq!(format_bytes(u64::MAX), "16777216.0 ТБ");
        assert_eq!(format_duration(Duration::from_secs(5)), "5 с");
        assert_eq!(format_duration(Duration::from_secs(65)), "1 мин 05 с");
        assert_eq!(
            format_duration(Duration::from_secs(3 * 3600 + 7 * 60)),
            "3 ч 07 мин"
        );
    }
}
