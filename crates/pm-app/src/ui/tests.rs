//! Headless UI tests: the real widgets are rendered and clicked through AccessKit.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use pm_core::config::{Action, ProxyKind, ProxyProfile, Rule};
use pm_core::logbuf::LogLine;
use pm_core::testing::{MockMode, MockProxy};
use pm_core::tracker::ConnMeta;

use super::*;
use crate::testing::FakePlatform;

fn sample_config() -> Config {
    let mut cfg = Config::default();
    cfg.proxies
        .push(ProxyProfile::new("home", ProxyKind::Socks5, "127.0.0.1", 1080).with_auth("u", "p"));
    cfg.proxies.push(ProxyProfile::new(
        "spare",
        ProxyKind::Http,
        "proxy.local",
        3128,
    ));
    cfg.rules.push(Rule::new(
        "Browsers",
        vec!["chrome.exe".into()],
        Action::Proxy("home".into()),
    ));
    cfg
}

fn app_with(cfg: Config, path: Option<PathBuf>, platform: FakePlatform) -> ProxyManagerApp {
    let ctl = Controller::new(Arc::new(platform), cfg, path).unwrap();
    let opts = AppOptions {
        elevated: true,
        ..Default::default()
    };
    ProxyManagerApp::with_context(&egui::Context::default(), ctl, LogBuffer::new(100), opts)
}

fn harness(app: ProxyManagerApp) -> Harness<'static, ProxyManagerApp> {
    let mut h = Harness::builder()
        .with_size([1400.0, 1000.0])
        .build_ui_state(
            |ui, app: &mut ProxyManagerApp| {
                let ctx = ui.ctx().clone();
                app.tick(&ctx);
                app.draw(ui);
            },
            app,
        );
    h.run();
    h
}

fn default_harness() -> Harness<'static, ProxyManagerApp> {
    harness(app_with(sample_config(), None, FakePlatform::default()))
}

fn show(h: &mut Harness<'static, ProxyManagerApp>, tab: Tab) {
    h.state_mut().tab = tab;
    h.run();
}

fn click(h: &mut Harness<'static, ProxyManagerApp>, label: &str) {
    h.get_by_label(label).click();
    h.run();
}

#[test]
fn every_tab_renders() {
    let mut h = default_harness();
    let tracker = h.state().ctl.tracker().clone();
    let meta = |port| ConnMeta {
        pid: Some(1),
        process: Some(Arc::from("C:\\b\\chrome.exe")),
        rule: Some(Arc::from("Browsers")),
        proxy: Arc::from("home"),
        target: SocketAddr::from(([1, 2, 3, 4], port)),
    };
    let open = tracker.open(meta(443));
    open.established();
    let failed = tracker.open(meta(80));
    failed.fail("отказ");
    drop(failed);
    drop(tracker.open(meta(8080)));
    h.state().logs.push(LogLine {
        time: chrono::Local::now(),
        level: tracing::Level::WARN,
        target: "t".into(),
        message: "warning-line".into(),
    });

    for tab in Tab::ALL {
        show(&mut h, tab);
        assert!(
            h.query_by_label(tab.title()).is_some(),
            "tab button {tab:?}"
        );
    }
    show(&mut h, Tab::Connections);
    assert!(h.query_by_label("Активные (1)").is_some());
    assert!(h.query_by_label("Завершённые (2)").is_some());
    show(&mut h, Tab::Log);
    assert!(h.query_by_label_contains("warning-line").is_some());
    show(&mut h, Tab::Rules);
    assert!(h.query_by_label("Остальные приложения:").is_some());
    drop(open);
}

#[test]
fn tabs_switch_by_click() {
    let mut h = default_harness();
    for tab in [Tab::Proxies, Tab::Settings, Tab::Rules] {
        click(&mut h, tab.title());
        assert_eq!(h.state().tab, tab);
    }
}

#[test]
fn rules_add_edit_apply_and_revert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut h = harness(app_with(
        sample_config(),
        Some(path.clone()),
        FakePlatform::default(),
    ));

    click(&mut h, "➕ Добавить");
    assert_eq!(h.state().draft.rules.len(), 2);
    assert_eq!(h.state().rule_sel, Some(1));
    assert!(h.query_by_label("Есть неприменённые изменения").is_some());

    h.state_mut().app_input = "telegram.exe".into();
    h.run();
    click(&mut h, "Добавить");
    assert_eq!(h.state().draft.rules[1].apps, vec!["telegram.exe"]);
    assert!(h.state().app_input.is_empty());

    click(&mut h, "✖");
    assert!(h.state().draft.rules[1].apps.is_empty());
    assert!(h.query_by_label_contains("Пока пусто").is_some());
    h.state_mut().draft.rules[1]
        .apps
        .push("telegram.exe".into());
    h.run();

    click(&mut h, "⬆");
    assert_eq!(h.state().draft.rules[0].apps, vec!["telegram.exe"]);
    assert_eq!(h.state().rule_sel, Some(0));
    click(&mut h, "⬇");
    assert_eq!(h.state().rule_sel, Some(1));

    click(&mut h, "Применить");
    assert_eq!(h.state().ctl.config().rules.len(), 2);
    assert_eq!(pm_core::config::Config::load(&path).unwrap().rules.len(), 2);
    assert!(
        h.query_by_label("Настройки применены и сохранены")
            .is_some()
    );

    click(&mut h, "🗑");
    assert_eq!(h.state().draft.rules.len(), 1);
    click(&mut h, "Отменить");
    assert_eq!(h.state().draft.rules.len(), 2);
    assert!(h.query_by_label("Есть неприменённые изменения").is_none());

    // Selecting a rule from the list.
    click(&mut h, "Browsers\nЧерез прокси «home»");
    assert_eq!(h.state().rule_sel, Some(0));
    // "From running processes" jumps to the processes tab with this rule as the target.
    click(&mut h, "📋 Из запущенных…");
    assert_eq!(h.state().tab, Tab::Processes);
    assert_eq!(h.state().proc_target, Some(0));
}

#[test]
fn invalid_changes_are_reported() {
    let mut h = default_harness();
    click(&mut h, "➕ Добавить");
    click(&mut h, "Применить");
    assert_eq!(h.state().errors.len(), 1, "{:?}", h.state().errors);
    assert!(
        h.query_by_label_contains("не указано ни одного приложения")
            .is_some()
    );
    assert_eq!(
        h.state().ctl.config().rules.len(),
        1,
        "invalid config not applied"
    );
}

#[test]
fn rules_tab_without_selection() {
    let mut h = harness(app_with(Config::default(), None, FakePlatform::default()));
    assert!(h.query_by_label_contains("Выберите правило").is_some());
    show(&mut h, Tab::Proxies);
    assert!(
        h.query_by_label_contains("Добавьте прокси-сервер")
            .is_some()
    );
}

#[test]
fn start_and_stop_from_header() {
    let mut h = default_harness();
    assert!(h.query_by_label("○ Остановлен").is_some());
    click(&mut h, "Запустить");
    assert!(h.state().ctl.is_running());
    assert!(h.query_by_label("● Работает").is_some());
    assert!(h.query_by_label_contains("перенаправлено 0").is_some());
    click(&mut h, "Остановить");
    assert!(!h.state().ctl.is_running());
    assert!(h.query_by_label("Проксирование остановлено").is_some());
}

#[test]
fn start_failure_and_autostart() {
    let platform = FakePlatform {
        fail: true,
        ..Default::default()
    };
    let mut h = harness(app_with(sample_config(), None, platform));
    click(&mut h, "Запустить");
    assert!(!h.state().ctl.is_running());
    assert!(h.query_by_label_contains("Не удалось запустить").is_some());

    let mut cfg = sample_config();
    cfg.general.autostart = true;
    let h = harness(app_with(cfg, None, FakePlatform::default()));
    assert!(h.state().ctl.is_running(), "autostart starts proxying");
}

#[test]
fn proxies_edit_check_and_delete() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mock = rt.block_on(MockProxy::start(
        ProxyKind::Socks5,
        Some(("u", "p")),
        MockMode::Respond(b"HTTP/1.1 200 OK\r\n\r\nsuccess".to_vec()),
    ));
    let mut cfg = sample_config();
    cfg.proxies[0].port = mock.addr.port();
    let mut h = harness(app_with(cfg, None, FakePlatform::default()));
    show(&mut h, Tab::Proxies);

    // Used proxy cannot be deleted.
    click(&mut h, "🗑");
    assert_eq!(h.state().draft.proxies.len(), 2);

    // The spinner keeps repainting, so step manually instead of `run`.
    h.get_by_label("🔍 Проверить").click();
    h.run_steps(1);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !matches!(h.state().checks.get("home"), Some(Check::Done(_))) {
        assert!(Instant::now() < deadline, "check did not finish");
        std::thread::sleep(Duration::from_millis(20));
        h.run_steps(1);
    }
    h.run_steps(2);
    assert!(h.query_by_label_contains("✔ работает").is_some());

    // Renaming updates the rule that references the proxy.
    // The name field is the first text input of the editor.
    h.get_all_by_role(Role::TextInput).next().unwrap().click();
    h.run();
    h.get_all_by_role(Role::TextInput)
        .next()
        .unwrap()
        .type_text("2");
    h.run();
    let new_name = h.state().draft.proxies[0].name.clone();
    assert_ne!(new_name, "home");
    assert_eq!(
        h.state().draft.rules[0].action,
        Action::Proxy(new_name.clone())
    );
    assert!(
        h.state().checks.contains_key(&new_name),
        "check result follows the rename"
    );

    click(&mut h, "показать");
    assert!(h.state().show_password);

    // The unused proxy can be deleted.
    click(&mut h, "spare\nHTTP CONNECT proxy.local:3128");
    assert_eq!(h.state().proxy_sel, Some(1));
    click(&mut h, "🗑");
    assert_eq!(h.state().draft.proxies.len(), 1);

    click(&mut h, "➕ Добавить");
    assert_eq!(h.state().draft.proxies.len(), 2);
    assert!(h.query_by_label_contains("не используется").is_some());
}

#[test]
fn failed_proxy_check_is_shown() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut cfg = sample_config();
    cfg.proxies[0].port = port;
    let mut h = harness(app_with(cfg, None, FakePlatform::default()));
    show(&mut h, Tab::Proxies);
    // The spinner keeps repainting, so step manually instead of `run`.
    h.get_by_label("🔍 Проверить").click();
    h.run_steps(1);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !matches!(h.state().checks.get("home"), Some(Check::Done(_))) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
        h.run_steps(1);
    }
    h.run_steps(2);
    assert!(
        h.query_by_label_contains("✖ не удалось подключиться")
            .is_some()
    );
}

#[test]
fn processes_can_be_added_to_rules() {
    let mut h = default_harness();
    show(&mut h, Tab::Processes);
    // Filter down to this test process (its name may be truncated on Linux, so use its path).
    let me = h
        .state()
        .processes
        .iter()
        .find(|e| e.pids.contains(&std::process::id()))
        .unwrap()
        .clone();
    let name = me.name.clone();
    h.state_mut().proc_filter = me.path.clone().unwrap();
    h.run();

    // Into a new rule, by name.
    h.get_all_by_label("По имени").next().unwrap().click();
    h.run();
    let rules = &h.state().draft.rules;
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[1].apps, vec![name.clone()]);
    assert_eq!(h.state().tab, Tab::Rules, "a new rule opens the rules tab");

    // Into the existing rule, by path.
    show(&mut h, Tab::Processes);
    assert_eq!(h.state().proc_target, Some(1));
    h.get_all_by_label("По пути").next().unwrap().click();
    h.run();
    assert_eq!(h.state().draft.rules[1].apps.len(), 2);
    assert_eq!(h.state().tab, Tab::Processes);

    click(&mut h, "🔄 Обновить");
    assert!(!h.state().processes.is_empty());
}

#[test]
fn log_level_filter_and_clear() {
    let mut h = default_harness();
    for (level, msg) in [
        (tracing::Level::INFO, "info-line"),
        (tracing::Level::DEBUG, "debug-line"),
    ] {
        h.state().logs.push(LogLine {
            time: chrono::Local::now(),
            level,
            target: "t".into(),
            message: msg.into(),
        });
    }
    show(&mut h, Tab::Log);
    assert!(h.query_by_label_contains("info-line").is_some());
    assert!(h.query_by_label_contains("debug-line").is_none());
    h.state_mut().log_level = tracing::Level::DEBUG;
    h.run();
    assert!(h.query_by_label_contains("debug-line").is_some());
    click(&mut h, "Очистить");
    assert!(h.state().logs.lines().is_empty());
}

#[test]
fn connection_history_can_be_cleared() {
    let mut h = default_harness();
    let tracker = h.state().ctl.tracker().clone();
    drop(tracker.open(ConnMeta {
        pid: None,
        process: None,
        rule: None,
        proxy: Arc::from("home"),
        target: SocketAddr::from(([1, 1, 1, 1], 1)),
    }));
    show(&mut h, Tab::Connections);
    assert!(h.query_by_label("Завершённые (1)").is_some());
    click(&mut h, "Очистить историю");
    assert!(h.query_by_label("Завершённые (0)").is_some());
    assert!(
        h.query_by_label_contains("Нет активных соединений")
            .is_some()
    );
}

#[test]
fn settings_bypass_editing() {
    let mut h = default_harness();
    show(&mut h, Tab::Settings);
    click(&mut h, "Блокировать UDP у проксируемых приложений");
    assert!(!h.state().draft.general.block_udp);
    let editor = h.get_by_role(Role::MultilineTextInput);
    editor.click();
    h.run();
    h.get_by_role(Role::MultilineTextInput)
        .type_text("\nnot-a-network");
    h.run();
    assert!(h.state().bypass_error.is_some());
    assert!(h.query_by_label_contains("не адрес и не подсеть").is_some());

    // Applying is refused while the list is invalid.
    click(&mut h, "Применить");
    assert!(
        h.query_by_label_contains("Исправьте список исключений")
            .is_some()
    );

    click(&mut h, "Вернуть стандартный список");
    assert!(h.state().bypass_error.is_none());
    assert_eq!(
        h.state().draft.general.bypass,
        pm_core::config::default_bypass()
    );

    click(&mut h, "Включать проксирование при запуске программы");
    assert!(h.state().draft.general.autostart);
}

#[test]
fn notices_expire_and_footer_shows_config_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cfg.toml");
    let mut h = harness(app_with(
        sample_config(),
        Some(path.clone()),
        FakePlatform::default(),
    ));
    assert!(h.query_by_label_contains("cfg.toml").is_some());
    h.state_mut().notify("hello", false);
    h.run();
    assert!(h.query_by_label("hello").is_some());
    h.state_mut().notice.as_mut().unwrap().at = Instant::now() - NOTICE_TTL;
    h.run();
    assert!(h.query_by_label("hello").is_none());

    let mut h = default_harness();
    assert!(h.query_by_label("Конфиг не сохраняется").is_some());
    h.state_mut().elevated = false;
    h.run();
    assert_eq!(
        h.query_by_label_contains("без прав администратора")
            .is_some(),
        cfg!(windows),
        "the elevation warning is Windows-only"
    );
}

#[test]
fn save_errors_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    // A directory in place of the config file.
    let mut h = harness(app_with(
        sample_config(),
        Some(dir.path().to_path_buf()),
        FakePlatform::default(),
    ));
    h.state_mut().draft.general.allow_dns = false;
    h.run();
    click(&mut h, "Применить");
    assert!(h.query_by_label_contains("не сохранены").is_some());
    assert!(!h.state().ctl.config().general.allow_dns, "still applied");
}

#[test]
fn invalid_startup_config_is_shown() {
    let mut cfg = sample_config();
    cfg.rules[0].action = Action::Proxy("ghost".into());
    let h = harness(app_with(cfg, None, FakePlatform::default()));
    assert!(
        h.query_by_label_contains("несуществующий прокси «ghost»")
            .is_some()
    );
}
