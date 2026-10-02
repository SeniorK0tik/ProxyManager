//! End-to-end tests with the real WinDivert driver.
//!
//! They need administrator rights and `WinDivert.dll` + `WinDivert64.sys` in the directory
//! given by `PM_WINDIVERT_DIR`, so they are ignored by default. Run with:
//!
//! ```text
//! cargo test -p pm-app --test e2e_windows -- --ignored --test-threads=1
//! ```
#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use pm_app::controller::Controller;
use pm_app::platform::WindowsPlatform;
use pm_core::config::{Action, Config, ProxyKind, Rule};
use pm_core::proxy::Target;
use pm_core::testing::{MockMode, MockProxy};

/// A public (non-bypassed) address from TEST-NET-3: nothing answers there,
/// so a successful response proves the connection went through the proxy.
const UNREACHABLE: &str = "203.0.113.10";
const BODY: &str = "proxied-by-proxy-manager";

fn windivert_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("PM_WINDIVERT_DIR")
            .expect("set PM_WINDIVERT_DIR to the WinDivert x64 directory"),
    )
}

fn curl(url: &str) -> (bool, String) {
    let out = Command::new("curl.exe")
        .args(["-s", "--max-time", "10", url])
        .output()
        .expect("curl.exe is available on Windows 10+");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn config(proxy: &MockProxy, action: Action) -> Config {
    let mut cfg = Config::default();
    cfg.proxies.push(proxy.profile("mock"));
    cfg.rules
        .push(Rule::new("curl", vec!["curl.exe".into()], action));
    cfg
}

fn response() -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    )
    .into_bytes()
}

#[test]
#[ignore = "needs administrator rights and the WinDivert driver"]
fn proxied_app_reaches_unroutable_host_through_socks5() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let proxy = rt.block_on(MockProxy::start(
        ProxyKind::Socks5,
        Some(("user", "pass")),
        MockMode::Respond(response()),
    ));
    let platform = Arc::new(WindowsPlatform::new(windivert_dir()));
    let mut ctl =
        Controller::new(platform, config(&proxy, Action::Proxy("mock".into())), None).unwrap();
    ctl.start().unwrap();

    let (ok, body) = curl(&format!("http://{UNREACHABLE}/"));
    let snapshot = ctl.tracker().snapshot();
    ctl.stop();

    assert!(ok, "curl failed; tracker: {snapshot:?}");
    assert_eq!(body, BODY);
    assert_eq!(
        proxy.requests(),
        vec![Target::Ip(format!("{UNREACHABLE}:80").parse().unwrap())]
    );
    let conn = snapshot
        .recent
        .first()
        .or(snapshot.active.first())
        .expect("connection tracked");
    assert!(
        conn.meta
            .process
            .as_deref()
            .unwrap()
            .to_lowercase()
            .ends_with("curl.exe")
    );
}

#[test]
#[ignore = "needs administrator rights and the WinDivert driver"]
fn http_connect_proxy_works_too() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let proxy = rt.block_on(MockProxy::start(
        ProxyKind::Http,
        None,
        MockMode::Respond(response()),
    ));
    let platform = Arc::new(WindowsPlatform::new(windivert_dir()));
    let mut ctl =
        Controller::new(platform, config(&proxy, Action::Proxy("mock".into())), None).unwrap();
    ctl.start().unwrap();
    let (ok, body) = curl(&format!("http://{UNREACHABLE}:8080/"));
    ctl.stop();
    assert!(ok);
    assert_eq!(body, BODY);
    assert_eq!(
        proxy.requests(),
        vec![Target::Ip(format!("{UNREACHABLE}:8080").parse().unwrap())]
    );
}

#[test]
#[ignore = "needs administrator rights and the WinDivert driver"]
fn blocked_app_cannot_connect_and_rules_change_live() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let proxy = rt.block_on(MockProxy::start(
        ProxyKind::Socks5,
        None,
        MockMode::Respond(response()),
    ));
    let platform = Arc::new(WindowsPlatform::new(windivert_dir()));
    let mut ctl = Controller::new(platform, config(&proxy, Action::Block), None).unwrap();
    ctl.start().unwrap();

    let (ok, _) = curl(&format!("http://{UNREACHABLE}/"));
    assert!(!ok, "blocked connection must fail");
    assert!(ctl.status().engine.blocked_tcp >= 1);
    assert!(proxy.requests().is_empty());

    // Switch the rule to the proxy without restarting.
    ctl.apply(config(&proxy, Action::Proxy("mock".into())))
        .unwrap();
    let (ok, body) = curl(&format!("http://{UNREACHABLE}/"));
    ctl.stop();
    assert!(ok);
    assert_eq!(body, BODY);
}

#[test]
#[ignore = "needs administrator rights and the WinDivert driver"]
fn other_traffic_is_untouched() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let proxy = rt.block_on(MockProxy::start(ProxyKind::Socks5, None, MockMode::Refuse));
    let mut cfg = config(&proxy, Action::Proxy("mock".into()));
    cfg.rules[0].apps = vec!["some-other-app.exe".into()];
    let platform = Arc::new(WindowsPlatform::new(windivert_dir()));
    let mut ctl = Controller::new(platform, cfg, None).unwrap();
    ctl.start().unwrap();

    // Real Internet access through the interception loop (packets are reinjected unchanged).
    let out = Command::new("curl.exe")
        .args([
            "-s",
            "-o",
            "NUL",
            "-w",
            "%{http_code}",
            "--max-time",
            "20",
            "https://example.com/",
        ])
        .output()
        .unwrap();
    ctl.stop();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "200");
    assert!(proxy.requests().is_empty());
}
