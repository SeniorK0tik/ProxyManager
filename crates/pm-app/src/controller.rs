//! Owns the runtime state: config, rules, NAT table, relay and interception.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use pm_core::config::{Config, ConfigError, ProxyProfile, ValidationError};
use pm_core::nat::{Engine, EngineStatsSnapshot, NatTable};
use pm_core::policy::Policy;
use pm_core::proxy::{self, CheckReport, ProxyError};
use pm_core::relay::{self, Relay};
use pm_core::rules::RuleSet;
use pm_core::tracker::Tracker;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::platform::{Interception, Platform};

const GC_INTERVAL: Duration = Duration::from_secs(10);

struct Running {
    interception: Box<dyn Interception>,
    stop: watch::Sender<bool>,
    relay_task: JoinHandle<()>,
    gc_task: JoinHandle<()>,
    engine: Arc<Engine>,
    port: u16,
    started: Instant,
}

/// Snapshot for the status bar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    pub running: bool,
    pub relay_port: Option<u16>,
    pub uptime: Option<Duration>,
    pub engine: EngineStatsSnapshot,
    pub nat_entries: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("в настройках есть ошибки")]
    Invalid(Vec<ValidationError>),
    #[error("настройки применены, но не сохранены: {0}")]
    Save(#[from] ConfigError),
}

pub struct Controller {
    runtime: tokio::runtime::Runtime,
    platform: Arc<dyn Platform>,
    config: Config,
    config_errors: Vec<ValidationError>,
    config_path: Option<PathBuf>,
    tracker: Arc<Tracker>,
    nat: Arc<NatTable>,
    policy: Arc<Policy>,
    relay: Arc<Relay>,
    running: Option<Running>,
}

impl Controller {
    /// Creates a stopped controller. An invalid config is kept (so the UI can show
    /// and fix it) but proxying cannot start until it is corrected.
    pub fn new(
        platform: Arc<dyn Platform>,
        config: Config,
        config_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("pm-runtime")
            .enable_all()
            .build()
            .context("не удалось создать асинхронный рантайм")?;
        let (rules, config_errors) = match RuleSet::compile(&config) {
            Ok(rules) => (rules, Vec::new()),
            Err(errors) => (RuleSet::default(), errors),
        };
        let nat = Arc::new(NatTable::default());
        let tracker = Arc::new(Tracker::default());
        let policy = Arc::new(Policy::new(
            platform.system_info(),
            rules,
            std::process::id(),
        ));
        let relay = Arc::new(Relay::new(
            nat.clone(),
            tracker.clone(),
            Duration::from_secs(config.general.connect_timeout_secs.max(1)),
        ));
        Ok(Self {
            runtime,
            platform,
            config,
            config_errors,
            config_path,
            tracker,
            nat,
            policy,
            relay,
            running: None,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Problems in the config the controller was created with (empty once a valid config is applied).
    pub fn config_errors(&self) -> &[ValidationError] {
        &self.config_errors
    }

    pub fn tracker(&self) -> &Arc<Tracker> {
        &self.tracker
    }

    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// Validates, applies (to new connections) and saves a config.
    pub fn apply(&mut self, config: Config) -> Result<(), ApplyError> {
        let rules = RuleSet::compile(&config).map_err(ApplyError::Invalid)?;
        self.policy.set_rules(rules);
        self.relay
            .set_connect_timeout(Duration::from_secs(config.general.connect_timeout_secs));
        self.config = config;
        self.config_errors.clear();
        info!(
            rules = self.config.rules.len(),
            proxies = self.config.proxies.len(),
            "configuration applied"
        );
        if let Some(path) = &self.config_path {
            self.config.save(path)?;
        }
        Ok(())
    }

    /// Starts the relay and packet interception.
    pub fn start(&mut self) -> anyhow::Result<()> {
        if self.running.is_some() {
            return Ok(());
        }
        if !self.config_errors.is_empty() {
            anyhow::bail!("исправьте ошибки в настройках перед запуском");
        }
        let listeners = self
            .runtime
            .block_on(relay::bind(0))
            .context("не удалось открыть локальный порт для relay")?;
        let port = listeners.port;
        let engine = Arc::new(Engine::new(port, self.nat.clone(), self.policy.clone()));
        let interception = self.platform.start(engine.clone())?;

        let (stop, rx) = watch::channel(false);
        let relay_task = self
            .runtime
            .spawn(self.relay.clone().run(listeners, rx.clone()));
        let gc_task = self.runtime.spawn(gc_loop(self.nat.clone(), rx));
        self.running = Some(Running {
            interception,
            stop,
            relay_task,
            gc_task,
            engine,
            port,
            started: Instant::now(),
        });
        info!(relay_port = port, "proxying started");
        Ok(())
    }

    /// Stops interception first (no new redirects), then the relay.
    pub fn stop(&mut self) {
        let Some(running) = self.running.take() else {
            return;
        };
        running.interception.stop();
        let _ = running.stop.send(true);
        let relay_task = running.relay_task;
        let finished = self
            .runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(5), relay_task).await });
        if finished.is_err() {
            warn!("relay did not stop in time");
        }
        running.gc_task.abort();
        self.nat.clear();
        info!("proxying stopped");
    }

    pub fn status(&self) -> Status {
        match &self.running {
            Some(r) => Status {
                running: true,
                relay_port: Some(r.port),
                uptime: Some(r.started.elapsed()),
                engine: r.engine.stats(),
                nat_entries: self.nat.len(),
            },
            None => Status::default(),
        }
    }

    /// Checks a proxy profile in the background (tunnel + HTTP request).
    pub fn spawn_check(
        &self,
        profile: ProxyProfile,
    ) -> JoinHandle<Result<CheckReport, ProxyError>> {
        let timeout = Duration::from_secs(self.config.general.connect_timeout_secs.max(1));
        self.runtime.spawn(async move {
            proxy::check(&profile, proxy::CHECK_HOST, 80, proxy::CHECK_PATH, timeout).await
        })
    }

    /// Waits for a finished background task.
    pub fn join<T>(&self, handle: JoinHandle<T>) -> Option<T> {
        self.runtime.block_on(handle).ok()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn gc_loop(nat: Arc<NatTable>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(GC_INTERVAL);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                nat.gc(Instant::now());
            }
            _ = stop.wait_for(|s| *s) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::NullSystemInfo;
    use crate::testing::{FakeInterception, FakePlatform};
    use pm_core::config::{Action, ProxyKind, Rule};
    use pm_core::nat::Verdict;
    use pm_core::packet::build::tcp;
    use pm_core::packet::tcp_flags::SYN;
    use pm_core::policy::SystemInfo;
    use pm_core::testing::{MockMode, MockProxy};
    use std::sync::atomic::{AtomicBool, Ordering};

    fn config() -> Config {
        let mut cfg = Config::default();
        cfg.proxies
            .push(ProxyProfile::new("p", ProxyKind::Socks5, "127.0.0.1", 1080));
        cfg.rules.push(Rule::new(
            "apps",
            vec!["app.exe".into()],
            Action::Proxy("p".into()),
        ));
        cfg
    }

    #[test]
    fn start_stop_lifecycle() {
        let platform = Arc::new(FakePlatform::default());
        let mut ctl = Controller::new(platform.clone(), config(), None).unwrap();
        assert!(!ctl.is_running());
        assert_eq!(ctl.status(), Status::default());

        ctl.start().unwrap();
        ctl.start().unwrap(); // idempotent
        let status = ctl.status();
        assert!(status.running);
        let port = status.relay_port.unwrap();
        assert!(port > 0);

        // The engine handed to the platform redirects the matching app.
        let engine = platform.engine.lock().clone().unwrap();
        assert_eq!(engine.relay_port(), port);
        let mut syn = tcp("10.0.0.2:50000", "203.0.113.10:80", SYN);
        assert_eq!(
            engine.handle_outbound(&mut syn),
            Verdict::Inject { outbound: false }
        );
        assert_eq!(ctl.status().nat_entries, 1);
        assert_eq!(ctl.status().engine.redirected, 1);

        ctl.stop();
        assert!(platform.stopped.load(Ordering::SeqCst));
        assert!(!ctl.is_running());
        assert_eq!(ctl.status().nat_entries, 0);
        ctl.stop(); // idempotent
    }

    #[test]
    fn apply_changes_rules_live_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let platform = Arc::new(FakePlatform::default());
        let mut ctl = Controller::new(platform.clone(), config(), Some(path.clone())).unwrap();
        assert_eq!(ctl.config_path(), Some(path.as_path()));
        ctl.start().unwrap();
        let engine = platform.engine.lock().clone().unwrap();

        let mut cfg = config();
        cfg.rules[0].action = Action::Block;
        cfg.general.connect_timeout_secs = 3;
        ctl.apply(cfg.clone()).unwrap();
        assert_eq!(ctl.config(), &cfg);
        assert_eq!(Config::load(&path).unwrap(), cfg);
        let mut syn = tcp("10.0.0.2:50001", "203.0.113.10:80", SYN);
        assert_eq!(
            engine.handle_outbound(&mut syn),
            Verdict::Drop,
            "new rules apply without restart"
        );

        let mut bad = cfg.clone();
        bad.rules[0].action = Action::Proxy("missing".into());
        let err = ctl.apply(bad).unwrap_err();
        assert!(
            matches!(err, ApplyError::Invalid(ref e) if e.len() == 1),
            "{err}"
        );
        assert_eq!(ctl.config(), &cfg, "invalid config is not applied");
    }

    #[test]
    fn apply_reports_save_errors() {
        let dir = tempfile::tempdir().unwrap();
        // A directory in place of the file makes saving fail.
        let mut ctl = Controller::new(
            Arc::new(FakePlatform::default()),
            config(),
            Some(dir.path().to_path_buf()),
        )
        .unwrap();
        let mut cfg = config();
        cfg.general.block_udp = false;
        let err = ctl.apply(cfg.clone()).unwrap_err();
        assert!(matches!(err, ApplyError::Save(_)));
        assert_eq!(ctl.config(), &cfg, "applied even though not saved");
    }

    #[test]
    fn invalid_initial_config_blocks_start_until_fixed() {
        let mut cfg = config();
        cfg.rules[0].action = Action::Proxy("ghost".into());
        let mut ctl = Controller::new(Arc::new(FakePlatform::default()), cfg, None).unwrap();
        assert_eq!(ctl.config_errors().len(), 1);
        assert!(ctl.start().is_err());
        ctl.apply(config()).unwrap();
        assert!(ctl.config_errors().is_empty());
        ctl.start().unwrap();
    }

    #[test]
    fn platform_failure_is_reported() {
        let platform = Arc::new(FakePlatform {
            fail: true,
            ..Default::default()
        });
        let mut ctl = Controller::new(platform, config(), None).unwrap();
        let err = ctl.start().unwrap_err();
        assert!(err.to_string().contains("boom"));
        assert!(!ctl.is_running());
    }

    #[test]
    fn proxy_check_runs_in_background() {
        let ctl = Controller::new(Arc::new(FakePlatform::default()), config(), None).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mock = rt.block_on(MockProxy::start(
            ProxyKind::Socks5,
            None,
            MockMode::Respond(b"HTTP/1.1 200 OK\r\n\r\nsuccess".to_vec()),
        ));
        let report = ctl
            .join(ctl.spawn_check(mock.profile("m")))
            .unwrap()
            .unwrap();
        assert_eq!(report.status_line, "HTTP/1.1 200 OK");
        assert!(ctl.tracker().snapshot().active.is_empty());
    }

    #[test]
    fn null_system_info_never_matches_rules() {
        struct NullPlatform;
        impl Platform for NullPlatform {
            fn system_info(&self) -> Arc<dyn SystemInfo> {
                Arc::new(NullSystemInfo)
            }
            fn start(&self, _: Arc<Engine>) -> anyhow::Result<Box<dyn Interception>> {
                Ok(Box::new(FakeInterception(Arc::new(AtomicBool::new(false)))))
            }
        }
        let mut ctl = Controller::new(Arc::new(NullPlatform), config(), None).unwrap();
        ctl.start().unwrap();
        drop(ctl); // Drop stops everything.
    }
}
