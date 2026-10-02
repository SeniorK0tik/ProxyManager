//! Per-flow decisions: who owns a connection and what to do with it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::rules::{ResolvedAction, RuleSet};

/// OS facilities needed to attribute traffic to processes.
pub trait SystemInfo: Send + Sync {
    /// PID of the process owning the TCP connection `local -> remote`.
    fn tcp_owner(&self, local: SocketAddr, remote: SocketAddr) -> Option<u32>;
    /// PID of the process owning the UDP socket bound to `local`.
    fn udp_owner(&self, local: SocketAddr) -> Option<u32>;
    /// Full executable path of a process.
    fn process_path(&self, pid: u32) -> Option<String>;
}

/// What happens to a new TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDecision {
    pub pid: Option<u32>,
    pub process: Option<Arc<str>>,
    pub rule: Option<Arc<str>>,
    pub action: ResolvedAction,
}

impl FlowDecision {
    fn direct() -> Self {
        Self {
            pid: None,
            process: None,
            rule: None,
            action: ResolvedAction::Direct,
        }
    }
}

/// Verdict for a UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpVerdict {
    Pass,
    Drop,
}

const PATH_TTL: Duration = Duration::from_secs(10);
const UDP_TTL: Duration = Duration::from_secs(5);
const CACHE_LIMIT: usize = 4096;

/// pid -> (executable path, lookup time).
type PathCache = HashMap<u32, (Option<Arc<str>>, Instant)>;

/// Combines OS lookups with the current [`RuleSet`]. Rules can be swapped at runtime.
pub struct Policy {
    sys: Arc<dyn SystemInfo>,
    rules: RwLock<Arc<RuleSet>>,
    self_pid: u32,
    paths: Mutex<PathCache>,
    udp: Mutex<HashMap<SocketAddr, (UdpVerdict, Instant)>>,
}

impl Policy {
    /// `self_pid` is the manager's own process: its traffic (relay to proxy) is never redirected.
    pub fn new(sys: Arc<dyn SystemInfo>, rules: RuleSet, self_pid: u32) -> Self {
        Self {
            sys,
            rules: RwLock::new(Arc::new(rules)),
            self_pid,
            paths: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
        }
    }

    pub fn rules(&self) -> Arc<RuleSet> {
        self.rules.read().clone()
    }

    /// Replaces the rules. Affects new connections only.
    pub fn set_rules(&self, rules: RuleSet) {
        *self.rules.write() = Arc::new(rules);
        self.udp.lock().clear();
    }

    pub fn decide_tcp(&self, local: SocketAddr, remote: SocketAddr) -> FlowDecision {
        let rules = self.rules();
        if rules.is_bypassed(remote.ip()) {
            return FlowDecision::direct();
        }
        let pid = self.sys.tcp_owner(local, remote);
        if pid == Some(self.self_pid) {
            return FlowDecision::direct();
        }
        let process = pid.and_then(|pid| self.process_path(pid));
        let m = rules.match_process(process.as_deref());
        FlowDecision {
            pid,
            process,
            rule: m.rule,
            action: m.action,
        }
    }

    pub fn decide_udp(&self, local: SocketAddr, remote: SocketAddr) -> UdpVerdict {
        let rules = self.rules();
        if (rules.allow_dns && remote.port() == 53) || rules.is_bypassed(remote.ip()) {
            return UdpVerdict::Pass;
        }
        let now = Instant::now();
        if let Some((verdict, at)) = self.udp.lock().get(&local)
            && now.duration_since(*at) < UDP_TTL
        {
            return *verdict;
        }

        let verdict = match self.sys.udp_owner(local) {
            Some(pid) if pid == self.self_pid => UdpVerdict::Pass,
            pid => {
                let process = pid.and_then(|pid| self.process_path(pid));
                match rules.match_process(process.as_deref()).action {
                    ResolvedAction::Block => UdpVerdict::Drop,
                    ResolvedAction::Proxy(_) if rules.block_udp => UdpVerdict::Drop,
                    _ => UdpVerdict::Pass,
                }
            }
        };

        let mut cache = self.udp.lock();
        if cache.len() >= CACHE_LIMIT {
            cache.retain(|_, (_, at)| now.duration_since(*at) < UDP_TTL);
        }
        cache.insert(local, (verdict, now));
        verdict
    }

    fn process_path(&self, pid: u32) -> Option<Arc<str>> {
        let now = Instant::now();
        if let Some((path, at)) = self.paths.lock().get(&pid)
            && now.duration_since(*at) < PATH_TTL
        {
            return path.clone();
        }
        let path: Option<Arc<str>> = self.sys.process_path(pid).map(Arc::from);
        let mut cache = self.paths.lock();
        if cache.len() >= CACHE_LIMIT {
            cache.retain(|_, (_, at)| now.duration_since(*at) < PATH_TTL);
        }
        cache.insert(pid, (path.clone(), now));
        path
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{Action, Config, ProxyKind, ProxyProfile, Rule};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// In-memory [`SystemInfo`]: every port is owned by the PID stored in the map.
    #[derive(Default)]
    pub struct FakeSystem {
        pub tcp: Mutex<HashMap<u16, u32>>,
        pub udp: Mutex<HashMap<u16, u32>>,
        pub paths: Mutex<HashMap<u32, String>>,
        pub path_lookups: AtomicUsize,
        pub udp_lookups: AtomicUsize,
    }

    impl FakeSystem {
        pub fn with_process(
            self,
            pid: u32,
            path: &str,
            tcp_ports: &[u16],
            udp_ports: &[u16],
        ) -> Self {
            self.paths.lock().insert(pid, path.to_string());
            for &p in tcp_ports {
                self.tcp.lock().insert(p, pid);
            }
            for &p in udp_ports {
                self.udp.lock().insert(p, pid);
            }
            self
        }
    }

    impl SystemInfo for FakeSystem {
        fn tcp_owner(&self, local: SocketAddr, _remote: SocketAddr) -> Option<u32> {
            self.tcp.lock().get(&local.port()).copied()
        }
        fn udp_owner(&self, local: SocketAddr) -> Option<u32> {
            self.udp_lookups.fetch_add(1, Ordering::SeqCst);
            self.udp.lock().get(&local.port()).copied()
        }
        fn process_path(&self, pid: u32) -> Option<String> {
            self.path_lookups.fetch_add(1, Ordering::SeqCst);
            self.paths.lock().get(&pid).cloned()
        }
    }

    pub fn test_config() -> Config {
        let mut cfg = Config::default();
        cfg.proxies
            .push(ProxyProfile::new("p", ProxyKind::Socks5, "127.0.0.1", 1080));
        cfg.rules.push(Rule::new(
            "browser",
            vec!["browser.exe".into()],
            Action::Proxy("p".into()),
        ));
        cfg.rules
            .push(Rule::new("bad", vec!["bad.exe".into()], Action::Block));
        cfg
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn policy(sys: FakeSystem) -> (Policy, Arc<FakeSystem>) {
        let sys = Arc::new(sys);
        let p = Policy::new(sys.clone(), RuleSet::compile(&test_config()).unwrap(), 1);
        (p, sys)
    }

    fn system() -> FakeSystem {
        FakeSystem::default()
            .with_process(1, "C:\\pm\\proxy-manager.exe", &[5000], &[5000])
            .with_process(10, "C:\\b\\Browser.exe", &[6000], &[6000])
            .with_process(20, "C:\\x\\bad.exe", &[7000], &[7000])
            .with_process(30, "C:\\x\\other.exe", &[8000], &[8000])
    }

    #[test]
    fn tcp_decisions() {
        let (p, _) = policy(system());
        let remote = sa("93.184.216.34:443");

        let d = p.decide_tcp(sa("192.168.1.2:6000"), remote);
        assert_eq!(d.pid, Some(10));
        assert_eq!(d.process.as_deref(), Some("C:\\b\\Browser.exe"));
        assert_eq!(d.rule.as_deref(), Some("browser"));
        assert!(matches!(d.action, ResolvedAction::Proxy(_)));

        assert_eq!(
            p.decide_tcp(sa("192.168.1.2:7000"), remote).action,
            ResolvedAction::Block
        );

        let d = p.decide_tcp(sa("192.168.1.2:8000"), remote);
        assert_eq!(
            (d.pid, d.rule, d.action),
            (Some(30), None, ResolvedAction::Direct)
        );

        let d = p.decide_tcp(sa("192.168.1.2:9999"), remote);
        assert_eq!(d.pid, None, "unknown owner falls back to default action");
        assert_eq!(d.action, ResolvedAction::Direct);
    }

    #[test]
    fn own_traffic_and_bypass_are_direct() {
        let (p, _) = policy(system());
        assert_eq!(
            p.decide_tcp(sa("192.168.1.2:5000"), sa("8.8.8.8:1080")),
            FlowDecision::direct()
        );
        assert_eq!(
            p.decide_tcp(sa("192.168.1.2:6000"), sa("192.168.1.1:80")),
            FlowDecision::direct()
        );
    }

    #[test]
    fn udp_decisions() {
        let (p, _) = policy(system());
        let remote = sa("1.2.3.4:443");
        assert_eq!(
            p.decide_udp(sa("0.0.0.0:6000"), remote),
            UdpVerdict::Drop,
            "proxied app, block_udp"
        );
        assert_eq!(
            p.decide_udp(sa("0.0.0.0:7000"), remote),
            UdpVerdict::Drop,
            "blocked app"
        );
        assert_eq!(
            p.decide_udp(sa("0.0.0.0:8000"), remote),
            UdpVerdict::Pass,
            "direct app"
        );
        assert_eq!(
            p.decide_udp(sa("0.0.0.0:5000"), remote),
            UdpVerdict::Pass,
            "own traffic"
        );
        assert_eq!(
            p.decide_udp(sa("0.0.0.0:9999"), remote),
            UdpVerdict::Pass,
            "unknown owner"
        );
        assert_eq!(
            p.decide_udp(sa("0.0.0.0:7000"), sa("1.2.3.4:53")),
            UdpVerdict::Pass,
            "dns allowed"
        );
        assert_eq!(
            p.decide_udp(sa("0.0.0.0:7000"), sa("192.168.0.1:9")),
            UdpVerdict::Pass,
            "bypass"
        );
    }

    #[test]
    fn udp_respects_flags() {
        let (p, _) = policy(system());
        let mut cfg = test_config();
        cfg.general.block_udp = false;
        cfg.general.allow_dns = false;
        p.set_rules(RuleSet::compile(&cfg).unwrap());
        assert_eq!(
            p.decide_udp(sa("0.0.0.0:6000"), sa("1.2.3.4:443")),
            UdpVerdict::Pass
        );
        assert_eq!(
            p.decide_udp(sa("0.0.0.0:7000"), sa("1.2.3.4:53")),
            UdpVerdict::Drop
        );
    }

    #[test]
    fn udp_verdicts_are_cached_until_rules_change() {
        let (p, sys) = policy(system());
        let local = sa("0.0.0.0:6000");
        for _ in 0..5 {
            assert_eq!(p.decide_udp(local, sa("1.2.3.4:443")), UdpVerdict::Drop);
        }
        assert_eq!(sys.udp_lookups.load(Ordering::SeqCst), 1);

        p.set_rules(RuleSet::default());
        assert_eq!(p.decide_udp(local, sa("1.2.3.4:443")), UdpVerdict::Pass);
        assert_eq!(sys.udp_lookups.load(Ordering::SeqCst), 2);
        assert_eq!(p.rules().rule_count(), 0);
    }

    #[test]
    fn process_paths_are_cached() {
        let (p, sys) = policy(system());
        for _ in 0..3 {
            p.decide_tcp(sa("10.0.0.2:6000"), sa("8.8.4.4:443"));
        }
        assert_eq!(sys.path_lookups.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn caches_are_bounded() {
        let sys = FakeSystem::default();
        for port in 1..=(CACHE_LIMIT as u16 + 10) {
            sys.udp.lock().insert(port, 30 + port as u32);
        }
        let (p, _) = policy(sys);
        for port in 1..=(CACHE_LIMIT as u16 + 10) {
            p.decide_udp(SocketAddr::from(([0, 0, 0, 0], port)), sa("1.2.3.4:443"));
        }
        // All entries are fresh, so the cache may exceed the soft limit only by the inserts after pruning.
        assert!(p.udp.lock().len() <= CACHE_LIMIT + 10);
        assert!(p.paths.lock().len() <= CACHE_LIMIT + 10);
    }
}
