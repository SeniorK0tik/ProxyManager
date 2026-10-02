//! NAT engine: redirects selected TCP connections to the local relay.
//!
//! The redirect uses the "reflection" trick: an outbound packet `L:p -> R:443` from a
//! proxied application is rewritten to `R:p -> L:relay_port` and reinjected as *inbound*.
//! The relay therefore accepts a connection whose peer address is `R:p`, which is the
//! key into the [`NatTable`] holding the original destination. Relay replies
//! `L:relay_port -> R:p` are rewritten back to `R:443 -> L:p` and also reinjected inbound,
//! so the application believes it talks to the real server.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::debug;

use crate::packet::{self, PROTO_TCP, PROTO_UDP, Packet};
use crate::policy::{FlowDecision, Policy, UdpVerdict};
use crate::rules::{ResolvedAction, canonical_ip};

/// Lifecycle of a redirected connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// SYN redirected, relay has not accepted yet.
    Pending,
    /// The relay is serving the connection.
    Active,
    /// The relay finished; kept for a while so FIN/ACK stragglers still get translated.
    Closed(Instant),
}

#[derive(Debug, Clone)]
pub struct NatEntry {
    /// Original destination of the application.
    pub orig_dst: SocketAddr,
    pub decision: FlowDecision,
    pub state: EntryState,
    pub last_seen: Instant,
}

/// How long various entries survive garbage collection.
#[derive(Debug, Clone, Copy)]
pub struct NatTimeouts {
    pub pending: Duration,
    pub closed: Duration,
}

impl Default for NatTimeouts {
    fn default() -> Self {
        Self {
            pending: Duration::from_secs(60),
            // Covers the default Windows TIME_WAIT (2 * MSL = 120 s).
            closed: Duration::from_secs(120),
        }
    }
}

/// Maps the relay peer address (`R:p`) to the redirected connection.
#[derive(Debug, Default)]
pub struct NatTable {
    map: Mutex<HashMap<SocketAddr, NatEntry>>,
    timeouts: NatTimeouts,
}

/// Normalizes a socket address to be used as a [`NatTable`] key.
pub fn nat_key(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(canonical_ip(ip), port)
}

impl NatTable {
    pub fn new(timeouts: NatTimeouts) -> Self {
        Self {
            map: Mutex::default(),
            timeouts,
        }
    }

    pub fn insert(&self, key: SocketAddr, orig_dst: SocketAddr, decision: FlowDecision) {
        self.map.lock().insert(
            key,
            NatEntry {
                orig_dst,
                decision,
                state: EntryState::Pending,
                last_seen: Instant::now(),
            },
        );
    }

    /// Returns the original destination and refreshes the entry.
    pub fn touch(&self, key: &SocketAddr) -> Option<SocketAddr> {
        let mut map = self.map.lock();
        let entry = map.get_mut(key)?;
        entry.last_seen = Instant::now();
        Some(entry.orig_dst)
    }

    pub fn get(&self, key: &SocketAddr) -> Option<NatEntry> {
        self.map.lock().get(key).cloned()
    }

    pub fn remove(&self, key: &SocketAddr) -> Option<NatEntry> {
        self.map.lock().remove(key)
    }

    /// Marks a pending entry as served by the relay. Returns `None` for unknown or
    /// already claimed keys, so a stray connection to the relay port is rejected.
    pub fn claim(self: &Arc<Self>, key: SocketAddr) -> Option<ClaimGuard> {
        let mut map = self.map.lock();
        let entry = map.get_mut(&key)?;
        if entry.state != EntryState::Pending {
            return None;
        }
        entry.state = EntryState::Active;
        entry.last_seen = Instant::now();
        Some(ClaimGuard {
            table: self.clone(),
            key,
            entry: entry.clone(),
        })
    }

    fn release(&self, key: &SocketAddr) {
        if let Some(entry) = self.map.lock().get_mut(key)
            && entry.state == EntryState::Active
        {
            entry.state = EntryState::Closed(Instant::now());
        }
    }

    /// Drops expired entries. Active entries are owned by the relay and never expire.
    pub fn gc(&self, now: Instant) -> usize {
        let timeouts = self.timeouts;
        let mut map = self.map.lock();
        let before = map.len();
        map.retain(|_, e| match e.state {
            EntryState::Pending => now.saturating_duration_since(e.last_seen) < timeouts.pending,
            EntryState::Active => true,
            EntryState::Closed(at) => {
                now.saturating_duration_since(at.max(e.last_seen)) < timeouts.closed
            }
        });
        before - map.len()
    }

    pub fn len(&self) -> usize {
        self.map.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.lock().is_empty()
    }

    pub fn clear(&self) {
        self.map.lock().clear();
    }
}

/// Keeps a NAT entry in the `Active` state while the relay serves it.
pub struct ClaimGuard {
    table: Arc<NatTable>,
    key: SocketAddr,
    entry: NatEntry,
}

impl ClaimGuard {
    pub fn entry(&self) -> &NatEntry {
        &self.entry
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        self.table.release(&self.key);
    }
}

/// What to do with an intercepted packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Reinject unchanged.
    Pass,
    /// Discard.
    Drop,
    /// The packet was rewritten: recalculate checksums and reinject in the given direction.
    Inject { outbound: bool },
}

/// Counters shown in the UI.
#[derive(Debug, Default)]
pub struct EngineStats {
    pub redirected: AtomicU64,
    pub blocked_tcp: AtomicU64,
    pub blocked_udp: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineStatsSnapshot {
    pub redirected: u64,
    pub blocked_tcp: u64,
    pub blocked_udp: u64,
}

impl EngineStats {
    pub fn snapshot(&self) -> EngineStatsSnapshot {
        EngineStatsSnapshot {
            redirected: self.redirected.load(Ordering::Relaxed),
            blocked_tcp: self.blocked_tcp.load(Ordering::Relaxed),
            blocked_udp: self.blocked_udp.load(Ordering::Relaxed),
        }
    }
}

/// Platform-independent packet decision logic.
pub struct Engine {
    relay_port: u16,
    nat: Arc<NatTable>,
    policy: Arc<Policy>,
    stats: EngineStats,
}

impl Engine {
    pub fn new(relay_port: u16, nat: Arc<NatTable>, policy: Arc<Policy>) -> Self {
        Self {
            relay_port,
            nat,
            policy,
            stats: EngineStats::default(),
        }
    }

    pub fn relay_port(&self) -> u16 {
        self.relay_port
    }

    pub fn stats(&self) -> EngineStatsSnapshot {
        self.stats.snapshot()
    }

    /// Handles an outbound, non-loopback packet. May rewrite `pkt` in place.
    pub fn handle_outbound(&self, pkt: &mut [u8]) -> Verdict {
        let Some(mut p) = packet::parse(pkt) else {
            return Verdict::Pass;
        };
        match p.protocol {
            PROTO_TCP => self.handle_tcp(pkt, &mut p),
            PROTO_UDP => self.handle_udp(&p),
            _ => Verdict::Pass,
        }
    }

    fn handle_tcp(&self, pkt: &mut [u8], p: &mut Packet) -> Verdict {
        // Relay -> application: L:relay -> R:p  ==>  R:orig_port -> L:p (inbound).
        if p.src_port == self.relay_port {
            let key = nat_key(p.dst, p.dst_port);
            return match self.nat.touch(&key) {
                Some(orig) => {
                    packet::swap_addresses(pkt, p);
                    packet::set_src_port(pkt, p, orig.port());
                    Verdict::Inject { outbound: false }
                }
                None => Verdict::Pass,
            };
        }

        let key = nat_key(p.dst, p.src_port);
        if p.is_syn() {
            let local = SocketAddr::new(p.src, p.src_port);
            let remote = SocketAddr::new(p.dst, p.dst_port);
            let decision = self.policy.decide_tcp(local, remote);
            return match decision.action {
                ResolvedAction::Proxy(_) => {
                    // Retransmitted SYNs keep the pending entry; anything else starts over.
                    let retransmit = self
                        .nat
                        .get(&key)
                        .is_some_and(|e| e.orig_dst == remote && e.state == EntryState::Pending);
                    if !retransmit {
                        debug!(pid = ?decision.pid, process = ?decision.process, %remote, "redirect");
                        self.nat.insert(key, remote, decision);
                        self.stats.redirected.fetch_add(1, Ordering::Relaxed);
                    }
                    self.redirect(pkt, p)
                }
                ResolvedAction::Block => {
                    self.nat.remove(&key);
                    debug!(pid = ?decision.pid, process = ?decision.process, %remote, "blocked tcp");
                    self.stats.blocked_tcp.fetch_add(1, Ordering::Relaxed);
                    Verdict::Drop
                }
                ResolvedAction::Direct => {
                    self.nat.remove(&key);
                    Verdict::Pass
                }
            };
        }

        // Application -> relay for an established redirected connection.
        match self.nat.touch(&key) {
            Some(orig) if orig.port() == p.dst_port => self.redirect(pkt, p),
            _ => Verdict::Pass,
        }
    }

    /// L:p -> R:orig_port  ==>  R:p -> L:relay (inbound).
    fn redirect(&self, pkt: &mut [u8], p: &mut Packet) -> Verdict {
        packet::swap_addresses(pkt, p);
        packet::set_dst_port(pkt, p, self.relay_port);
        Verdict::Inject { outbound: false }
    }

    fn handle_udp(&self, p: &Packet) -> Verdict {
        let local = SocketAddr::new(p.src, p.src_port);
        let remote = SocketAddr::new(p.dst, p.dst_port);
        match self.policy.decide_udp(local, remote) {
            UdpVerdict::Pass => Verdict::Pass,
            UdpVerdict::Drop => {
                self.stats.blocked_udp.fetch_add(1, Ordering::Relaxed);
                Verdict::Drop
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::build::{tcp, udp};
    use crate::packet::tcp_flags::*;
    use crate::policy::tests::{FakeSystem, test_config};
    use crate::rules::RuleSet;

    const RELAY: u16 = 40000;

    fn engine() -> (Engine, Arc<NatTable>) {
        let sys = FakeSystem::default()
            .with_process(1, "C:\\pm\\pm.exe", &[5000], &[])
            .with_process(10, "C:\\b\\browser.exe", &[50000, 50002], &[50000])
            .with_process(20, "C:\\x\\bad.exe", &[51000], &[51000])
            .with_process(30, "C:\\x\\other.exe", &[52000], &[52000]);
        let policy = Arc::new(Policy::new(
            Arc::new(sys),
            RuleSet::compile(&test_config()).unwrap(),
            1,
        ));
        let nat = Arc::new(NatTable::default());
        (Engine::new(RELAY, nat.clone(), policy), nat)
    }

    fn parsed(pkt: &[u8]) -> Packet {
        packet::parse(pkt).unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn full_redirect_roundtrip_v4() {
        let (e, nat) = engine();
        assert_eq!(e.relay_port(), RELAY);

        // App SYN is reflected to the relay.
        let mut syn = tcp("192.168.1.5:50000", "93.184.216.34:443", SYN);
        assert_eq!(
            e.handle_outbound(&mut syn),
            Verdict::Inject { outbound: false }
        );
        let p = parsed(&syn);
        assert_eq!(
            SocketAddr::new(p.src, p.src_port),
            sa("93.184.216.34:50000")
        );
        assert_eq!(SocketAddr::new(p.dst, p.dst_port), sa("192.168.1.5:40000"));

        let key = sa("93.184.216.34:50000");
        let entry = nat.get(&key).unwrap();
        assert_eq!(entry.orig_dst, sa("93.184.216.34:443"));
        assert_eq!(entry.decision.pid, Some(10));
        assert_eq!(entry.state, EntryState::Pending);

        // Relay SYN-ACK goes back to the app as if from the real server.
        let mut synack = tcp("192.168.1.5:40000", "93.184.216.34:50000", SYN | ACK);
        assert_eq!(
            e.handle_outbound(&mut synack),
            Verdict::Inject { outbound: false }
        );
        let p = parsed(&synack);
        assert_eq!(SocketAddr::new(p.src, p.src_port), sa("93.184.216.34:443"));
        assert_eq!(SocketAddr::new(p.dst, p.dst_port), sa("192.168.1.5:50000"));

        // Subsequent app data keeps flowing to the relay.
        let mut data = tcp("192.168.1.5:50000", "93.184.216.34:443", ACK);
        assert_eq!(
            e.handle_outbound(&mut data),
            Verdict::Inject { outbound: false }
        );
        assert_eq!(parsed(&data).dst_port, RELAY);

        assert_eq!(e.stats().redirected, 1);
    }

    #[test]
    fn redirect_v6() {
        let (e, nat) = engine();
        let mut syn = tcp("[2001:db8::5]:50002", "[2a00:1450::1]:443", SYN);
        assert_eq!(
            e.handle_outbound(&mut syn),
            Verdict::Inject { outbound: false }
        );
        let p = parsed(&syn);
        assert_eq!(
            SocketAddr::new(p.dst, p.dst_port),
            sa("[2001:db8::5]:40000")
        );
        assert!(nat.get(&sa("[2a00:1450::1]:50002")).is_some());

        let mut reply = tcp("[2001:db8::5]:40000", "[2a00:1450::1]:50002", SYN | ACK);
        assert_eq!(
            e.handle_outbound(&mut reply),
            Verdict::Inject { outbound: false }
        );
        assert_eq!(parsed(&reply).src_port, 443);
    }

    #[test]
    fn retransmitted_syn_keeps_entry() {
        let (e, nat) = engine();
        let key = sa("8.8.8.8:50000");
        e.handle_outbound(&mut tcp("10.0.0.2:50000", "8.8.8.8:443", SYN));
        let first = nat.get(&key).unwrap();
        e.handle_outbound(&mut tcp("10.0.0.2:50000", "8.8.8.8:443", SYN));
        assert_eq!(nat.get(&key).unwrap().orig_dst, first.orig_dst);
        assert_eq!(e.stats().redirected, 1);
        assert_eq!(nat.len(), 1);
    }

    #[test]
    fn syn_after_closed_connection_starts_over() {
        let (e, nat) = engine();
        let key = sa("8.8.8.8:50000");
        e.handle_outbound(&mut tcp("10.0.0.2:50000", "8.8.8.8:443", SYN));
        drop(nat.claim(key).unwrap());
        assert!(matches!(
            nat.get(&key).unwrap().state,
            EntryState::Closed(_)
        ));
        e.handle_outbound(&mut tcp("10.0.0.2:50000", "8.8.8.8:443", SYN));
        assert_eq!(nat.get(&key).unwrap().state, EntryState::Pending);
        assert!(
            nat.claim(key).is_some(),
            "relay can serve the new connection"
        );
        assert_eq!(e.stats().redirected, 2);
    }

    #[test]
    fn port_reuse_with_new_destination_replaces_entry() {
        let (e, nat) = engine();
        let key = sa("8.8.8.8:50000");
        e.handle_outbound(&mut tcp("10.0.0.2:50000", "8.8.8.8:443", SYN));
        e.handle_outbound(&mut tcp("10.0.0.2:50000", "8.8.8.8:80", SYN));
        assert_eq!(nat.get(&key).unwrap().orig_dst, sa("8.8.8.8:80"));
        // Data for the old destination port is no longer translated.
        let mut stale = tcp("10.0.0.2:50000", "8.8.8.8:443", ACK);
        assert_eq!(e.handle_outbound(&mut stale), Verdict::Pass);
        assert_eq!(e.stats().redirected, 2);
    }

    #[test]
    fn blocked_and_direct_apps() {
        let (e, nat) = engine();
        let mut blocked = tcp("10.0.0.2:51000", "8.8.8.8:443", SYN);
        assert_eq!(e.handle_outbound(&mut blocked), Verdict::Drop);
        let mut direct = tcp("10.0.0.2:52000", "8.8.8.8:443", SYN);
        let original = direct.clone();
        assert_eq!(e.handle_outbound(&mut direct), Verdict::Pass);
        assert_eq!(direct, original, "pass-through packets are untouched");
        assert!(nat.is_empty());
        assert_eq!(e.stats().blocked_tcp, 1);
    }

    #[test]
    fn new_direct_flow_clears_stale_entry() {
        let (e, nat) = engine();
        nat.insert(
            sa("8.8.8.8:52000"),
            sa("8.8.8.8:443"),
            FlowDecision {
                pid: None,
                process: None,
                rule: None,
                action: ResolvedAction::Direct,
            },
        );
        e.handle_outbound(&mut tcp("10.0.0.2:52000", "8.8.8.8:443", SYN));
        assert!(nat.is_empty());
    }

    #[test]
    fn unrelated_packets_pass() {
        let (e, _) = engine();
        for mut pkt in [
            tcp("10.0.0.2:50000", "8.8.8.8:443", ACK), // pre-existing connection
            tcp("10.0.0.2:40000", "8.8.8.8:1234", SYN | ACK), // relay port, unknown peer
            tcp("10.0.0.2:50000", "192.168.0.1:443", SYN), // bypassed destination
            tcp("10.0.0.2:5000", "8.8.8.8:1080", SYN), // manager's own connection
            vec![0x45, 0, 0],                          // garbage
        ] {
            assert_eq!(e.handle_outbound(&mut pkt), Verdict::Pass);
        }
        let mut icmp = tcp("10.0.0.2:1", "8.8.8.8:2", 0);
        icmp[9] = 1;
        assert_eq!(e.handle_outbound(&mut icmp), Verdict::Pass);
    }

    #[test]
    fn udp_verdicts() {
        let (e, _) = engine();
        assert_eq!(
            e.handle_outbound(&mut udp("10.0.0.2:50000", "8.8.8.8:443")),
            Verdict::Drop
        );
        assert_eq!(
            e.handle_outbound(&mut udp("10.0.0.2:51000", "8.8.8.8:443")),
            Verdict::Drop
        );
        assert_eq!(
            e.handle_outbound(&mut udp("10.0.0.2:52000", "8.8.8.8:443")),
            Verdict::Pass
        );
        assert_eq!(
            e.handle_outbound(&mut udp("10.0.0.2:50000", "8.8.8.8:53")),
            Verdict::Pass
        );
        assert_eq!(e.stats().blocked_udp, 2);
    }

    #[test]
    fn claim_release_and_gc() {
        let table = Arc::new(NatTable::new(NatTimeouts {
            pending: Duration::from_secs(10),
            closed: Duration::from_secs(20),
        }));
        let d = FlowDecision {
            pid: Some(1),
            process: None,
            rule: None,
            action: ResolvedAction::Block,
        };
        let pending = sa("1.1.1.1:1");
        let active = sa("1.1.1.1:2");
        let closed = sa("1.1.1.1:3");
        for k in [pending, active, closed] {
            table.insert(k, sa("1.1.1.1:443"), d.clone());
        }
        assert!(table.claim(sa("9.9.9.9:9")).is_none(), "unknown key");

        let guard = table.claim(active).unwrap();
        assert_eq!(guard.entry().orig_dst, sa("1.1.1.1:443"));
        assert!(table.claim(active).is_none(), "cannot claim twice");
        assert_eq!(table.get(&active).unwrap().state, EntryState::Active);

        drop(table.claim(closed).unwrap());
        assert!(matches!(
            table.get(&closed).unwrap().state,
            EntryState::Closed(_)
        ));

        let now = Instant::now();
        assert_eq!(table.gc(now), 0);
        assert_eq!(
            table.gc(now + Duration::from_secs(15)),
            1,
            "pending expired"
        );
        assert!(table.get(&pending).is_none());
        assert_eq!(table.gc(now + Duration::from_secs(25)), 1, "closed expired");
        assert_eq!(
            table.gc(now + Duration::from_secs(1000)),
            0,
            "active never expires"
        );
        assert_eq!(table.len(), 1);

        drop(guard);
        assert!(matches!(
            table.get(&active).unwrap().state,
            EntryState::Closed(_)
        ));
        assert!(table.remove(&active).is_some());
        assert!(table.is_empty());

        table.insert(pending, sa("1.1.1.1:443"), d);
        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn release_after_removal_is_harmless() {
        let table = Arc::new(NatTable::default());
        let key = sa("1.1.1.1:1");
        table.insert(
            key,
            sa("1.1.1.1:443"),
            FlowDecision {
                pid: None,
                process: None,
                rule: None,
                action: ResolvedAction::Direct,
            },
        );
        let guard = table.claim(key).unwrap();
        table.clear();
        drop(guard);
        assert!(table.is_empty());
    }

    #[test]
    fn nat_key_unmaps_v4() {
        assert_eq!(
            nat_key("::ffff:1.2.3.4".parse().unwrap(), 5),
            sa("1.2.3.4:5")
        );
    }
}
