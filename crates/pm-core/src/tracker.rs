//! Live statistics about proxied connections, shown in the UI.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::Mutex;

/// Static description of a proxied connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnMeta {
    pub pid: Option<u32>,
    pub process: Option<Arc<str>>,
    pub rule: Option<Arc<str>>,
    pub proxy: Arc<str>,
    pub target: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnStatus {
    Connecting,
    Open,
    Closed,
    Failed(String),
}

impl ConnStatus {
    pub fn label(&self) -> &str {
        match self {
            ConnStatus::Connecting => "подключение",
            ConnStatus::Open => "открыто",
            ConnStatus::Closed => "закрыто",
            ConnStatus::Failed(_) => "ошибка",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnSnapshot {
    pub id: u64,
    pub meta: ConnMeta,
    pub status: ConnStatus,
    pub started: SystemTime,
    pub duration: Duration,
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrackerSnapshot {
    pub active: Vec<ConnSnapshot>,
    pub recent: Vec<ConnSnapshot>,
    pub total_connections: u64,
    pub failed_connections: u64,
    pub total_up: u64,
    pub total_down: u64,
}

struct Record {
    meta: ConnMeta,
    status: ConnStatus,
    started: SystemTime,
    started_at: Instant,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

impl Record {
    fn snapshot(&self, id: u64) -> ConnSnapshot {
        ConnSnapshot {
            id,
            meta: self.meta.clone(),
            status: self.status.clone(),
            started: self.started,
            duration: self.started_at.elapsed(),
            up: self.up.load(Ordering::Relaxed),
            down: self.down.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
struct Inner {
    active: HashMap<u64, Record>,
    recent: VecDeque<ConnSnapshot>,
}

/// Registry of active and recently finished connections.
pub struct Tracker {
    next_id: AtomicU64,
    inner: Mutex<Inner>,
    history: usize,
    total_connections: AtomicU64,
    failed_connections: AtomicU64,
    finished_up: AtomicU64,
    finished_down: AtomicU64,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new(500)
    }
}

impl Tracker {
    /// `history` is how many finished connections to keep.
    pub fn new(history: usize) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            inner: Mutex::default(),
            history,
            total_connections: AtomicU64::new(0),
            failed_connections: AtomicU64::new(0),
            finished_up: AtomicU64::new(0),
            finished_down: AtomicU64::new(0),
        }
    }

    /// Registers a new connection. The returned handle finishes it when dropped.
    pub fn open(self: &Arc<Self>, meta: ConnMeta) -> ConnHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().active.insert(
            id,
            Record {
                meta,
                status: ConnStatus::Connecting,
                started: SystemTime::now(),
                started_at: Instant::now(),
                up: up.clone(),
                down: down.clone(),
            },
        );
        ConnHandle {
            tracker: self.clone(),
            id,
            up,
            down,
        }
    }

    fn set_status(&self, id: u64, status: ConnStatus) {
        if let Some(r) = self.inner.lock().active.get_mut(&id) {
            r.status = status;
        }
    }

    fn finish(&self, id: u64) {
        let mut inner = self.inner.lock();
        let Some(mut record) = inner.active.remove(&id) else {
            return;
        };
        match record.status {
            ConnStatus::Failed(_) => {
                self.failed_connections.fetch_add(1, Ordering::Relaxed);
            }
            _ => record.status = ConnStatus::Closed,
        }
        let snap = record.snapshot(id);
        self.finished_up.fetch_add(snap.up, Ordering::Relaxed);
        self.finished_down.fetch_add(snap.down, Ordering::Relaxed);
        if self.history > 0 {
            if inner.recent.len() == self.history {
                inner.recent.pop_front();
            }
            inner.recent.push_back(snap);
        }
    }

    /// Active connections (sorted by id) and recent ones (newest first) plus totals.
    pub fn snapshot(&self) -> TrackerSnapshot {
        let inner = self.inner.lock();
        let mut active: Vec<ConnSnapshot> =
            inner.active.iter().map(|(&id, r)| r.snapshot(id)).collect();
        active.sort_by_key(|c| c.id);
        let live_up: u64 = active.iter().map(|c| c.up).sum();
        let live_down: u64 = active.iter().map(|c| c.down).sum();
        TrackerSnapshot {
            recent: inner.recent.iter().rev().cloned().collect(),
            active,
            total_connections: self.total_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            total_up: self.finished_up.load(Ordering::Relaxed) + live_up,
            total_down: self.finished_down.load(Ordering::Relaxed) + live_down,
        }
    }

    pub fn active_count(&self) -> usize {
        self.inner.lock().active.len()
    }

    /// Forgets finished connections.
    pub fn clear_history(&self) {
        self.inner.lock().recent.clear();
    }
}

/// Owned by the relay task serving the connection.
pub struct ConnHandle {
    tracker: Arc<Tracker>,
    id: u64,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

impl ConnHandle {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn established(&self) {
        self.tracker.set_status(self.id, ConnStatus::Open);
    }

    pub fn fail(&self, reason: impl Into<String>) {
        self.tracker
            .set_status(self.id, ConnStatus::Failed(reason.into()));
    }

    /// Counter for bytes sent by the application.
    pub fn up_counter(&self) -> Arc<AtomicU64> {
        self.up.clone()
    }

    /// Counter for bytes received by the application.
    pub fn down_counter(&self) -> Arc<AtomicU64> {
        self.down.clone()
    }
}

impl Drop for ConnHandle {
    fn drop(&mut self) {
        self.tracker.finish(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(port: u16) -> ConnMeta {
        ConnMeta {
            pid: Some(42),
            process: Some(Arc::from("C:\\app.exe")),
            rule: Some(Arc::from("r")),
            proxy: Arc::from("p"),
            target: SocketAddr::from(([1, 2, 3, 4], port)),
        }
    }

    #[test]
    fn lifecycle_and_totals() {
        let t = Arc::new(Tracker::new(10));
        let a = t.open(meta(1));
        let b = t.open(meta(2));
        assert_ne!(a.id(), b.id());
        assert_eq!(t.active_count(), 2);

        a.established();
        a.up_counter().fetch_add(100, Ordering::Relaxed);
        a.down_counter().fetch_add(1000, Ordering::Relaxed);
        b.fail("boom");

        let s = t.snapshot();
        assert_eq!(s.active.len(), 2);
        assert_eq!(s.active[0].status, ConnStatus::Open);
        assert_eq!(s.active[1].status, ConnStatus::Failed("boom".into()));
        assert_eq!((s.total_up, s.total_down), (100, 1000));
        assert_eq!(s.total_connections, 2);

        drop(a);
        drop(b);
        let s = t.snapshot();
        assert!(s.active.is_empty());
        assert_eq!(s.recent.len(), 2);
        assert_eq!(
            s.recent[0].status,
            ConnStatus::Failed("boom".into()),
            "newest first"
        );
        assert_eq!(s.recent[1].status, ConnStatus::Closed);
        assert_eq!(s.recent[1].up, 100);
        assert_eq!(
            (s.total_up, s.total_down),
            (100, 1000),
            "totals survive closing"
        );
        assert_eq!(s.failed_connections, 1);

        t.clear_history();
        assert!(t.snapshot().recent.is_empty());
    }

    #[test]
    fn history_is_bounded() {
        let t = Arc::new(Tracker::new(3));
        for port in 0..10 {
            drop(t.open(meta(port)));
        }
        let s = t.snapshot();
        assert_eq!(s.recent.len(), 3);
        assert_eq!(s.recent[0].meta.target.port(), 9);
        assert_eq!(s.total_connections, 10);

        let none = Arc::new(Tracker::new(0));
        drop(none.open(meta(1)));
        assert!(none.snapshot().recent.is_empty());
    }

    #[test]
    fn finish_and_status_on_unknown_ids_are_ignored() {
        let t = Tracker::default();
        t.set_status(99, ConnStatus::Open);
        t.finish(99);
        assert_eq!(t.snapshot(), TrackerSnapshot::default());
    }

    #[test]
    fn status_labels() {
        assert_eq!(ConnStatus::Connecting.label(), "подключение");
        assert_eq!(ConnStatus::Open.label(), "открыто");
        assert_eq!(ConnStatus::Closed.label(), "закрыто");
        assert_eq!(ConnStatus::Failed("x".into()).label(), "ошибка");
    }
}
