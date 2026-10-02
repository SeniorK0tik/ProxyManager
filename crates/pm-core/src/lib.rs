//! Platform-independent core of Proxy Manager.
//!
//! * [`config`] — user configuration (TOML).
//! * [`rules`] — compiled rule set matching executables to actions.
//! * [`policy`] — per-flow decisions using OS lookups ([`policy::SystemInfo`]).
//! * [`packet`] / [`nat`] — packet parsing and the redirect engine.
//! * [`proxy`] — SOCKS5 and HTTP CONNECT clients.
//! * [`relay`] — local listener tunnelling redirected connections.
//! * [`tracker`] / [`logbuf`] — statistics and logs for the UI.

pub mod config;
pub mod logbuf;
pub mod nat;
pub mod packet;
pub mod policy;
pub mod proxy;
pub mod relay;
pub mod rules;
pub mod tracker;

#[cfg(any(test, feature = "test-util"))]
pub mod testing;

pub use config::{Action, Config, ProxyKind, ProxyProfile, Rule};
