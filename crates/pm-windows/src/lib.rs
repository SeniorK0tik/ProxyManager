//! Windows integration for Proxy Manager.
//!
//! * [`tables`] — connection owner lookup (TCP/UDP tables).
//! * [`address`] / `divert` — WinDivert binding (loaded from `WinDivert.dll` at runtime).
//! * `interceptor` — the packet loop feeding [`pm_core::nat::Engine`].
//! * [`firewall`] / `elevation` — environment preparation.
//!
//! Platform-independent parts are compiled everywhere so they can be unit tested on any OS.

pub mod address;
pub mod autorun;
pub mod errors;
pub mod firewall;
pub mod tables;

#[cfg(windows)]
pub mod divert;
#[cfg(windows)]
pub mod elevation;
#[cfg(windows)]
pub mod interceptor;
#[cfg(windows)]
pub mod system;
