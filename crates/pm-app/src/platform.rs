//! OS-specific parts behind a trait, so the controller can be tested anywhere.

use std::net::SocketAddr;
use std::sync::Arc;

use pm_core::nat::Engine;
use pm_core::policy::SystemInfo;

/// A running packet interception.
pub trait Interception: Send {
    fn stop(self: Box<Self>);
}

pub trait Platform: Send + Sync {
    fn system_info(&self) -> Arc<dyn SystemInfo>;
    /// Starts diverting packets through `engine`.
    fn start(&self, engine: Arc<Engine>) -> anyhow::Result<Box<dyn Interception>>;
}

/// Knows nothing about the system: every lookup fails.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSystemInfo;

impl SystemInfo for NullSystemInfo {
    fn tcp_owner(&self, _: SocketAddr, _: SocketAddr) -> Option<u32> {
        None
    }
    fn udp_owner(&self, _: SocketAddr) -> Option<u32> {
        None
    }
    fn process_path(&self, _: u32) -> Option<String> {
        None
    }
}

/// Used on systems without interception support (development builds).
#[derive(Debug, Default)]
pub struct UnsupportedPlatform;

impl Platform for UnsupportedPlatform {
    fn system_info(&self) -> Arc<dyn SystemInfo> {
        Arc::new(NullSystemInfo)
    }

    fn start(&self, _engine: Arc<Engine>) -> anyhow::Result<Box<dyn Interception>> {
        anyhow::bail!("перехват трафика поддерживается только в Windows")
    }
}

#[cfg(windows)]
pub use windows::WindowsPlatform;

#[cfg(windows)]
mod windows {
    use super::*;
    use std::path::PathBuf;

    use parking_lot::Mutex;
    use pm_windows::divert::WinDivert;
    use pm_windows::interceptor::Interceptor;
    use pm_windows::system::WinSystemInfo;
    use tracing::warn;

    pub struct WindowsPlatform {
        windivert_dir: PathBuf,
        lib: Mutex<Option<Arc<WinDivert>>>,
    }

    impl WindowsPlatform {
        pub fn new(windivert_dir: PathBuf) -> Self {
            Self {
                windivert_dir,
                lib: Mutex::new(None),
            }
        }

        fn lib(&self) -> anyhow::Result<Arc<WinDivert>> {
            let mut lib = self.lib.lock();
            if let Some(lib) = lib.as_ref() {
                return Ok(lib.clone());
            }
            let loaded = WinDivert::load(&self.windivert_dir)
                .map_err(|e| anyhow::anyhow!("не удалось загрузить WinDivert: {e}"))?;
            *lib = Some(loaded.clone());
            Ok(loaded)
        }
    }

    impl Interception for Interceptor {
        fn stop(self: Box<Self>) {
            Interceptor::stop(*self);
        }
    }

    impl Platform for WindowsPlatform {
        fn system_info(&self) -> Arc<dyn SystemInfo> {
            Arc::new(WinSystemInfo)
        }

        fn start(&self, engine: Arc<Engine>) -> anyhow::Result<Box<dyn Interception>> {
            let lib = self.lib()?;
            match std::env::current_exe() {
                Ok(exe) => {
                    if let Err(e) = pm_windows::firewall::ensure_rule(&exe) {
                        warn!(error = %e, "could not add the firewall rule; the relay may be blocked");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "cannot determine executable path for the firewall rule")
                }
            }
            Ok(Box::new(Interceptor::start(&lib, engine)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pm_core::nat::NatTable;
    use pm_core::policy::Policy;
    use pm_core::rules::RuleSet;

    #[test]
    fn unsupported_platform() {
        let p = UnsupportedPlatform;
        let sys = p.system_info();
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        assert_eq!(sys.tcp_owner(a, a), None);
        assert_eq!(sys.udp_owner(a), None);
        assert_eq!(sys.process_path(1), None);
        let policy = Arc::new(Policy::new(sys, RuleSet::default(), 1));
        let engine = Arc::new(Engine::new(1, Arc::new(NatTable::default()), policy));
        assert!(p.start(engine).is_err());
    }
}
