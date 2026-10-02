//! Test doubles shared by unit tests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use pm_core::nat::Engine;
use pm_core::policy::SystemInfo;

use crate::platform::{Interception, Platform};

/// Every connection belongs to PID 4242, `C:\apps\app.exe`.
pub struct FakeSys;

impl SystemInfo for FakeSys {
    fn tcp_owner(&self, _: SocketAddr, _: SocketAddr) -> Option<u32> {
        Some(4242)
    }
    fn udp_owner(&self, _: SocketAddr) -> Option<u32> {
        Some(4242)
    }
    fn process_path(&self, _: u32) -> Option<String> {
        Some("C:\\apps\\app.exe".into())
    }
}

pub struct FakeInterception(pub Arc<AtomicBool>);

impl Interception for FakeInterception {
    fn stop(self: Box<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Records the engine it was started with; can be told to fail.
#[derive(Default)]
pub struct FakePlatform {
    pub engine: Mutex<Option<Arc<Engine>>>,
    pub stopped: Arc<AtomicBool>,
    pub fail: bool,
}

impl Platform for FakePlatform {
    fn system_info(&self) -> Arc<dyn SystemInfo> {
        Arc::new(FakeSys)
    }

    fn start(&self, engine: Arc<Engine>) -> anyhow::Result<Box<dyn Interception>> {
        if self.fail {
            anyhow::bail!("boom");
        }
        *self.engine.lock() = Some(engine);
        Ok(Box::new(FakeInterception(self.stopped.clone())))
    }
}
