//! Packet loop: WinDivert -> [`Engine`] -> WinDivert.

use std::io;
use std::sync::Arc;
use std::thread::JoinHandle;

use pm_core::nat::{Engine, Verdict};
use tracing::{info, warn};

use crate::address::WinDivertAddress;
use crate::divert::{Handle, LAYER_NETWORK, WinDivert};
use crate::errors::explain_open_error;

/// Every outbound TCP/UDP packet that leaves the machine. Loopback traffic (including
/// the relay <-> upstream proxy leg when the proxy is local) is never touched.
pub const FILTER: &str = "outbound and !loopback and (tcp or udp)";

/// `WINDIVERT_MTU_MAX`.
const MAX_PACKET: usize = 40 + 0xFFFF;

/// `ERROR_NO_DATA`: the handle was shut down.
const ERROR_NO_DATA: i32 = 232;
/// `ERROR_OPERATION_ABORTED`.
const ERROR_OPERATION_ABORTED: i32 = 995;
/// `ERROR_INVALID_HANDLE`.
const ERROR_INVALID_HANDLE: i32 = 6;

/// A running interception loop.
pub struct Interceptor {
    handle: Arc<Handle>,
    worker: Option<JoinHandle<()>>,
}

impl Interceptor {
    /// Opens the WinDivert handle and starts the packet thread.
    ///
    /// A single thread keeps packets of a flow in order.
    pub fn start(lib: &Arc<WinDivert>, engine: Arc<Engine>) -> io::Result<Self> {
        let handle = Handle::open(lib, FILTER, LAYER_NETWORK, 0, 0).map_err(|e| {
            let code = e.raw_os_error().unwrap_or(0);
            io::Error::new(e.kind(), explain_open_error(code))
        })?;
        let handle = Arc::new(handle);
        let worker_handle = handle.clone();
        let worker = std::thread::Builder::new()
            .name("pm-divert".into())
            .spawn(move || packet_loop(&worker_handle, &engine))?;
        info!(filter = FILTER, "interception started");
        Ok(Self {
            handle,
            worker: Some(worker),
        })
    }

    /// Stops the loop and waits for the thread. Packets are no longer diverted afterwards.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.handle.shutdown();
            let _ = worker.join();
            info!("interception stopped");
        }
    }
}

impl Drop for Interceptor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn packet_loop(handle: &Handle, engine: &Engine) {
    let mut buf = vec![0u8; MAX_PACKET];
    let mut addr = WinDivertAddress::default();
    loop {
        let len = match handle.recv(&mut buf, &mut addr) {
            Ok(len) => len,
            Err(e) => match e.raw_os_error() {
                Some(ERROR_NO_DATA | ERROR_OPERATION_ABORTED | ERROR_INVALID_HANDLE) => return,
                _ => {
                    warn!(error = %e, "WinDivertRecv failed");
                    continue;
                }
            },
        };
        let pkt = &mut buf[..len];
        let verdict = engine.handle_outbound(pkt);
        let result = match verdict {
            Verdict::Pass => handle.send(pkt, &addr),
            Verdict::Drop => continue,
            Verdict::Inject { outbound } => {
                addr.set_outbound(outbound);
                handle.calc_checksums(pkt, &mut addr);
                handle.send(pkt, &addr)
            }
        };
        if let Err(e) = result {
            warn!(error = %e, ?verdict, "WinDivertSend failed");
        }
    }
}
