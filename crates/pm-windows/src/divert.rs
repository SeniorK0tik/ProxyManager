//! Thin binding to `WinDivert.dll` (2.x), loaded at runtime.
//!
//! Loading dynamically avoids link-time dependencies: the DLL and `WinDivert64.sys`
//! only have to sit next to the executable.

use std::ffi::{CString, c_char, c_void};
use std::io;
use std::path::Path;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

use crate::address::WinDivertAddress;

pub const DLL_NAME: &str = "WinDivert.dll";
pub const DRIVER_NAME: &str = "WinDivert64.sys";

/// `WINDIVERT_LAYER_NETWORK`.
pub const LAYER_NETWORK: i32 = 0;
/// `WINDIVERT_SHUTDOWN_BOTH`.
const SHUTDOWN_BOTH: i32 = 3;

type OpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> HANDLE;
type RecvFn =
    unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
type SendFn =
    unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const WinDivertAddress) -> i32;
type ShutdownFn = unsafe extern "C" fn(HANDLE, i32) -> i32;
type CloseFn = unsafe extern "C" fn(HANDLE) -> i32;
type ChecksumsFn = unsafe extern "C" fn(*mut c_void, u32, *mut WinDivertAddress, u64) -> i32;

/// Function table of a loaded `WinDivert.dll`.
pub struct WinDivert {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    calc_checksums: ChecksumsFn,
    _lib: libloading::Library,
}

impl WinDivert {
    /// Loads `WinDivert.dll` from `dir`.
    pub fn load(dir: &Path) -> io::Result<Arc<Self>> {
        let path = dir.join(DLL_NAME);
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("не найден {}", path.display()),
            ));
        }
        if !dir.join(DRIVER_NAME).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("не найден драйвер {}", dir.join(DRIVER_NAME).display()),
            ));
        }
        let lib = unsafe { libloading::Library::new(&path) }.map_err(io::Error::other)?;
        unsafe {
            Ok(Arc::new(Self {
                open: *lib
                    .get::<OpenFn>("WinDivertOpen")
                    .map_err(io::Error::other)?,
                recv: *lib
                    .get::<RecvFn>("WinDivertRecv")
                    .map_err(io::Error::other)?,
                send: *lib
                    .get::<SendFn>("WinDivertSend")
                    .map_err(io::Error::other)?,
                shutdown: *lib
                    .get::<ShutdownFn>("WinDivertShutdown")
                    .map_err(io::Error::other)?,
                close: *lib
                    .get::<CloseFn>("WinDivertClose")
                    .map_err(io::Error::other)?,
                calc_checksums: *lib
                    .get::<ChecksumsFn>("WinDivertHelperCalcChecksums")
                    .map_err(io::Error::other)?,
                _lib: lib,
            }))
        }
    }
}

/// An open WinDivert handle. Safe to use from several threads concurrently.
pub struct Handle {
    lib: Arc<WinDivert>,
    raw: HANDLE,
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    pub fn open(
        lib: &Arc<WinDivert>,
        filter: &str,
        layer: i32,
        priority: i16,
        flags: u64,
    ) -> io::Result<Self> {
        let filter =
            CString::new(filter).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let raw = unsafe { (lib.open)(filter.as_ptr(), layer, priority, flags) };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            lib: lib.clone(),
            raw,
        })
    }

    /// Blocks until a packet arrives. Fails with `ERROR_NO_DATA` after [`Handle::shutdown`].
    pub fn recv(&self, buf: &mut [u8], addr: &mut WinDivertAddress) -> io::Result<usize> {
        let mut len = 0u32;
        let ok = unsafe {
            (self.lib.recv)(
                self.raw,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut len,
                addr,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(len as usize)
    }

    pub fn send(&self, pkt: &[u8], addr: &WinDivertAddress) -> io::Result<usize> {
        let mut len = 0u32;
        let ok = unsafe {
            (self.lib.send)(
                self.raw,
                pkt.as_ptr().cast(),
                pkt.len() as u32,
                &mut len,
                addr,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(len as usize)
    }

    /// Recomputes IP/TCP/UDP checksums and updates the checksum flags in `addr`.
    pub fn calc_checksums(&self, pkt: &mut [u8], addr: &mut WinDivertAddress) {
        unsafe {
            (self.lib.calc_checksums)(pkt.as_mut_ptr().cast(), pkt.len() as u32, addr, 0);
        }
    }

    /// Wakes up blocked `recv` calls and stops queueing new packets.
    pub fn shutdown(&self) {
        unsafe {
            (self.lib.shutdown)(self.raw, SHUTDOWN_BOTH);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            (self.lib.close)(self.raw);
        }
    }
}
