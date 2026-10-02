//! [`SystemInfo`] implementation backed by the Windows IP Helper and process APIs.

use std::net::SocketAddr;

use pm_core::policy::SystemInfo;
use tracing::debug;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::tables::{find_tcp_owner, find_udp_owner, tcp_rows, udp_rows};

#[derive(Debug, Default, Clone, Copy)]
pub struct WinSystemInfo;

impl SystemInfo for WinSystemInfo {
    fn tcp_owner(&self, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
        // An IPv4 packet may belong to a dual-stack IPv6 socket, so check both tables.
        let mut tables = vec![local.is_ipv6()];
        if local.is_ipv4() {
            tables.push(true);
        }
        tables.into_iter().find_map(|v6| match tcp_rows(v6) {
            Ok(rows) => find_tcp_owner(&rows, local, remote),
            Err(e) => {
                debug!(error = %e, "GetExtendedTcpTable failed");
                None
            }
        })
    }

    fn udp_owner(&self, local: SocketAddr) -> Option<u32> {
        let mut tables = vec![local.is_ipv6()];
        if local.is_ipv4() {
            tables.push(true);
        }
        tables.into_iter().find_map(|v6| match udp_rows(v6) {
            Ok(rows) => find_udp_owner(&rows, local),
            Err(e) => {
                debug!(error = %e, "GetExtendedUdpTable failed");
                None
            }
        })
    }

    fn process_path(&self, pid: u32) -> Option<String> {
        process_path(pid)
    }
}

/// Full image path of a process, `None` if it is gone or inaccessible.
pub fn process_path(pid: u32) -> Option<String> {
    match pid {
        0 => return None,
        4 => return Some("System".to_string()),
        _ => {}
    }
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_own_process() {
        let path = process_path(std::process::id()).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert!(
            path.eq_ignore_ascii_case(&exe.to_string_lossy()),
            "{path} vs {exe:?}"
        );
        assert_eq!(process_path(0), None);
        assert_eq!(process_path(4).as_deref(), Some("System"));
        assert_eq!(process_path(u32::MAX - 3), None);
    }

    #[test]
    fn owner_of_live_sockets() {
        let sys = WinSystemInfo;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let pid = sys.tcp_owner(client.local_addr().unwrap(), client.peer_addr().unwrap());
        assert_eq!(pid, Some(std::process::id()));

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            sys.udp_owner(udp.local_addr().unwrap()),
            Some(std::process::id())
        );
        assert!(sys.process_path(std::process::id()).is_some());
    }
}
