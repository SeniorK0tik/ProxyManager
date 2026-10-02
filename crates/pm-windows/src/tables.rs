//! Connection owner lookup via `GetExtendedTcpTable` / `GetExtendedUdpTable`.
//!
//! Parsing is platform independent (and unit tested); only fetching is Windows-specific.
//! Table layouts (all fields `DWORD` unless noted, addresses and ports in network order):
//! * `MIB_TCPROW_OWNER_PID`  — state, local addr, local port, remote addr, remote port, pid (24 bytes)
//! * `MIB_TCP6ROW_OWNER_PID` — local addr[16], scope, local port, remote addr[16], scope, remote port, state, pid (56 bytes)
//! * `MIB_UDPROW_OWNER_PID`  — local addr, local port, pid (12 bytes)
//! * `MIB_UDP6ROW_OWNER_PID` — local addr[16], scope, local port, pid (28 bytes)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use pm_core::rules::canonical_ip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u32,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpRow {
    pub local: SocketAddr,
    pub pid: u32,
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap())
}

fn port_at(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn v4_at(buf: &[u8], at: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        buf[at],
        buf[at + 1],
        buf[at + 2],
        buf[at + 3],
    ))
}

fn v6_at(buf: &[u8], at: usize) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&buf[at..at + 16]).unwrap(),
    ))
}

/// Iterates over complete rows of a `{ DWORD dwNumEntries; ROW table[]; }` buffer.
fn rows(buf: &[u8], row_size: usize) -> impl Iterator<Item = &[u8]> {
    let count = if buf.len() >= 4 {
        u32_at(buf, 0) as usize
    } else {
        0
    };
    let body = buf.get(4..).unwrap_or_default();
    body.chunks_exact(row_size).take(count)
}

pub fn parse_tcp4(buf: &[u8]) -> Vec<TcpRow> {
    rows(buf, 24)
        .map(|r| TcpRow {
            state: u32_at(r, 0),
            local: SocketAddr::new(v4_at(r, 4), port_at(r, 8)),
            remote: SocketAddr::new(v4_at(r, 12), port_at(r, 16)),
            pid: u32_at(r, 20),
        })
        .collect()
}

pub fn parse_tcp6(buf: &[u8]) -> Vec<TcpRow> {
    rows(buf, 56)
        .map(|r| TcpRow {
            local: SocketAddr::new(v6_at(r, 0), port_at(r, 20)),
            remote: SocketAddr::new(v6_at(r, 24), port_at(r, 44)),
            state: u32_at(r, 48),
            pid: u32_at(r, 52),
        })
        .collect()
}

pub fn parse_udp4(buf: &[u8]) -> Vec<UdpRow> {
    rows(buf, 12)
        .map(|r| UdpRow {
            local: SocketAddr::new(v4_at(r, 0), port_at(r, 4)),
            pid: u32_at(r, 8),
        })
        .collect()
}

pub fn parse_udp6(buf: &[u8]) -> Vec<UdpRow> {
    rows(buf, 28)
        .map(|r| UdpRow {
            local: SocketAddr::new(v6_at(r, 0), port_at(r, 20)),
            pid: u32_at(r, 24),
        })
        .collect()
}

fn ip_matches(row: IpAddr, packet: IpAddr) -> bool {
    let row = canonical_ip(row);
    row.is_unspecified() || row == canonical_ip(packet)
}

/// Finds the owner of a TCP connection. Prefers an exact 4-tuple match,
/// falls back to the local port (the row may list a wildcard local address).
pub fn find_tcp_owner(rows: &[TcpRow], local: SocketAddr, remote: SocketAddr) -> Option<u32> {
    let same_port = |r: &&TcpRow| r.local.port() == local.port();
    rows.iter()
        .filter(same_port)
        .find(|r| {
            ip_matches(r.local.ip(), local.ip())
                && r.remote.port() == remote.port()
                && canonical_ip(r.remote.ip()) == canonical_ip(remote.ip())
        })
        .or_else(|| {
            rows.iter()
                .filter(same_port)
                .find(|r| ip_matches(r.local.ip(), local.ip()))
        })
        .map(|r| r.pid)
}

/// Finds the owner of a UDP socket, preferring an exact local address over a wildcard bind.
pub fn find_udp_owner(rows: &[UdpRow], local: SocketAddr) -> Option<u32> {
    let candidates = rows.iter().filter(|r| r.local.port() == local.port());
    let mut wildcard = None;
    for r in candidates {
        if canonical_ip(r.local.ip()) == canonical_ip(local.ip()) {
            return Some(r.pid);
        }
        if r.local.ip().is_unspecified() && wildcard.is_none() {
            wildcard = Some(r.pid);
        }
    }
    wildcard
}

#[cfg(windows)]
mod os {
    use super::*;
    use std::io;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    /// Calls a `GetExtended*Table` function, growing the buffer as needed.
    /// The buffer is `u32`-aligned because the API writes `DWORD` structures into it.
    fn fetch(call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> io::Result<Vec<u8>> {
        let mut size: u32 = 16 * 1024;
        for _ in 0..8 {
            let mut buf = vec![0u32; (size as usize).div_ceil(4)];
            let mut len = size;
            match call(buf.as_mut_ptr().cast(), &mut len) {
                NO_ERROR => {
                    let bytes: Vec<u8> = buf
                        .iter()
                        .flat_map(|w| w.to_ne_bytes())
                        .take(len as usize)
                        .collect();
                    return Ok(bytes);
                }
                ERROR_INSUFFICIENT_BUFFER => size = len.max(size) + 4096,
                code => return Err(io::Error::from_raw_os_error(code as i32)),
            }
        }
        Err(io::Error::other("connection table keeps growing"))
    }

    pub fn tcp_rows(v6: bool) -> io::Result<Vec<TcpRow>> {
        let family = u32::from(if v6 { AF_INET6 } else { AF_INET });
        let buf = fetch(|ptr, len| unsafe {
            GetExtendedTcpTable(ptr, len, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        Ok(if v6 {
            parse_tcp6(&buf)
        } else {
            parse_tcp4(&buf)
        })
    }

    pub fn udp_rows(v6: bool) -> io::Result<Vec<UdpRow>> {
        let family = u32::from(if v6 { AF_INET6 } else { AF_INET });
        let buf = fetch(|ptr, len| unsafe {
            GetExtendedUdpTable(ptr, len, 0, family, UDP_TABLE_OWNER_PID, 0)
        })?;
        Ok(if v6 {
            parse_udp6(&buf)
        } else {
            parse_udp4(&buf)
        })
    }
}

#[cfg(windows)]
pub use os::{tcp_rows, udp_rows};

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn table(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = (rows.len() as u32).to_ne_bytes().to_vec();
        for r in rows {
            buf.extend_from_slice(r);
        }
        buf
    }

    fn port(p: u16) -> [u8; 4] {
        let b = p.to_be_bytes();
        [b[0], b[1], 0, 0]
    }

    fn tcp4_row(state: u32, local: SocketAddr, remote: SocketAddr, pid: u32) -> Vec<u8> {
        let ip = |a: SocketAddr| match a.ip() {
            IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        [
            state.to_ne_bytes(),
            ip(local),
            port(local.port()),
            ip(remote),
            port(remote.port()),
            pid.to_ne_bytes(),
        ]
        .concat()
    }

    fn v6_octets(a: SocketAddr) -> [u8; 16] {
        match a.ip() {
            IpAddr::V6(v6) => v6.octets(),
            _ => unreachable!(),
        }
    }

    fn tcp6_row(state: u32, local: SocketAddr, remote: SocketAddr, pid: u32) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&v6_octets(local));
        r.extend_from_slice(&0u32.to_ne_bytes());
        r.extend_from_slice(&port(local.port()));
        r.extend_from_slice(&v6_octets(remote));
        r.extend_from_slice(&0u32.to_ne_bytes());
        r.extend_from_slice(&port(remote.port()));
        r.extend_from_slice(&state.to_ne_bytes());
        r.extend_from_slice(&pid.to_ne_bytes());
        r
    }

    #[test]
    fn parses_tcp_tables() {
        let buf = table(&[
            tcp4_row(2, sa("0.0.0.0:135"), sa("0.0.0.0:0"), 4),
            tcp4_row(3, sa("192.168.1.5:50000"), sa("93.184.216.34:443"), 1234),
        ]);
        let rows = parse_tcp4(&buf);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[1],
            TcpRow {
                local: sa("192.168.1.5:50000"),
                remote: sa("93.184.216.34:443"),
                state: 3,
                pid: 1234
            }
        );

        let buf = table(&[tcp6_row(
            3,
            sa("[2001:db8::5]:50001"),
            sa("[2a00::1]:443"),
            77,
        )]);
        let rows = parse_tcp6(&buf);
        assert_eq!(
            rows,
            vec![TcpRow {
                local: sa("[2001:db8::5]:50001"),
                remote: sa("[2a00::1]:443"),
                state: 3,
                pid: 77
            }]
        );
    }

    #[test]
    fn parses_udp_tables() {
        let row4 = [[0u8, 0, 0, 0], port(5353), 99u32.to_ne_bytes()].concat();
        assert_eq!(
            parse_udp4(&table(&[row4])),
            vec![UdpRow {
                local: sa("0.0.0.0:5353"),
                pid: 99
            }]
        );

        let mut row6 = v6_octets(sa("[::1]:1")).to_vec();
        row6.extend_from_slice(&0u32.to_ne_bytes());
        row6.extend_from_slice(&port(443));
        row6.extend_from_slice(&5u32.to_ne_bytes());
        assert_eq!(
            parse_udp6(&table(&[row6])),
            vec![UdpRow {
                local: sa("[::1]:443"),
                pid: 5
            }]
        );
    }

    #[test]
    fn tolerates_short_buffers() {
        assert!(parse_tcp4(&[]).is_empty());
        assert!(parse_tcp4(&[1, 0]).is_empty());
        // Header claims 5 rows but only one is present.
        let mut buf = table(&[tcp4_row(1, sa("1.1.1.1:1"), sa("2.2.2.2:2"), 3)]);
        buf[0] = 5;
        assert_eq!(parse_tcp4(&buf).len(), 1);
        // Trailing partial row is ignored.
        buf.extend_from_slice(&[0; 10]);
        assert_eq!(parse_tcp4(&buf).len(), 1);
    }

    #[test]
    fn tcp_owner_lookup() {
        let rows = vec![
            TcpRow {
                local: sa("10.0.0.2:50000"),
                remote: sa("1.1.1.1:443"),
                state: 3,
                pid: 1,
            },
            TcpRow {
                local: sa("10.0.0.2:50000"),
                remote: sa("8.8.8.8:443"),
                state: 3,
                pid: 2,
            },
            TcpRow {
                local: sa("[::]:50001"),
                remote: sa("[::ffff:9.9.9.9]:80"),
                state: 3,
                pid: 3,
            },
        ];
        assert_eq!(
            find_tcp_owner(&rows, sa("10.0.0.2:50000"), sa("8.8.8.8:443")),
            Some(2)
        );
        assert_eq!(
            find_tcp_owner(&rows, sa("10.0.0.2:50000"), sa("4.4.4.4:443")),
            Some(1),
            "port-only fallback"
        );
        assert_eq!(
            find_tcp_owner(&rows, sa("10.0.0.2:50001"), sa("9.9.9.9:80")),
            Some(3),
            "dual-stack socket"
        );
        assert_eq!(
            find_tcp_owner(&rows, sa("10.0.0.3:50000"), sa("8.8.8.8:443")),
            None,
            "different local address"
        );
        assert_eq!(
            find_tcp_owner(&rows, sa("10.0.0.2:1"), sa("8.8.8.8:443")),
            None
        );
    }

    #[test]
    fn udp_owner_lookup() {
        let rows = vec![
            UdpRow {
                local: sa("0.0.0.0:5000"),
                pid: 1,
            },
            UdpRow {
                local: sa("10.0.0.2:5000"),
                pid: 2,
            },
            UdpRow {
                local: sa("[::]:6000"),
                pid: 3,
            },
            UdpRow {
                local: sa("[::ffff:10.0.0.2]:7000"),
                pid: 4,
            },
        ];
        assert_eq!(
            find_udp_owner(&rows, sa("10.0.0.2:5000")),
            Some(2),
            "exact beats wildcard"
        );
        assert_eq!(find_udp_owner(&rows, sa("10.0.0.9:5000")), Some(1));
        assert_eq!(find_udp_owner(&rows, sa("10.0.0.2:6000")), Some(3));
        assert_eq!(find_udp_owner(&rows, sa("10.0.0.2:7000")), Some(4));
        assert_eq!(find_udp_owner(&rows, sa("10.0.0.2:8000")), None);
    }

    #[cfg(windows)]
    #[test]
    fn finds_own_live_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let rows = tcp_rows(false).unwrap();
        let owner = find_tcp_owner(
            &rows,
            client.local_addr().unwrap(),
            client.peer_addr().unwrap(),
        );
        assert_eq!(owner, Some(std::process::id()));

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let rows = udp_rows(false).unwrap();
        assert_eq!(
            find_udp_owner(&rows, udp.local_addr().unwrap()),
            Some(std::process::id())
        );
        assert!(tcp_rows(true).is_ok());
        assert!(udp_rows(true).is_ok());
    }
}
