//! Minimal IPv4/IPv6 + TCP/UDP header parsing and in-place rewriting.
//!
//! Checksums are not touched here: the platform layer recalculates them before reinjection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const ACK: u8 = 0x10;
}

/// Header fields needed by the NAT engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    /// Offset of the TCP/UDP header.
    pub l4_offset: usize,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP flags, zero for UDP.
    pub tcp_flags: u8,
}

impl Packet {
    /// A connection-opening segment: SYN without ACK.
    pub fn is_syn(&self) -> bool {
        self.protocol == PROTO_TCP
            && self.tcp_flags & (tcp_flags::SYN | tcp_flags::ACK) == tcp_flags::SYN
    }

    pub fn is_ipv6(&self) -> bool {
        self.src.is_ipv6()
    }
}

/// Parses an IP packet carrying TCP or UDP. Returns `None` for anything else,
/// including truncated packets and non-first fragments.
pub fn parse(pkt: &[u8]) -> Option<Packet> {
    let (src, dst, protocol, l4_offset) = match pkt.first()? >> 4 {
        4 => parse_ipv4(pkt)?,
        6 => parse_ipv6(pkt)?,
        _ => return None,
    };
    let l4 = &pkt[l4_offset..];
    let (src_port, dst_port, tcp_flags) = match protocol {
        PROTO_TCP if l4.len() >= 20 => (be16(l4, 0), be16(l4, 2), l4[13]),
        PROTO_UDP if l4.len() >= 8 => (be16(l4, 0), be16(l4, 2), 0),
        _ => return None,
    };
    Some(Packet {
        src,
        dst,
        protocol,
        l4_offset,
        src_port,
        dst_port,
        tcp_flags,
    })
}

fn parse_ipv4(pkt: &[u8]) -> Option<(IpAddr, IpAddr, u8, usize)> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let fragment_offset = be16(pkt, 6) & 0x1fff;
    if fragment_offset != 0 {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some((src.into(), dst.into(), pkt[9], ihl))
}

fn parse_ipv6(pkt: &[u8]) -> Option<(IpAddr, IpAddr, u8, usize)> {
    if pkt.len() < 40 {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
    let mut next = pkt[6];
    let mut offset = 40;
    // Walk a bounded chain of extension headers.
    for _ in 0..8 {
        match next {
            PROTO_TCP | PROTO_UDP => return Some((src.into(), dst.into(), next, offset)),
            // Hop-by-hop, routing, destination options.
            0 | 43 | 60 => {
                let hdr = pkt.get(offset..offset + 2)?;
                next = hdr[0];
                offset += (usize::from(hdr[1]) + 1) * 8;
            }
            // Fragment header: only the first fragment carries the L4 header.
            44 => {
                let hdr = pkt.get(offset..offset + 8)?;
                if be16(hdr, 2) >> 3 != 0 {
                    return None;
                }
                next = hdr[0];
                offset += 8;
            }
            _ => return None,
        }
    }
    None
}

fn be16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn addr_ranges(p: &Packet) -> (std::ops::Range<usize>, std::ops::Range<usize>) {
    if p.is_ipv6() {
        (8..24, 24..40)
    } else {
        (12..16, 16..20)
    }
}

/// Swaps source and destination IP addresses.
pub fn swap_addresses(pkt: &mut [u8], p: &mut Packet) {
    let (src, dst) = addr_ranges(p);
    let len = src.len();
    let (head, tail) = pkt.split_at_mut(dst.start);
    head[src].swap_with_slice(&mut tail[..len]);
    std::mem::swap(&mut p.src, &mut p.dst);
}

pub fn set_src_port(pkt: &mut [u8], p: &mut Packet, port: u16) {
    pkt[p.l4_offset..p.l4_offset + 2].copy_from_slice(&port.to_be_bytes());
    p.src_port = port;
}

pub fn set_dst_port(pkt: &mut [u8], p: &mut Packet, port: u16) {
    pkt[p.l4_offset + 2..p.l4_offset + 4].copy_from_slice(&port.to_be_bytes());
    p.dst_port = port;
}

/// Test helpers to build packets.
#[cfg(any(test, feature = "test-util"))]
pub mod build {
    use super::*;

    fn l4(protocol: u8, src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut h = vec![0u8; if protocol == PROTO_TCP { 20 } else { 8 }];
        h[0..2].copy_from_slice(&src_port.to_be_bytes());
        h[2..4].copy_from_slice(&dst_port.to_be_bytes());
        if protocol == PROTO_TCP {
            h[12] = 5 << 4;
            h[13] = flags;
        } else {
            let len = h.len() as u16;
            h[4..6].copy_from_slice(&len.to_be_bytes());
        }
        h
    }

    /// Builds an IPv4 or IPv6 packet depending on the address family of `src`.
    pub fn packet(
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let payload = l4(protocol, src_port, dst_port, flags);
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let mut ip = vec![0u8; 20];
                ip[0] = 0x45;
                let total = (20 + payload.len()) as u16;
                ip[2..4].copy_from_slice(&total.to_be_bytes());
                ip[8] = 64;
                ip[9] = protocol;
                ip[12..16].copy_from_slice(&s.octets());
                ip[16..20].copy_from_slice(&d.octets());
                ip.extend(payload);
                ip
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let mut ip = vec![0u8; 40];
                ip[0] = 0x60;
                ip[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
                ip[6] = protocol;
                ip[7] = 64;
                ip[8..24].copy_from_slice(&s.octets());
                ip[24..40].copy_from_slice(&d.octets());
                ip.extend(payload);
                ip
            }
            _ => panic!("mixed address families"),
        }
    }

    pub fn tcp(src: &str, dst: &str, flags: u8) -> Vec<u8> {
        let src: std::net::SocketAddr = src.parse().unwrap();
        let dst: std::net::SocketAddr = dst.parse().unwrap();
        packet(PROTO_TCP, src.ip(), src.port(), dst.ip(), dst.port(), flags)
    }

    pub fn udp(src: &str, dst: &str) -> Vec<u8> {
        let src: std::net::SocketAddr = src.parse().unwrap();
        let dst: std::net::SocketAddr = dst.parse().unwrap();
        packet(PROTO_UDP, src.ip(), src.port(), dst.ip(), dst.port(), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::tcp_flags::*;
    use super::*;

    #[test]
    fn parses_ipv4_tcp() {
        let pkt = tcp("10.0.0.2:50000", "93.184.216.34:443", SYN);
        let p = parse(&pkt).unwrap();
        assert_eq!(p.src, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(p.dst, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(
            (p.src_port, p.dst_port, p.protocol, p.l4_offset),
            (50000, 443, PROTO_TCP, 20)
        );
        assert!(p.is_syn());
        assert!(!p.is_ipv6());
    }

    #[test]
    fn parses_ipv6_udp() {
        let pkt = udp("[2001:db8::1]:5353", "[2001:db8::2]:53");
        let p = parse(&pkt).unwrap();
        assert!(p.is_ipv6());
        assert_eq!(
            (p.src_port, p.dst_port, p.protocol, p.l4_offset),
            (5353, 53, PROTO_UDP, 40)
        );
        assert!(!p.is_syn());
    }

    #[test]
    fn syn_detection() {
        for (flags, syn) in [
            (SYN, true),
            (SYN | ACK, false),
            (ACK, false),
            (FIN | ACK, false),
            (RST, false),
        ] {
            let p = parse(&tcp("1.1.1.1:1", "2.2.2.2:2", flags)).unwrap();
            assert_eq!(p.is_syn(), syn, "flags {flags:#x}");
        }
    }

    #[test]
    fn ipv4_options_are_skipped() {
        let mut pkt = tcp("1.1.1.1:1000", "2.2.2.2:2000", SYN);
        // Insert 4 bytes of options (IHL = 6).
        pkt[0] = 0x46;
        pkt.splice(20..20, [1, 1, 1, 0]);
        let p = parse(&pkt).unwrap();
        assert_eq!((p.l4_offset, p.src_port, p.dst_port), (24, 1000, 2000));
    }

    #[test]
    fn ipv6_extension_headers_are_walked() {
        let mut pkt = tcp("[::1]:1000", "[::2]:2000", SYN);
        pkt[6] = 0; // hop-by-hop
        // Hop-by-hop (next = destination options), 8 bytes.
        let hbh = [60, 0, 0, 0, 0, 0, 0, 0];
        // Destination options (next = fragment), 8 bytes.
        let dst_opts = [44, 0, 0, 0, 0, 0, 0, 0];
        // First fragment (offset 0, next = TCP).
        let frag = [PROTO_TCP, 0, 0, 1, 0, 0, 0, 7];
        let ext: Vec<u8> = [hbh, dst_opts, frag].concat();
        pkt.splice(40..40, ext);
        let p = parse(&pkt).unwrap();
        assert_eq!((p.l4_offset, p.src_port, p.dst_port), (64, 1000, 2000));
    }

    #[test]
    fn rejects_unsupported_and_broken_packets() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x50; 40]).is_none(), "IP version 5");
        let pkt = tcp("1.1.1.1:1", "2.2.2.2:2", SYN);
        assert!(parse(&pkt[..19]).is_none(), "short IPv4 header");
        assert!(parse(&pkt[..30]).is_none(), "short TCP header");
        let mut bad_ihl = pkt.clone();
        bad_ihl[0] = 0x44;
        assert!(parse(&bad_ihl).is_none());
        let mut huge_ihl = pkt.clone();
        huge_ihl[0] = 0x4f;
        assert!(parse(&huge_ihl[..40]).is_none());

        let mut fragment = pkt.clone();
        fragment[7] = 1; // fragment offset != 0
        assert!(parse(&fragment).is_none());
        let mut first_fragment = pkt.clone();
        first_fragment[6] = 0x20; // MF flag only
        assert!(parse(&first_fragment).is_some());

        let mut icmp = pkt.clone();
        icmp[9] = 1;
        assert!(parse(&icmp).is_none());

        let v6 = tcp("[::1]:1", "[::2]:2", SYN);
        assert!(parse(&v6[..39]).is_none());
        let mut v6_icmp = v6.clone();
        v6_icmp[6] = 58;
        assert!(parse(&v6_icmp).is_none());
        let mut v6_trunc_ext = v6.clone();
        v6_trunc_ext[6] = 0;
        assert!(parse(&v6_trunc_ext[..41]).is_none());
        let mut v6_frag = v6.clone();
        v6_frag[6] = 44;
        v6_frag.splice(40..40, [PROTO_TCP, 0, 0, 8, 0, 0, 0, 1]);
        assert!(parse(&v6_frag).is_none(), "non-first IPv6 fragment");
        let mut v6_loop = v6.clone();
        v6_loop[6] = 60;
        v6_loop.splice(40..40, [60u8, 0, 0, 0, 0, 0, 0, 0].repeat(9));
        assert!(parse(&v6_loop).is_none(), "too many extension headers");
    }

    #[test]
    fn rewrites_v4() {
        let mut pkt = tcp("10.0.0.2:50000", "8.8.8.8:443", SYN);
        let mut p = parse(&pkt).unwrap();
        swap_addresses(&mut pkt, &mut p);
        set_dst_port(&mut pkt, &mut p, 34567);
        set_src_port(&mut pkt, &mut p, 50001);
        assert_eq!(parse(&pkt).unwrap(), p);
        assert_eq!(p.src, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(p.dst, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!((p.src_port, p.dst_port), (50001, 34567));
    }

    #[test]
    fn rewrites_v6() {
        let mut pkt = udp("[2001:db8::1]:1000", "[2001:db8::2]:2000");
        let mut p = parse(&pkt).unwrap();
        swap_addresses(&mut pkt, &mut p);
        let reparsed = parse(&pkt).unwrap();
        assert_eq!(reparsed, p);
        assert_eq!(reparsed.src, "2001:db8::2".parse::<IpAddr>().unwrap());
    }
}
