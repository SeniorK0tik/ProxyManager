//! `WINDIVERT_ADDRESS` from WinDivert 2.x.
//!
//! ```c
//! typedef struct {
//!     INT64  Timestamp;
//!     UINT32 Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1,
//!            IPv6:1, IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:8;
//!     UINT32 Reserved2;
//!     union { WINDIVERT_DATA_NETWORK Network; ...; UINT8 Reserved3[64]; };
//! } WINDIVERT_ADDRESS;
//! ```
//! MSVC allocates bit fields starting from the least significant bit.

const SNIFFED: u32 = 1 << 16;
const OUTBOUND: u32 = 1 << 17;
const LOOPBACK: u32 = 1 << 18;
const IMPOSTOR: u32 = 1 << 19;
const IPV6: u32 = 1 << 20;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    bits: u32,
    reserved2: u32,
    data: [u8; 64],
}

const _: () = assert!(size_of::<WinDivertAddress>() == 80);

impl Default for WinDivertAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            bits: 0,
            reserved2: 0,
            data: [0; 64],
        }
    }
}

impl std::fmt::Debug for WinDivertAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinDivertAddress")
            .field("layer", &self.layer())
            .field("outbound", &self.outbound())
            .field("loopback", &self.loopback())
            .field("impostor", &self.impostor())
            .field("ipv6", &self.ipv6())
            .field("if_idx", &self.if_idx())
            .finish()
    }
}

impl WinDivertAddress {
    fn flag(&self, mask: u32) -> bool {
        self.bits & mask != 0
    }

    fn set_flag(&mut self, mask: u32, value: bool) {
        if value {
            self.bits |= mask;
        } else {
            self.bits &= !mask;
        }
    }

    pub fn layer(&self) -> u8 {
        (self.bits & 0xff) as u8
    }

    pub fn event(&self) -> u8 {
        ((self.bits >> 8) & 0xff) as u8
    }

    pub fn sniffed(&self) -> bool {
        self.flag(SNIFFED)
    }

    pub fn outbound(&self) -> bool {
        self.flag(OUTBOUND)
    }

    pub fn set_outbound(&mut self, value: bool) {
        self.set_flag(OUTBOUND, value);
    }

    pub fn loopback(&self) -> bool {
        self.flag(LOOPBACK)
    }

    pub fn impostor(&self) -> bool {
        self.flag(IMPOSTOR)
    }

    pub fn ipv6(&self) -> bool {
        self.flag(IPV6)
    }

    /// Network layer: interface index.
    pub fn if_idx(&self) -> u32 {
        u32::from_ne_bytes(self.data[0..4].try_into().unwrap())
    }

    /// Network layer: sub-interface index.
    pub fn sub_if_idx(&self) -> u32 {
        u32::from_ne_bytes(self.data[4..8].try_into().unwrap())
    }

    #[cfg(test)]
    fn from_raw(bits: u32, if_idx: u32) -> Self {
        let mut a = Self {
            bits,
            ..Self::default()
        };
        a.data[0..4].copy_from_slice(&if_idx.to_ne_bytes());
        a.data[4..8].copy_from_slice(&7u32.to_ne_bytes());
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitfields() {
        // Layer 0 (network), event 0, outbound + IPv6 + IP/TCP checksum flags.
        let mut a = WinDivertAddress::from_raw(OUTBOUND | IPV6 | (1 << 21) | (1 << 22), 12);
        assert_eq!(a.layer(), 0);
        assert_eq!(a.event(), 0);
        assert!(a.outbound());
        assert!(a.ipv6());
        assert!(!a.loopback());
        assert!(!a.impostor());
        assert!(!a.sniffed());
        assert_eq!(a.if_idx(), 12);
        assert_eq!(a.sub_if_idx(), 7);

        a.set_outbound(false);
        assert!(!a.outbound());
        assert!(a.ipv6(), "other bits are preserved");
        a.set_outbound(true);
        assert!(a.outbound());

        let b = WinDivertAddress::from_raw(3 | (2 << 8) | SNIFFED | LOOPBACK | IMPOSTOR, 0);
        assert_eq!((b.layer(), b.event()), (3, 2));
        assert!(b.sniffed() && b.loopback() && b.impostor());
        assert!(format!("{b:?}").contains("loopback: true"));
    }
}
