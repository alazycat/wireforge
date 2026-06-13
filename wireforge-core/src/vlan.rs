//! IEEE 802.1Q / 802.1ad VLAN tag parser.

use alloc::vec;
use alloc::vec::Vec;

use crate::types::EtherType;
use crate::util::read_u16be;

/// Length of a single VLAN tag header (TPID + TCI).
pub const VLAN_HEADER_LEN: usize = 4;

/// Maximum number of VLAN tags to parse before stopping (prevents loops).
const MAX_VLAN_DEPTH: usize = 2;

/// Zero-copy 802.1Q VLAN tag parser.
///
/// Holds a reference to the underlying byte slice starting at the VLAN tag.
#[derive(Debug, Clone)]
pub struct VlanPacket<'a> {
    buf: &'a [u8],
}

impl<'a> VlanPacket<'a> {
    /// Attempt to parse a VLAN tag from raw bytes.
    ///
    /// Returns `None` if `buf` is shorter than [`VLAN_HEADER_LEN`] (4 bytes).
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < VLAN_HEADER_LEN {
            return None;
        }
        Some(Self { buf })
    }

    /// Priority Code Point (3 bits).
    #[inline]
    pub fn pcp(&self) -> u8 {
        self.buf[0] >> 5
    }

    /// Drop Eligible Indicator (1 bit).
    #[inline]
    pub fn dei(&self) -> bool {
        self.buf[0] & 0x10 != 0
    }

    /// VLAN Identifier (12 bits).
    #[inline]
    pub fn vid(&self) -> u16 {
        read_u16be(&self.buf[..2]) & 0x0FFF
    }

    /// The TPID / encapsulating EtherType.
    #[inline]
    pub fn tpid(&self) -> EtherType {
        EtherType::Unknown(read_u16be(&self.buf[..2]) & 0xFFFF)
    }

    /// The inner EtherType (next protocol after the VLAN tag).
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        EtherType::from(read_u16be(&self.buf[2..4]))
    }

    /// Raw inner ethertype value.
    #[inline]
    pub fn raw_ethertype(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }

    /// Data following this VLAN tag (may be another VLAN tag or actual payload).
    #[inline]
    pub fn inner(&self) -> &'a [u8] {
        &self.buf[VLAN_HEADER_LEN..]
    }
}

/// Parse a chain of 802.1Q / 802.1ad VLAN tags.
///
/// Returns the list of VLAN layers, the final EtherType, and the remaining
/// payload after all VLAN tags. Stops after [`MAX_VLAN_DEPTH`] tags.
pub fn parse_vlan_chain(buf: &[u8]) -> Option<(Vec<VlanPacket<'_>>, EtherType, &[u8])> {
    let mut tags = Vec::new();
    let mut remaining = buf;

    for _ in 0..MAX_VLAN_DEPTH {
        let vlan = VlanPacket::new(remaining)?;
        let inner_et = vlan.raw_ethertype();
        tags.push(vlan);
        remaining = &remaining[VLAN_HEADER_LEN..];

        // Stop if the next protocol is not another VLAN tag
        if inner_et != 0x8100 && inner_et != 0x88A8 {
            return Some((tags, EtherType::from(inner_et), remaining));
        }
    }
    // Hit max depth — return whatever we have
    if tags.is_empty() {
        None
    } else {
        let last_et = tags.last().unwrap().raw_ethertype();
        Some((tags, EtherType::from(last_et), remaining))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_vlan_tag() {
        // TPID=0x8100, PCP=3, DEI=1, VID=100, inner EtherType=0x0800
        let data = [
            0x60 | 0x10 | 0x00, 0x64, // PCP=3, DEI=1, VID=100
            0x08, 0x00, // IPv4
        ];
        let vlan = VlanPacket::new(&data).unwrap();
        assert_eq!(vlan.pcp(), 3);
        assert!(vlan.dei());
        assert_eq!(vlan.vid(), 100);
        assert_eq!(vlan.ethertype(), EtherType::Ipv4);
    }

    #[test]
    fn parse_vlan_tag_no_dei() {
        let data = [
            0x20, 0x0A, // PCP=1, DEI=0, VID=10
            0x08, 0x06, // ARP
        ];
        let vlan = VlanPacket::new(&data).unwrap();
        assert_eq!(vlan.pcp(), 1);
        assert!(!vlan.dei());
        assert_eq!(vlan.vid(), 10);
        assert_eq!(vlan.ethertype(), EtherType::Arp);
    }

    #[test]
    fn vlan_too_short() {
        assert!(VlanPacket::new(&[]).is_none());
        assert!(VlanPacket::new(&[0u8; 3]).is_none());
    }

    #[test]
    fn vlan_chain_single() {
        // 802.1Q tag → IPv4
        let data = [
            0x00, 0x64, // VID=100
            0x08, 0x00, // EtherType = IPv4
            0x45, // payload
        ];
        let (tags, final_et, payload) = parse_vlan_chain(&data).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].vid(), 100);
        assert_eq!(final_et, EtherType::Ipv4);
        assert_eq!(payload, &[0x45]);
    }
}
