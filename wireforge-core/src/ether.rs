//! Ethernet II frame parser and builder.

use alloc::vec::Vec;

use crate::types::EtherType;
use crate::util::{read_u16be, write_u16be, PacketBuilder};

/// Minimum Ethernet II header length (dst MAC + src MAC + ethertype).
pub const ETHER_HEADER_LEN: usize = 14;

/// Zero-copy Ethernet II frame parser.
///
/// Holds a reference to the underlying byte slice. All field accessors
/// are inline offset reads — no allocation.
#[derive(Debug, Clone)]
pub struct EthernetPacket<'a> {
    buf: &'a [u8],
}

impl<'a> EthernetPacket<'a> {
    crate::parser_new!(ETHER_HEADER_LEN);

    /// Raw bytes backing this frame.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] { self.buf }

    /// Destination MAC address.
    #[inline]
    pub fn dst_mac(&self) -> [u8; 6] {
        self.buf[..6].try_into().unwrap()
    }

    /// Source MAC address.
    #[inline]
    pub fn src_mac(&self) -> [u8; 6] {
        self.buf[6..12].try_into().unwrap()
    }

    /// EtherType field.
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        EtherType::from(read_u16be(&self.buf[12..14]))
    }

    /// Raw ethertype value.
    #[inline]
    pub fn raw_ethertype(&self) -> u16 {
        read_u16be(&self.buf[12..14])
    }

    /// Payload following the Ethernet header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[ETHER_HEADER_LEN..]
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing Ethernet II frames.
#[derive(Debug, Clone)]
pub struct EthernetPacketBuilder {
    buf: [u8; ETHER_HEADER_LEN],
    payload: Option<Vec<u8>>,
}

impl Default for EthernetPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EthernetPacketBuilder {
    pub fn new() -> Self {
        Self {
            buf: [0u8; ETHER_HEADER_LEN],
            payload: None,
        }
    }

    pub fn dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.buf[..6].copy_from_slice(&mac);
        self
    }

    pub fn src_mac(mut self, mac: [u8; 6]) -> Self {
        self.buf[6..12].copy_from_slice(&mac);
        self
    }

    pub fn ethertype(mut self, et: EtherType) -> Self {
        write_u16be(&mut self.buf[12..14], et.into());
        self
    }

    pub fn raw_ethertype(mut self, et: u16) -> Self {
        write_u16be(&mut self.buf[12..14], et);
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }

    /// Assemble the complete Ethernet frame.
    pub fn build(self) -> Vec<u8> {
        <Self as PacketBuilder>::build(self)
    }
}

impl PacketBuilder for EthernetPacketBuilder {
    type Output = Vec<u8>;

    fn build(self) -> Vec<u8> {
        let mut frame = self.buf.to_vec();
        if let Some(ref p) = self.payload {
            frame.extend_from_slice(p);
        }
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real Ethernet frame: IPv4 packet
    const SAMPLE_FRAME: &[u8] = &[
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // dst
        0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, // src
        0x08, 0x00, // ethertype (IPv4)
        0x45, // ... payload
    ];

    #[test]
    fn parse_valid_frame() {
        let pkt = EthernetPacket::new(SAMPLE_FRAME).unwrap();
        assert_eq!(pkt.dst_mac(), [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        assert_eq!(pkt.src_mac(), [0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F]);
        assert_eq!(pkt.ethertype(), EtherType::Ipv4);
    }

    #[test]
    fn parse_too_short() {
        assert!(EthernetPacket::new(&[0u8; 13]).is_none());
        assert!(EthernetPacket::new(&[]).is_none());
    }

    #[test]
    fn parse_minimum_frame() {
        let pkt = EthernetPacket::new(&[0u8; 14]).unwrap();
        assert_eq!(pkt.ethertype(), EtherType::Unknown(0));
        assert_eq!(pkt.payload().len(), 0);
    }

    #[test]
    fn payload_slice() {
        let pkt = EthernetPacket::new(SAMPLE_FRAME).unwrap();
        assert_eq!(pkt.payload(), &[0x45]);
    }

    #[test]
    fn build_and_parse_roundtrip() {
        let frame = EthernetPacketBuilder::new()
            .dst_mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
            .src_mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
            .ethertype(EtherType::Arp)
            .payload(&[0x01, 0x02, 0x03])
            .build();

        let pkt = EthernetPacket::new(&frame).unwrap();
        assert_eq!(pkt.dst_mac(), [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(pkt.src_mac(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(pkt.ethertype(), EtherType::Arp);
        assert_eq!(pkt.payload(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn ethertype_arp() {
        let frame = [
            0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // broadcast
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x06, // ARP
        ];
        let pkt = EthernetPacket::new(&frame).unwrap();
        assert_eq!(pkt.ethertype(), EtherType::Arp);
    }
}
