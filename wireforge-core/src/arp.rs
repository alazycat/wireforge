//! ARP packet parser and builder (Ethernet/IPv4 hardware/protocol combination).

use alloc::vec;
use alloc::vec::Vec;

use crate::types::{ArpHardwareType, ArpOperation, EtherType};
use crate::util::{read_u16be, write_u16be, BuildError};

/// Minimum ARP packet length for Ethernet/IPv4 (28 bytes: 8-byte header + 2×6 MAC + 2×4 IP).
pub const ARP_HEADER_LEN: usize = 28;

/// Zero-copy ARP packet parser.
#[derive(Debug, Clone)]
pub struct ArpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    /// Attempt to parse an ARP packet. Returns `None` if `buf` is shorter than
    /// [`ARP_HEADER_LEN`].
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < ARP_HEADER_LEN {
            return None;
        }
        Some(Self { buf })
    }

    #[inline]
    pub fn hardware_type(&self) -> ArpHardwareType {
        ArpHardwareType::from(read_u16be(&self.buf[..2]))
    }

    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::from(read_u16be(&self.buf[2..4]))
    }

    #[inline]
    pub fn hw_addr_len(&self) -> u8 {
        self.buf[4]
    }

    #[inline]
    pub fn proto_addr_len(&self) -> u8 {
        self.buf[5]
    }

    #[inline]
    pub fn operation(&self) -> ArpOperation {
        ArpOperation::from(read_u16be(&self.buf[6..8]))
    }

    #[inline]
    pub fn sender_hw_addr(&self) -> &'a [u8] {
        let len = self.hw_addr_len() as usize;
        &self.buf[8..8 + len]
    }

    #[inline]
    pub fn sender_proto_addr(&self) -> &'a [u8] {
        let hw_len = self.hw_addr_len() as usize;
        let start = 8 + hw_len;
        let len = self.proto_addr_len() as usize;
        &self.buf[start..start + len]
    }

    #[inline]
    pub fn target_hw_addr(&self) -> &'a [u8] {
        let hw_len = self.hw_addr_len() as usize;
        let proto_len = self.proto_addr_len() as usize;
        let start = 8 + hw_len + proto_len;
        &self.buf[start..start + hw_len]
    }

    #[inline]
    pub fn target_proto_addr(&self) -> &'a [u8] {
        let hw_len = self.hw_addr_len() as usize;
        let proto_len = self.proto_addr_len() as usize;
        let start = 8 + hw_len + proto_len + hw_len;
        &self.buf[start..start + proto_len]
    }

    #[inline]
    pub fn is_request(&self) -> bool {
        self.operation() == ArpOperation::Request
    }

    #[inline]
    pub fn is_reply(&self) -> bool {
        self.operation() == ArpOperation::Reply
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for ARP packets (Ethernet/IPv4).
#[derive(Debug, Clone)]
pub struct ArpPacketBuilder {
    hw_type: u16,
    proto_type: u16,
    hw_addr_len: u8,
    proto_addr_len: u8,
    operation: u16,
    sender_hw: Vec<u8>,
    sender_proto: Vec<u8>,
    target_hw: Vec<u8>,
    target_proto: Vec<u8>,
}

impl Default for ArpPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpPacketBuilder {
    /// Create a new builder with Ethernet/IPv4 defaults.
    pub fn new() -> Self {
        Self {
            hw_type: 1, // Ethernet
            proto_type: 0x0800, // IPv4
            hw_addr_len: 6,
            proto_addr_len: 4,
            operation: 1, // Request
            sender_hw: vec![0u8; 6],
            sender_proto: vec![0u8; 4],
            target_hw: vec![0u8; 6],
            target_proto: vec![0u8; 4],
        }
    }

    pub fn hardware_type(mut self, ht: ArpHardwareType) -> Self {
        self.hw_type = ht.into();
        self
    }

    pub fn protocol_type(mut self, pt: EtherType) -> Self {
        self.proto_type = pt.into();
        self
    }

    pub fn operation(mut self, op: ArpOperation) -> Self {
        self.operation = op.into();
        self
    }

    pub fn sender_hw_addr(mut self, addr: &[u8]) -> Result<Self, BuildError> {
        if addr.len() as u8 != self.hw_addr_len {
            return Err(BuildError::InvalidField {
                field: "sender_hw_addr",
                reason: "length mismatch",
            });
        }
        self.sender_hw = addr.to_vec();
        Ok(self)
    }

    pub fn sender_proto_addr(mut self, addr: &[u8]) -> Result<Self, BuildError> {
        if addr.len() as u8 != self.proto_addr_len {
            return Err(BuildError::InvalidField {
                field: "sender_proto_addr",
                reason: "length mismatch",
            });
        }
        self.sender_proto = addr.to_vec();
        Ok(self)
    }

    pub fn target_hw_addr(mut self, addr: &[u8]) -> Result<Self, BuildError> {
        if addr.len() as u8 != self.hw_addr_len {
            return Err(BuildError::InvalidField {
                field: "target_hw_addr",
                reason: "length mismatch",
            });
        }
        self.target_hw = addr.to_vec();
        Ok(self)
    }

    pub fn target_proto_addr(mut self, addr: &[u8]) -> Result<Self, BuildError> {
        if addr.len() as u8 != self.proto_addr_len {
            return Err(BuildError::InvalidField {
                field: "target_proto_addr",
                reason: "length mismatch",
            });
        }
        self.target_proto = addr.to_vec();
        Ok(self)
    }

    pub fn build(self) -> Vec<u8> {
        let total = 8 + self.sender_hw.len() + self.sender_proto.len()
            + self.target_hw.len() + self.target_proto.len();
        let mut buf = Vec::with_capacity(total);

        write_u16be(&mut [0u8; 2], self.hw_type);
        buf.extend_from_slice(&self.hw_type.to_be_bytes());
        buf.extend_from_slice(&self.proto_type.to_be_bytes());
        buf.push(self.hw_addr_len);
        buf.push(self.proto_addr_len);
        buf.extend_from_slice(&self.operation.to_be_bytes());
        buf.extend_from_slice(&self.sender_hw);
        buf.extend_from_slice(&self.sender_proto);
        buf.extend_from_slice(&self.target_hw);
        buf.extend_from_slice(&self.target_proto);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ARP Request: who-has 192.168.1.2 tell 192.168.1.1
    const SAMPLE_ARP_REQUEST: &[u8] = &[
        0x00, 0x01, // hardware: Ethernet
        0x08, 0x00, // protocol: IPv4
        0x06, // hw addr len
        0x04, // proto addr len
        0x00, 0x01, // operation: Request
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // sender MAC
        0xC0, 0xA8, 0x01, 0x01, // sender IP: 192.168.1.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (zero)
        0xC0, 0xA8, 0x01, 0x02, // target IP: 192.168.1.2
    ];

    #[test]
    fn parse_arp_request() {
        let pkt = ArpPacket::new(SAMPLE_ARP_REQUEST).unwrap();
        assert_eq!(pkt.hardware_type(), ArpHardwareType::Ethernet);
        assert_eq!(pkt.protocol_type(), EtherType::Ipv4);
        assert!(pkt.is_request());
        assert!(!pkt.is_reply());
        assert_eq!(pkt.sender_hw_addr(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(pkt.sender_proto_addr(), &[192, 168, 1, 1]);
        assert_eq!(pkt.target_hw_addr(), &[0u8; 6]);
        assert_eq!(pkt.target_proto_addr(), &[192, 168, 1, 2]);
    }

    #[test]
    fn parse_too_short() {
        assert!(ArpPacket::new(&[0u8; 27]).is_none());
        assert!(ArpPacket::new(&[]).is_none());
    }

    #[test]
    fn build_and_parse_roundtrip() {
        let buf = ArpPacketBuilder::new()
            .operation(ArpOperation::Reply)
            .sender_hw_addr(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
            .unwrap()
            .sender_proto_addr(&[10, 0, 0, 1])
            .unwrap()
            .target_hw_addr(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
            .unwrap()
            .target_proto_addr(&[10, 0, 0, 2])
            .unwrap()
            .build();

        let pkt = ArpPacket::new(&buf).unwrap();
        assert!(pkt.is_reply());
        assert_eq!(pkt.sender_hw_addr(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(pkt.target_proto_addr(), &[10, 0, 0, 2]);
    }
}
