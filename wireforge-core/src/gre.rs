//! GRE (Generic Routing Encapsulation) tunnel packet parser and builder.
//! Implements RFC 2784 (base) and RFC 2890 (Key/Sequence extensions).

use alloc::vec;
use alloc::vec::Vec;

use crate::types::EtherType;
use crate::util::{seal_internet_checksum, read_u16be, read_u32be, write_u16be};

pub const GRE_MIN_LEN: usize = 4;

// Flag bits in the first 2 bytes
const FLAG_CHECKSUM: u16 = 0x8000;
const FLAG_ROUTING: u16 = 0x4000;
const FLAG_KEY: u16 = 0x2000;
const FLAG_SEQUENCE: u16 = 0x1000;
const FLAG_STRICT_ROUTE: u16 = 0x0800;
const FLAG_RECURSION_MASK: u16 = 0x0700;
const FLAG_VERSION_MASK: u16 = 0x0007;
const FLAG_RECURSION_SHIFT: u16 = 8;

/// Zero-copy GRE packet parser.
#[derive(Debug, Clone)]
pub struct GrePacket<'a> {
    buf: &'a [u8],
}

impl<'a> GrePacket<'a> {
    crate::parser_new!(GRE_MIN_LEN);

    /// Raw bytes backing this packet.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] { self.buf }

    #[inline]
    pub fn flags(&self) -> u16 {
        read_u16be(&self.buf[..2])
    }

    #[inline] pub fn checksum_present(&self) -> bool { self.flags() & FLAG_CHECKSUM != 0 }
    #[inline] pub fn routing_present(&self) -> bool { self.flags() & FLAG_ROUTING != 0 }
    #[inline] pub fn key_present(&self) -> bool { self.flags() & FLAG_KEY != 0 }
    #[inline] pub fn sequence_present(&self) -> bool { self.flags() & FLAG_SEQUENCE != 0 }
    #[inline] pub fn strict_source_route(&self) -> bool { self.flags() & FLAG_STRICT_ROUTE != 0 }
    #[inline] pub fn recursion_control(&self) -> u8 {
        ((self.flags() & FLAG_RECURSION_MASK) >> FLAG_RECURSION_SHIFT) as u8
    }
    #[inline] pub fn version(&self) -> u8 {
        (self.flags() & FLAG_VERSION_MASK) as u8
    }

    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::from(read_u16be(&self.buf[2..4]))
    }

    fn option_offset(&self) -> usize {
        let mut off = GRE_MIN_LEN;
        if self.checksum_present() { off += 4; }
        if self.key_present() { off += 4; }
        if self.sequence_present() { off += 4; }
        if self.routing_present()
            && off + 2 <= self.buf.len() {
                let routing_len = read_u16be(&self.buf[off..off+2]) as usize;
                off += routing_len;
        }
        off
    }

    pub fn checksum(&self) -> Option<u16> {
        if self.checksum_present() && self.buf.len() >= 8 {
            Some(read_u16be(&self.buf[4..6]))
        } else { None }
    }

    pub fn key(&self) -> Option<u32> {
        if !self.key_present() { return None; }
        let mut off = GRE_MIN_LEN;
        if self.checksum_present() { off += 4; }
        if off + 4 <= self.buf.len() { Some(read_u32be(&self.buf[off..off+4])) } else { None }
    }

    pub fn sequence(&self) -> Option<u32> {
        if !self.sequence_present() { return None; }
        let mut off = GRE_MIN_LEN;
        if self.checksum_present() { off += 4; }
        if self.key_present() { off += 4; }
        if off + 4 <= self.buf.len() { Some(read_u32be(&self.buf[off..off+4])) } else { None }
    }

    pub fn routing(&self) -> Option<&[u8]> {
        if !self.routing_present() { return None; }
        let mut off = GRE_MIN_LEN;
        if self.checksum_present() { off += 4; }
        if self.key_present() { off += 4; }
        if self.sequence_present() { off += 4; }
        if off + 2 <= self.buf.len() {
            let len = read_u16be(&self.buf[off..off+2]) as usize;
            let end = (off + len).min(self.buf.len());
            Some(&self.buf[off..end])
        } else { None }
    }

    #[inline]
    pub fn header_length(&self) -> usize { self.option_offset() }

    #[inline]
    pub fn payload(&self) -> &'a [u8] { &self.buf[self.option_offset()..] }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub struct GrePacketBuilder {
    buf: Vec<u8>,
    has_checksum: bool,
    has_key: bool,
    has_seq: bool,
    key_val: u32,
    seq_val: u32,
    payload: Option<Vec<u8>>,
}

impl GrePacketBuilder {
    pub fn new(protocol_type: EtherType) -> Self {
        let mut buf = vec![0u8; GRE_MIN_LEN];
        let pt: u16 = protocol_type.into();
        write_u16be(&mut buf[2..4], pt);
        Self {
            buf, has_checksum: false, has_key: false, has_seq: false,
            key_val: 0, seq_val: 0, payload: None,
        }
    }

    pub fn key(mut self, key: u32) -> Self {
        self.has_key = true; self.key_val = key; self
    }

    pub fn sequence(mut self, seq: u32) -> Self {
        self.has_seq = true; self.seq_val = seq; self
    }

    pub fn checksum(mut self) -> Self {
        self.has_checksum = true; self
    }

    pub fn recursion_control(mut self, v: u8) -> Self {
        let flags = read_u16be(&self.buf[..2]);
        let updated = (flags & !FLAG_RECURSION_MASK) | (((v as u16) << FLAG_RECURSION_SHIFT) & FLAG_RECURSION_MASK);
        write_u16be(&mut self.buf[..2], updated);
        self
    }

    pub fn version(mut self, v: u8) -> Self {
        let flags = read_u16be(&self.buf[..2]);
        write_u16be(&mut self.buf[..2], (flags & !FLAG_VERSION_MASK) | (v as u16 & FLAG_VERSION_MASK));
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }

    pub fn build(mut self) -> Vec<u8> {
        let mut flags = read_u16be(&self.buf[..2]);
        if self.has_checksum { flags |= FLAG_CHECKSUM; }
        if self.has_key { flags |= FLAG_KEY; }
        if self.has_seq {
            flags |= FLAG_SEQUENCE;
            if !self.has_key { self.has_key = true; self.key_val = 0; flags |= FLAG_KEY; }
        }
        write_u16be(&mut self.buf[..2], flags);

        let mut extras = Vec::new();
        // Checksum slot (0 for now)
        let csum_pos = if self.has_checksum { let p = extras.len() + GRE_MIN_LEN; extras.extend_from_slice(&[0u8; 4]); Some(p) } else { None };
        // Key
        if self.has_key { extras.extend_from_slice(&self.key_val.to_be_bytes()); }
        // Sequence
        if self.has_seq { extras.extend_from_slice(&self.seq_val.to_be_bytes()); }

        let mut pkt = self.buf;
        pkt.extend_from_slice(&extras);
        if let Some(ref p) = self.payload { pkt.extend_from_slice(p); }

        // Compute GRE checksum (RFC 2784: over GRE header + payload)
        if let Some(pos) = csum_pos {
            seal_internet_checksum(&mut pkt, pos);
        }

        pkt
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_gre() {
        // GRE with no options, protocol_type=IPv4(0x0800)
        let data = &[0x00u8, 0x00, 0x08, 0x00, 0xAA, 0xBB];
        let pkt = GrePacket::new(data).unwrap();
        assert!(!pkt.checksum_present());
        assert!(!pkt.key_present());
        assert!(!pkt.sequence_present());
        assert_eq!(pkt.version(), 0);
        assert_eq!(pkt.protocol_type(), EtherType::Ipv4);
        assert_eq!(pkt.header_length(), 4);
        assert_eq!(pkt.payload(), &[0xAA, 0xBB]);
        assert_eq!(pkt.key(), None);
        assert_eq!(pkt.sequence(), None);
    }

    #[test]
    fn parse_gre_with_key() {
        // K bit set, key=0x12345678
        let mut data = vec![0x20u8, 0x00, 0x08, 0x00]; // K=1
        data.extend_from_slice(&0x12345678u32.to_be_bytes());
        data.extend_from_slice(&[0xCC, 0xDD]);
        let pkt = GrePacket::new(&data).unwrap();
        assert!(pkt.key_present());
        assert_eq!(pkt.key(), Some(0x12345678));
        assert_eq!(pkt.header_length(), 8);
        assert_eq!(pkt.payload(), &[0xCC, 0xDD]);
    }

    #[test]
    fn parse_gre_with_key_seq() {
        // K+S, key=1, seq=42
        let mut data = vec![0x30u8, 0x00, 0x08, 0x00];
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&42u32.to_be_bytes());
        data.push(0xEE);
        let pkt = GrePacket::new(&data).unwrap();
        assert!(pkt.key_present());
        assert!(pkt.sequence_present());
        assert_eq!(pkt.key(), Some(1));
        assert_eq!(pkt.sequence(), Some(42));
        assert_eq!(pkt.header_length(), 12);
        assert_eq!(pkt.payload(), &[0xEE]);
    }

    #[test]
    fn build_roundtrip() {
        let pkt = GrePacketBuilder::new(EtherType::Ipv4)
            .key(0xABCD)
            .sequence(100)
            .payload(&[0x01, 0x02, 0x03])
            .build();

        let parsed = GrePacket::new(&pkt).unwrap();
        assert_eq!(parsed.protocol_type(), EtherType::Ipv4);
        assert_eq!(parsed.key(), Some(0xABCD));
        assert_eq!(parsed.sequence(), Some(100));
        assert!(parsed.key_present()); // key always set when seq is set
        assert_eq!(parsed.payload(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn build_with_checksum() {
        let pkt = GrePacketBuilder::new(EtherType::Ipv4)
            .key(1)
            .checksum()
            .payload(&[0xAA])
            .build();

        let parsed = GrePacket::new(&pkt).unwrap();
        assert!(parsed.checksum_present());
        assert!(parsed.checksum().is_some());
        assert_eq!(parsed.payload(), &[0xAA]);
    }

    #[test]
    fn parse_too_short() {
        assert!(GrePacket::new(&[]).is_none());
        assert!(GrePacket::new(&[0u8; 3]).is_none());
        assert!(GrePacket::new(&[0u8; 4]).is_some());
    }

    #[test]
    fn header_length_variants() {
        let basic = GrePacketBuilder::new(EtherType::Ipv4).build();
        assert_eq!(GrePacket::new(&basic).unwrap().header_length(), 4);

        let with_key = GrePacketBuilder::new(EtherType::Ipv4).key(1).build();
        assert_eq!(GrePacket::new(&with_key).unwrap().header_length(), 8);

        let with_key_seq = GrePacketBuilder::new(EtherType::Ipv4).key(1).sequence(1).build();
        assert_eq!(GrePacket::new(&with_key_seq).unwrap().header_length(), 12);
    }
}
