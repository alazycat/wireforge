//! IPv4 packet parser and builder.

use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::types::IpProtocol;
use crate::util::{internet_checksum, read_u16be, read_u32be, write_u16be, write_u32be, BuildError};

/// Minimum IPv4 header length in bytes (without options).
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// Zero-copy IPv4 packet parser.
#[derive(Debug, Clone)]
pub struct Ipv4Packet<'a> {
    buf: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Attempt to parse an IPv4 packet. Returns `None` if `buf` is shorter than
    /// the minimum header length, or if the IHL-declared header length exceeds `buf`.
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < IPV4_MIN_HEADER_LEN {
            return None;
        }
        let ihl = (buf[0] & 0x0F) as usize * 4;
        if ihl < IPV4_MIN_HEADER_LEN || buf.len() < ihl {
            return None;
        }
        Some(Self { buf })
    }

    #[inline]
    pub fn version(&self) -> u8 {
        self.buf[0] >> 4
    }

    #[inline]
    pub fn ihl(&self) -> u8 {
        self.buf[0] & 0x0F
    }

    #[inline]
    pub fn dscp(&self) -> u8 {
        self.buf[1] >> 2
    }

    #[inline]
    pub fn ecn(&self) -> u8 {
        self.buf[1] & 0x03
    }

    #[inline]
    pub fn total_length(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }

    #[inline]
    pub fn identification(&self) -> u16 {
        read_u16be(&self.buf[4..6])
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.buf[6] >> 5
    }

    #[inline]
    pub fn dont_fragment(&self) -> bool {
        self.flags() & 0x02 != 0
    }

    #[inline]
    pub fn more_fragments(&self) -> bool {
        self.flags() & 0x01 != 0
    }

    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        read_u16be(&self.buf[6..8]) & 0x1FFF
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        self.buf[8]
    }

    #[inline]
    pub fn protocol(&self) -> IpProtocol {
        IpProtocol::from(self.buf[9])
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        read_u16be(&self.buf[10..12])
    }

    #[inline]
    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::from_bits(read_u32be(&self.buf[12..16]))
    }

    #[inline]
    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::from_bits(read_u32be(&self.buf[16..20]))
    }

    /// IP options bytes (if any).
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        let hdr_len = self.ihl() as usize * 4;
        if hdr_len > IPV4_MIN_HEADER_LEN {
            &self.buf[IPV4_MIN_HEADER_LEN..hdr_len]
        } else {
            &[]
        }
    }

    /// Payload following the IPv4 header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.ihl() as usize * 4..]
    }

    /// Total header length in bytes (IHL × 4).
    #[inline]
    pub fn header_length(&self) -> usize {
        self.ihl() as usize * 4
    }

    /// Verify the IPv4 header checksum.
    pub fn verify_checksum(&self) -> bool {
        internet_checksum(&self.buf[..self.header_length()]) == 0
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for IPv4 packets.
#[derive(Debug, Clone)]
pub struct Ipv4PacketBuilder {
    buf: Vec<u8>,
    payload: Option<Vec<u8>>,
}

impl Default for Ipv4PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv4PacketBuilder {
    /// Create a new builder with a default IPv4 header (version=4, IHL=5, TTL=64).
    pub fn new() -> Self {
        let mut buf = vec![0u8; IPV4_MIN_HEADER_LEN];
        buf[0] = 0x45; // version=4, IHL=5
        buf[8] = 64; // TTL=64
        Self { buf, payload: None }
    }

    pub fn dscp(mut self, dscp: u8) -> Self {
        self.buf[1] = (self.buf[1] & 0x03) | (dscp << 2);
        self
    }

    pub fn ecn(mut self, ecn: u8) -> Self {
        self.buf[1] = (self.buf[1] & 0xFC) | (ecn & 0x03);
        self
    }

    pub fn identification(mut self, id: u16) -> Self {
        write_u16be(&mut self.buf[4..6], id);
        self
    }

    pub fn dont_fragment(mut self, df: bool) -> Self {
        if df {
            self.buf[6] |= 0x40;
        } else {
            self.buf[6] &= !0x40;
        }
        self
    }

    pub fn more_fragments(mut self, mf: bool) -> Self {
        if mf {
            self.buf[6] |= 0x20;
        } else {
            self.buf[6] &= !0x20;
        }
        self
    }

    pub fn fragment_offset(mut self, offset: u16) -> Self {
        let current = read_u16be(&self.buf[6..8]);
        let new = (current & 0xE000) | (offset & 0x1FFF);
        write_u16be(&mut self.buf[6..8], new);
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.buf[8] = ttl;
        self
    }

    pub fn protocol(mut self, proto: IpProtocol) -> Self {
        self.buf[9] = proto.into();
        self
    }

    pub fn source(mut self, addr: Ipv4Addr) -> Self {
        write_u32be(&mut self.buf[12..16], addr.to_bits());
        self
    }

    pub fn destination(mut self, addr: Ipv4Addr) -> Self {
        write_u32be(&mut self.buf[16..20], addr.to_bits());
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Result<Self, BuildError> {
        if data.len() > 65535 - self.buf.len() {
            return Err(BuildError::PayloadTooLarge {
                max: 65535 - self.buf.len(),
                actual: data.len(),
            });
        }
        self.payload = Some(data.to_vec());
        Ok(self)
    }

    /// Build the IPv4 packet, computing total_length and header checksum automatically.
    pub fn build(mut self) -> Vec<u8> {
        let total_len = self.buf.len() + self.payload.as_ref().map_or(0, |p| p.len());
        write_u16be(&mut self.buf[2..4], total_len as u16);

        // Zero the checksum field before computing
        self.buf[10] = 0;
        self.buf[11] = 0;
        let checksum = internet_checksum(&self.buf);
        write_u16be(&mut self.buf[10..12], checksum);

        let mut packet = self.buf;
        if let Some(p) = self.payload {
            packet.extend_from_slice(&p);
        }
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real IPv4 header: 192.168.10.99 → 172.16.10.12, TCP, TTL=64
    const SAMPLE_IPV4: &[u8] = &[
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xAC, 0x10, 0x0A, 0x63,
        0xAC, 0x10, 0x0A, 0x0C,
    ];

    #[test]
    fn parse_ipv4() {
        let pkt = Ipv4Packet::new(SAMPLE_IPV4).unwrap();
        assert_eq!(pkt.version(), 4);
        assert_eq!(pkt.ihl(), 5);
        assert_eq!(pkt.header_length(), 20);
        assert_eq!(pkt.protocol(), IpProtocol::Tcp);
        assert_eq!(pkt.ttl(), 64);
        assert_eq!(pkt.source(), Ipv4Addr::new(172, 16, 10, 99));
        assert_eq!(pkt.destination(), Ipv4Addr::new(172, 16, 10, 12));
        assert!(pkt.dont_fragment());
        assert!(!pkt.more_fragments());
    }

    #[test]
    fn parse_too_short() {
        assert!(Ipv4Packet::new(&[0u8; 19]).is_none());
        assert!(Ipv4Packet::new(&[]).is_none());
    }

    #[test]
    fn parse_ihl_exceeds_buffer() {
        // IHL=6 (24 bytes) but only 22 bytes provided
        let mut data = [0u8; 22];
        data[0] = 0x46; // version=4, IHL=6
        assert!(Ipv4Packet::new(&data).is_none());
    }

    #[test]
    fn verify_checksum() {
        // Build a packet and verify its checksum
        let pkt_bytes = Ipv4PacketBuilder::new()
            .source(Ipv4Addr::new(10, 0, 0, 1))
            .destination(Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .ttl(64)
            .build();

        let pkt = Ipv4Packet::new(&pkt_bytes).unwrap();
        assert!(pkt.verify_checksum());
    }

    #[test]
    fn build_and_parse_roundtrip() {
        let pkt_bytes = Ipv4PacketBuilder::new()
            .source(Ipv4Addr::new(192, 168, 1, 1))
            .destination(Ipv4Addr::new(192, 168, 1, 2))
            .protocol(IpProtocol::Udp)
            .ttl(128)
            .dont_fragment(true)
            .identification(0x1234)
            .build();

        let pkt = Ipv4Packet::new(&pkt_bytes).unwrap();
        assert_eq!(pkt.source(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(pkt.destination(), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(pkt.protocol(), IpProtocol::Udp);
        assert_eq!(pkt.ttl(), 128);
        assert!(pkt.dont_fragment());
        assert_eq!(pkt.identification(), 0x1234);
        assert!(pkt.verify_checksum());
    }

    #[test]
    fn parse_with_options() {
        // IPv4 header with 4 bytes of options (IHL=6, total header=24)
        let mut data = vec![0x46u8, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01, 0xC0, 0xA8, 0x01, 0x02,
            0x01, 0x02, 0x03, 0x04, // options
            0xAA, 0xBB, // payload
        ];
        // Compute checksum
        let csum = internet_checksum(&data[..24]);
        data[10..12].copy_from_slice(&csum.to_be_bytes());

        let pkt = Ipv4Packet::new(&data).unwrap();
        assert_eq!(pkt.ihl(), 6);
        assert_eq!(pkt.header_length(), 24);
        assert_eq!(pkt.options(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(pkt.payload(), &[0xAA, 0xBB]);
        assert!(pkt.verify_checksum());
    }
}
