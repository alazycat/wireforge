//! UDP packet parser and builder.

use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::util::{pseudo_header_checksum, read_u16be, write_u16be};

pub const UDP_HEADER_LEN: usize = 8;

/// Zero-copy UDP packet parser.
#[derive(Debug, Clone)]
pub struct UdpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < UDP_HEADER_LEN {
            return None;
        }
        Some(Self { buf })
    }

    #[inline]
    pub fn source_port(&self) -> u16 {
        read_u16be(&self.buf[..2])
    }

    #[inline]
    pub fn destination_port(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }

    #[inline]
    pub fn length(&self) -> u16 {
        read_u16be(&self.buf[4..6])
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        read_u16be(&self.buf[6..8])
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[UDP_HEADER_LEN..]
    }

    /// Verify the UDP checksum (includes IPv4 pseudo-header).
    /// Returns true for zero checksum (allowed in IPv4 UDP).
    pub fn verify_checksum(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        if self.checksum() == 0 {
            return true; // zero checksum means "not computed" per RFC 768
        }
        pseudo_header_checksum(
            &src.octets(),
            &dst.octets(),
            17, // UDP protocol number
            self.buf,
        ) == 0
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub struct UdpPacketBuilder {
    buf: Vec<u8>,
    payload: Option<Vec<u8>>,
}

impl Default for UdpPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpPacketBuilder {
    pub fn new() -> Self {
        Self { buf: vec![0u8; UDP_HEADER_LEN], payload: None }
    }

    pub fn source_port(mut self, port: u16) -> Self {
        write_u16be(&mut self.buf[..2], port);
        self
    }

    pub fn destination_port(mut self, port: u16) -> Self {
        write_u16be(&mut self.buf[2..4], port);
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }

    /// Build the UDP packet, computing the checksum (IPv4 pseudo-header).
    pub fn build(mut self, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        self.buf[6] = 0;
        self.buf[7] = 0;

        let mut packet = self.buf;
        if let Some(ref p) = self.payload {
            packet.extend_from_slice(p);
        }
        let total_len = packet.len();
        write_u16be(&mut packet[4..6], total_len as u16);

        let csum = pseudo_header_checksum(
            &src.octets(),
            &dst.octets(),
            17, // UDP
            &packet,
        );
        write_u16be(&mut packet[6..8], csum);
        packet
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_udp() {
        let data: &[u8] = &[
            0x12, 0x34, // src port = 4660
            0x00, 0x50, // dst port = 80
            0x00, 0x0C, // length = 12
            0x00, 0x00, // checksum = 0
            0xAA, 0xBB, 0xCC, 0xDD, // payload
        ];
        let pkt = UdpPacket::new(data).unwrap();
        assert_eq!(pkt.source_port(), 4660);
        assert_eq!(pkt.destination_port(), 80);
        assert_eq!(pkt.length(), 12);
        assert_eq!(pkt.checksum(), 0);
        assert_eq!(pkt.payload(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn parse_udp_too_short() {
        assert!(UdpPacket::new(&[]).is_none());
        assert!(UdpPacket::new(&[0u8; 7]).is_none());
        assert!(UdpPacket::new(&[0u8; 8]).is_some());
    }

    #[test]
    fn udp_zero_checksum() {
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
        ];
        let pkt = UdpPacket::new(data).unwrap();
        assert!(pkt.verify_checksum(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        ));
    }

    #[test]
    fn udp_build_and_verify_checksum() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let pkt_bytes = UdpPacketBuilder::new()
            .source_port(12345)
            .destination_port(53)
            .payload(&[0x01, 0x02, 0x03, 0x04])
            .build(src, dst);

        let pkt = UdpPacket::new(&pkt_bytes).unwrap();
        assert_eq!(pkt.source_port(), 12345);
        assert_eq!(pkt.destination_port(), 53);
        assert_eq!(pkt.length(), 12);
        assert_eq!(pkt.payload(), &[0x01, 0x02, 0x03, 0x04]);
        assert!(pkt.verify_checksum(src, dst));
    }
}
