//! UDP packet parser and builder.

use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::types::IpProtocol;
use crate::util::{
    ipv4_transport_checksum, ipv6_transport_checksum, read_u16be, seal_transport_checksum,
    write_u16be,
};

pub const UDP_HEADER_LEN: usize = 8;

/// Zero-copy UDP packet parser.
#[derive(Debug, Clone)]
pub struct UdpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    crate::parser_new!(UDP_HEADER_LEN);

    /// Raw bytes backing this packet.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
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

    /// Verify the UDP checksum with an IPv4 pseudo-header.
    /// Returns true for a zero checksum (allowed in IPv4 UDP).
    pub fn verify_checksum(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        if self.checksum() == 0 {
            return true; // zero checksum means "not computed" per RFC 768
        }
        ipv4_transport_checksum(src, dst, IpProtocol::Udp.into(), self.buf) == 0
    }

    /// Verify the UDP checksum with an IPv6 pseudo-header.
    ///
    /// Unlike IPv4, a zero checksum is not valid for UDP over IPv6.
    pub fn verify_checksum_v6(&self, src: Ipv6Addr, dst: Ipv6Addr) -> bool {
        ipv6_transport_checksum(src, dst, IpProtocol::Udp.into(), self.buf) == 0
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
        Self {
            buf: vec![0u8; UDP_HEADER_LEN],
            payload: None,
        }
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

    /// Finalize the UDP datagram with a zero checksum field.
    fn finish(mut self) -> Vec<u8> {
        if let Some(ref p) = self.payload {
            self.buf.extend_from_slice(p);
        }
        let total_len = self.buf.len();
        write_u16be(&mut self.buf[4..6], total_len as u16);
        self.buf
    }

    /// Build the UDP packet, computing the checksum with an IPv4 pseudo-header.
    pub fn build(self, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut packet = self.finish();
        seal_transport_checksum(
            &mut packet,
            6,
            &src.octets(),
            &dst.octets(),
            IpProtocol::Udp.into(),
        );
        packet
    }

    /// Build the UDP packet, computing the checksum with an IPv6 pseudo-header.
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    /// use wireforge_core::udp::{UdpPacket, UdpPacketBuilder};
    ///
    /// let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    /// let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
    /// let bytes = UdpPacketBuilder::new()
    ///     .source_port(53)
    ///     .destination_port(5353)
    ///     .build_v6(src, dst);
    /// assert!(UdpPacket::new(&bytes).unwrap().verify_checksum_v6(src, dst));
    /// ```
    pub fn build_v6(self, src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut packet = self.finish();
        seal_transport_checksum(
            &mut packet,
            6,
            &src.octets(),
            &dst.octets(),
            IpProtocol::Udp.into(),
        );
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
        let data: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00];
        let pkt = UdpPacket::new(data).unwrap();
        assert!(pkt.verify_checksum(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2),));
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

crate::impl_mutable_packet!(MutableUdpPacket, UDP_HEADER_LEN);

impl<'a> MutableUdpPacket<'a> {
    fn view(&self) -> UdpPacket<'_> {
        UdpPacket::new(&*self.buf).expect("validated in MutableUdpPacket::new")
    }

    fn payload_offset(&self) -> usize {
        UDP_HEADER_LEN
    }

    /// Source port.
    pub fn source_port(&self) -> u16 {
        self.view().source_port()
    }

    /// Set the source port.
    pub fn set_source_port(&mut self, port: u16) {
        write_u16be(&mut self.buf[..2], port);
    }

    /// Destination port.
    pub fn destination_port(&self) -> u16 {
        self.view().destination_port()
    }

    /// Set the destination port.
    pub fn set_destination_port(&mut self, port: u16) {
        write_u16be(&mut self.buf[2..4], port);
    }

    /// UDP length field.
    pub fn length(&self) -> u16 {
        self.view().length()
    }

    /// Set the UDP length field.
    pub fn set_length(&mut self, length: u16) {
        write_u16be(&mut self.buf[4..6], length);
    }

    /// Checksum.
    pub fn checksum(&self) -> u16 {
        self.view().checksum()
    }

    /// Set the checksum directly.
    pub fn set_checksum(&mut self, checksum: u16) {
        write_u16be(&mut self.buf[6..8], checksum);
    }

    /// Recompute the UDP checksum with an IPv4 pseudo-header.
    pub fn update_checksum(&mut self, src: Ipv4Addr, dst: Ipv4Addr) {
        seal_transport_checksum(
            self.buf,
            6,
            &src.octets(),
            &dst.octets(),
            IpProtocol::Udp.into(),
        );
    }

    /// Recompute the UDP checksum with an IPv6 pseudo-header.
    pub fn update_checksum_v6(&mut self, src: Ipv6Addr, dst: Ipv6Addr) {
        seal_transport_checksum(
            self.buf,
            6,
            &src.octets(),
            &dst.octets(),
            IpProtocol::Udp.into(),
        );
    }
}
