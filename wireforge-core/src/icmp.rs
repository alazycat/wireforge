//! ICMP (v4) and ICMPv6 packet parsers and builders, including NDP messages.

use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv6Addr;

use crate::types::IpProtocol;
use crate::util::{internet_checksum, pseudo_header_checksum, read_u16be, read_u32be, write_u16be};

// ---------------------------------------------------------------------------
// ICMPv4 constants
// ---------------------------------------------------------------------------

pub const ICMP_HEADER_LEN: usize = 8;

pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_DEST_UNREACH: u8 = 3;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_TYPE_TIME_EXCEEDED: u8 = 11;

// ---------------------------------------------------------------------------
// ICMPv6 constants
// ---------------------------------------------------------------------------

pub const ICMPV6_HEADER_LEN: usize = 8;

pub const ICMPV6_TYPE_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_TYPE_ECHO_REPLY: u8 = 129;
pub const ICMPV6_TYPE_ROUTER_SOLICIT: u8 = 133;
pub const ICMPV6_TYPE_ROUTER_ADVERT: u8 = 134;
pub const ICMPV6_TYPE_NEIGHBOR_SOLICIT: u8 = 135;
pub const ICMPV6_TYPE_NEIGHBOR_ADVERT: u8 = 136;

// ---------------------------------------------------------------------------
// ICMPv4 message types
// ---------------------------------------------------------------------------

/// Parsed ICMPv4 message variant.
#[derive(Debug, Clone)]
pub enum IcmpMessage<'a> {
    EchoReply {
        identifier: u16,
        sequence_number: u16,
        data: &'a [u8],
    },
    EchoRequest {
        identifier: u16,
        sequence_number: u16,
        data: &'a [u8],
    },
    DestUnreachable {
        code: u8,
        data: &'a [u8],
    },
    TimeExceeded {
        code: u8,
        data: &'a [u8],
    },
    Unknown {
        type_: u8,
        code: u8,
        data: &'a [u8],
    },
}

/// Zero-copy ICMPv4 packet parser.
#[derive(Debug, Clone)]
pub struct IcmpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < ICMP_HEADER_LEN {
            return None;
        }
        Some(Self { buf })
    }

    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf[0]
    }

    #[inline]
    pub fn code(&self) -> u8 {
        self.buf[1]
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }

    /// The rest-of-header field (bytes 4..8), interpreted per message type.
    #[inline]
    pub fn rest_of_header(&self) -> u32 {
        read_u32be(&self.buf[4..8])
    }

    /// Payload following the 8-byte ICMP header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[ICMP_HEADER_LEN..]
    }

    /// Verify the ICMP checksum over the entire message.
    pub fn verify_checksum(&self) -> bool {
        internet_checksum(self.buf) == 0
    }

    /// Parse the ICMP message into a typed variant.
    pub fn message(&self) -> IcmpMessage<'a> {
        let payload = self.payload();
        let roh = self.rest_of_header();
        match self.type_() {
            ICMP_TYPE_ECHO_REPLY => IcmpMessage::EchoReply {
                identifier: (roh >> 16) as u16,
                sequence_number: roh as u16,
                data: payload,
            },
            ICMP_TYPE_ECHO_REQUEST => IcmpMessage::EchoRequest {
                identifier: (roh >> 16) as u16,
                sequence_number: roh as u16,
                data: payload,
            },
            ICMP_TYPE_DEST_UNREACH => IcmpMessage::DestUnreachable {
                code: self.code(),
                data: payload,
            },
            ICMP_TYPE_TIME_EXCEEDED => IcmpMessage::TimeExceeded {
                code: self.code(),
                data: payload,
            },
            _ => IcmpMessage::Unknown {
                type_: self.type_(),
                code: self.code(),
                data: payload,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// ICMPv4 builder
// ---------------------------------------------------------------------------

pub struct IcmpPacketBuilder {
    buf: Vec<u8>,
    payload: Option<Vec<u8>>,
}

impl Default for IcmpPacketBuilder {
    fn default() -> Self {
        Self::new(ICMP_TYPE_ECHO_REQUEST, 0)
    }
}

impl IcmpPacketBuilder {
    pub fn new(type_: u8, code: u8) -> Self {
        let mut buf = vec![0u8; ICMP_HEADER_LEN];
        buf[0] = type_;
        buf[1] = code;
        Self { buf, payload: None }
    }

    /// Create a builder for an Echo Request (type 8).
    pub fn echo_request() -> Self {
        Self::new(ICMP_TYPE_ECHO_REQUEST, 0)
    }

    /// Create a builder for an Echo Reply (type 0).
    pub fn echo_reply() -> Self {
        Self::new(ICMP_TYPE_ECHO_REPLY, 0)
    }

    pub fn code(mut self, code: u8) -> Self {
        self.buf[1] = code;
        self
    }

    pub fn identifier(mut self, id: u16) -> Self {
        write_u16be(&mut self.buf[4..6], id);
        self
    }

    pub fn sequence_number(mut self, seq: u16) -> Self {
        write_u16be(&mut self.buf[6..8], seq);
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }

    pub fn build(mut self) -> Vec<u8> {
        // Zero checksum, compute over entire message, write it back.
        self.buf[2] = 0;
        self.buf[3] = 0;

        let mut packet = self.buf;
        if let Some(ref p) = self.payload {
            packet.extend_from_slice(p);
        }
        let csum = internet_checksum(&packet);
        write_u16be(&mut packet[2..4], csum);
        packet
    }
}

// ---------------------------------------------------------------------------
// ICMPv6 message types
// ---------------------------------------------------------------------------

/// Parsed ICMPv6 message variant, including NDP messages.
#[derive(Debug, Clone)]
pub enum Icmpv6Message<'a> {
    EchoRequest {
        identifier: u16,
        sequence_number: u16,
        data: &'a [u8],
    },
    EchoReply {
        identifier: u16,
        sequence_number: u16,
        data: &'a [u8],
    },
    NeighborSolicitation {
        target_address: Ipv6Addr,
        options: &'a [u8],
    },
    NeighborAdvertisement {
        flags: u8,
        target_address: Ipv6Addr,
        options: &'a [u8],
    },
    RouterSolicitation {
        options: &'a [u8],
    },
    RouterAdvertisement {
        hop_limit: u8,
        flags: u8,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
        options: &'a [u8],
    },
    Unknown {
        type_: u8,
        code: u8,
        data: &'a [u8],
    },
}

/// Zero-copy ICMPv6 packet parser.
#[derive(Debug, Clone)]
pub struct Icmpv6Packet<'a> {
    buf: &'a [u8],
}

impl<'a> Icmpv6Packet<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < ICMPV6_HEADER_LEN {
            return None;
        }
        Some(Self { buf })
    }

    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf[0]
    }

    #[inline]
    pub fn code(&self) -> u8 {
        self.buf[1]
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }

    /// The body after the 8-byte ICMPv6 header.
    #[inline]
    pub fn body(&self) -> &'a [u8] {
        &self.buf[ICMPV6_HEADER_LEN..]
    }

    /// Verify the ICMPv6 checksum (includes IPv6 pseudo-header).
    pub fn verify_checksum(&self, src: Ipv6Addr, dst: Ipv6Addr) -> bool {
        let csum = pseudo_header_checksum(
            &src.octets(),
            &dst.octets(),
            u8::from(IpProtocol::Icmpv6),
            self.buf,
        );
        csum == 0
    }

    /// Parse the ICMPv6 message into a typed variant.
    pub fn message(&self) -> Icmpv6Message<'a> {
        let buf = self.buf;
        match self.type_() {
            ICMPV6_TYPE_ECHO_REQUEST => {
                let id = if buf.len() >= 6 { read_u16be(&buf[4..6]) } else { 0 };
                let seq = if buf.len() >= 8 { read_u16be(&buf[6..8]) } else { 0 };
                let data = if buf.len() > 8 { &buf[8..] } else { &[] };
                Icmpv6Message::EchoRequest { identifier: id, sequence_number: seq, data }
            }
            ICMPV6_TYPE_ECHO_REPLY => {
                let id = if buf.len() >= 6 { read_u16be(&buf[4..6]) } else { 0 };
                let seq = if buf.len() >= 8 { read_u16be(&buf[6..8]) } else { 0 };
                let data = if buf.len() > 8 { &buf[8..] } else { &[] };
                Icmpv6Message::EchoReply { identifier: id, sequence_number: seq, data }
            }
            ICMPV6_TYPE_NEIGHBOR_SOLICIT => {
                let target = if buf.len() >= 24 {
                    let b: [u8; 16] = buf[8..24].try_into().unwrap();
                    Ipv6Addr::from(b)
                } else {
                    Ipv6Addr::UNSPECIFIED
                };
                let options = if buf.len() > 24 { &buf[24..] } else { &[] };
                Icmpv6Message::NeighborSolicitation { target_address: target, options }
            }
            ICMPV6_TYPE_NEIGHBOR_ADVERT => {
                let flags = if buf.len() >= 8 { buf[4] } else { 0 };
                let target = if buf.len() >= 24 {
                    let b: [u8; 16] = buf[8..24].try_into().unwrap();
                    Ipv6Addr::from(b)
                } else {
                    Ipv6Addr::UNSPECIFIED
                };
                let options = if buf.len() > 24 { &buf[24..] } else { &[] };
                Icmpv6Message::NeighborAdvertisement { flags, target_address: target, options }
            }
            ICMPV6_TYPE_ROUTER_SOLICIT => {
                let options = if buf.len() > 8 { &buf[8..] } else { &[] };
                Icmpv6Message::RouterSolicitation { options }
            }
            ICMPV6_TYPE_ROUTER_ADVERT => {
                let hop_limit = if buf.len() >= 8 { buf[4] } else { 0 };
                let flags = if buf.len() >= 8 { buf[5] } else { 0 };
                let router_lifetime = if buf.len() >= 8 { read_u16be(&buf[6..8]) } else { 0 };
                let reachable_time = if buf.len() >= 12 { read_u32be(&buf[8..12]) } else { 0 };
                let retrans_timer = if buf.len() >= 16 { read_u32be(&buf[12..16]) } else { 0 };
                let options = if buf.len() > 16 { &buf[16..] } else { &[] };
                Icmpv6Message::RouterAdvertisement {
                    hop_limit, flags, router_lifetime, reachable_time, retrans_timer, options,
                }
            }
            _ => Icmpv6Message::Unknown {
                type_: self.type_(),
                code: self.code(),
                data: if buf.len() > 8 { &buf[8..] } else { &[] },
            },
        }
    }
}

// ---------------------------------------------------------------------------
// ICMPv6 builder
// ---------------------------------------------------------------------------

pub struct Icmpv6PacketBuilder {
    buf: Vec<u8>,
    body: Vec<u8>,
}

impl Default for Icmpv6PacketBuilder {
    fn default() -> Self {
        Self::new(ICMPV6_TYPE_ECHO_REQUEST, 0)
    }
}

impl Icmpv6PacketBuilder {
    pub fn new(type_: u8, code: u8) -> Self {
        let mut buf = vec![0u8; ICMPV6_HEADER_LEN];
        buf[0] = type_;
        buf[1] = code;
        Self { buf, body: Vec::new() }
    }

    pub fn echo_request() -> Self {
        Self::new(ICMPV6_TYPE_ECHO_REQUEST, 0)
    }

    pub fn echo_reply() -> Self {
        Self::new(ICMPV6_TYPE_ECHO_REPLY, 0)
    }

    pub fn code(mut self, code: u8) -> Self {
        self.buf[1] = code;
        self
    }

    /// Set the identifier field (bytes 4-5 of ICMPv6 header; used by Echo).
    pub fn identifier(mut self, id: u16) -> Self {
        write_u16be(&mut self.buf[4..6], id);
        self
    }

    /// Set the sequence number field (bytes 6-7 of ICMPv6 header; used by Echo).
    pub fn sequence_number(mut self, seq: u16) -> Self {
        write_u16be(&mut self.buf[6..8], seq);
        self
    }

    /// Set raw body bytes (for NDP messages and arbitrary data).
    pub fn body(mut self, data: &[u8]) -> Self {
        self.body = data.to_vec();
        self
    }

    /// Build the ICMPv6 packet, computing the checksum with the IPv6 pseudo-header.
    pub fn build(mut self, src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        self.buf[2] = 0;
        self.buf[3] = 0;

        let mut packet = self.buf;
        packet.extend_from_slice(&self.body);
        let csum = pseudo_header_checksum(
            &src.octets(),
            &dst.octets(),
            u8::from(IpProtocol::Icmpv6),
            &packet,
        );
        write_u16be(&mut packet[2..4], csum);
        packet
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv6Addr;

    // ---------- ICMPv4 tests ----------

    #[test]
    fn parse_icmp_echo_request() {
        // ICMP Echo Request: type=8, code=0, id=0x0001, seq=0x0002
        let data: &[u8] = &[
            0x08, 0x00, 0x00, 0x00, // type, code, checksum (zero for sample)
            0x00, 0x01, 0x00, 0x02, // id=1, seq=2
            0x41, 0x42, 0x43, 0x44, // payload "ABCD"
        ];
        let pkt = IcmpPacket::new(data).unwrap();
        assert_eq!(pkt.type_(), 8);
        assert_eq!(pkt.code(), 0);
        assert_eq!(pkt.payload(), &[0x41, 0x42, 0x43, 0x44]);

        match pkt.message() {
            IcmpMessage::EchoRequest { identifier, sequence_number, data } => {
                assert_eq!(identifier, 1);
                assert_eq!(sequence_number, 2);
                assert_eq!(data, &[0x41, 0x42, 0x43, 0x44]);
            }
            _ => panic!("expected EchoRequest"),
        }
    }

    #[test]
    fn parse_icmp_echo_reply() {
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // type=0, code=0
            0x00, 0x03, 0x00, 0x04, // id=3, seq=4
        ];
        let pkt = IcmpPacket::new(data).unwrap();
        match pkt.message() {
            IcmpMessage::EchoReply { identifier, sequence_number, .. } => {
                assert_eq!(identifier, 3);
                assert_eq!(sequence_number, 4);
            }
            _ => panic!("expected EchoReply"),
        }
    }

    #[test]
    fn parse_icmp_dest_unreachable() {
        let data: &[u8] = &[
            0x03, 0x01, 0x00, 0x00, // type=3, code=1 (host unreachable)
            0x00, 0x00, 0x00, 0x00, // rest of header
            0x11, 0x22, // payload
        ];
        let pkt = IcmpPacket::new(data).unwrap();
        match pkt.message() {
            IcmpMessage::DestUnreachable { code, data: d } => {
                assert_eq!(code, 1);
                assert_eq!(d, &[0x11, 0x22]);
            }
            _ => panic!("expected DestUnreachable"),
        }
    }

    #[test]
    fn parse_icmp_time_exceeded() {
        let data: &[u8] = &[
            0x0B, 0x00, 0x00, 0x00, // type=11, code=0 (TTL exceeded in transit)
            0x00, 0x00, 0x00, 0x00,
        ];
        let pkt = IcmpPacket::new(data).unwrap();
        match pkt.message() {
            IcmpMessage::TimeExceeded { code, .. } => {
                assert_eq!(code, 0);
            }
            _ => panic!("expected TimeExceeded"),
        }
    }

    #[test]
    fn parse_icmp_too_short() {
        assert!(IcmpPacket::new(&[]).is_none());
        assert!(IcmpPacket::new(&[0u8; 7]).is_none());
        assert!(IcmpPacket::new(&[0u8; 8]).is_some());
    }

    #[test]
    fn icmp_echo_build_and_verify_checksum() {
        let pkt_bytes = IcmpPacketBuilder::echo_request()
            .identifier(0x1234)
            .sequence_number(1)
            .payload(&[0xAA, 0xBB, 0xCC, 0xDD])
            .build();

        let pkt = IcmpPacket::new(&pkt_bytes).unwrap();
        assert!(pkt.verify_checksum());
        match pkt.message() {
            IcmpMessage::EchoRequest { identifier, sequence_number, .. } => {
                assert_eq!(identifier, 0x1234);
                assert_eq!(sequence_number, 1);
            }
            _ => panic!("expected EchoRequest"),
        }
    }

    // ---------- ICMPv6 tests ----------

    #[test]
    fn parse_icmpv6_echo_request() {
        let data: &[u8] = &[
            0x80, 0x00, 0x00, 0x00, // type=128, code=0
            0x00, 0x05, 0x00, 0x06, // id=5, seq=6
            0xDE, 0xAD, // data
        ];
        let pkt = Icmpv6Packet::new(data).unwrap();
        assert_eq!(pkt.type_(), 128);
        match pkt.message() {
            Icmpv6Message::EchoRequest { identifier, sequence_number, data } => {
                assert_eq!(identifier, 5);
                assert_eq!(sequence_number, 6);
                assert_eq!(data, &[0xDE, 0xAD]);
            }
            _ => panic!("expected EchoRequest"),
        }
    }

    #[test]
    fn parse_icmpv6_echo_reply() {
        let data: &[u8] = &[
            0x81, 0x00, 0x00, 0x00,
            0x00, 0x07, 0x00, 0x08,
        ];
        let pkt = Icmpv6Packet::new(data).unwrap();
        match pkt.message() {
            Icmpv6Message::EchoReply { identifier, sequence_number, .. } => {
                assert_eq!(identifier, 7);
                assert_eq!(sequence_number, 8);
            }
            _ => panic!("expected EchoReply"),
        }
    }

    #[test]
    fn parse_icmpv6_neighbor_solicitation() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut data = vec![0x87u8, 0x00, 0x00, 0x00]; // type=135, code=0
        data.extend_from_slice(&[0u8; 4]); // reserved
        data.extend_from_slice(&target.octets()); // target address
        data.extend_from_slice(&[0x01, 0x01, 0x02, 0x03]); // source link-layer option

        let pkt = Icmpv6Packet::new(&data).unwrap();
        match pkt.message() {
            Icmpv6Message::NeighborSolicitation { target_address, options } => {
                assert_eq!(target_address, target);
                assert_eq!(options.len(), 4);
            }
            _ => panic!("expected NeighborSolicitation"),
        }
    }

    #[test]
    fn parse_icmpv6_neighbor_advertisement() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let mut data = vec![0x88u8, 0x00, 0x00, 0x00]; // type=136, code=0
        data.push(0x60); // flags: S=1, O=1
        data.extend_from_slice(&[0u8; 3]); // reserved
        data.extend_from_slice(&target.octets()); // target address

        let pkt = Icmpv6Packet::new(&data).unwrap();
        match pkt.message() {
            Icmpv6Message::NeighborAdvertisement { flags, target_address, .. } => {
                assert_eq!(flags, 0x60);
                assert_eq!(target_address, target);
            }
            _ => panic!("expected NeighborAdvertisement"),
        }
    }

    #[test]
    fn parse_icmpv6_router_solicitation() {
        let data: &[u8] = &[
            0x85, 0x00, 0x00, 0x00, // type=133, code=0
            0x00, 0x00, 0x00, 0x00, // reserved
            0x01, 0x01, // option (source link-layer address)
        ];
        let pkt = Icmpv6Packet::new(data).unwrap();
        match pkt.message() {
            Icmpv6Message::RouterSolicitation { options } => {
                assert_eq!(options.len(), 2);
            }
            _ => panic!("expected RouterSolicitation"),
        }
    }

    #[test]
    fn parse_icmpv6_router_advertisement() {
        let mut data = vec![0x86u8, 0x00, 0x00, 0x00]; // type=134, code=0
        data.push(64); // hop_limit
        data.push(0x08); // flags: prf=medium
        data.extend_from_slice(&0x0E10u16.to_be_bytes()); // router_lifetime = 3600
        data.extend_from_slice(&0x0000EA60u32.to_be_bytes()); // reachable_time = 60000
        data.extend_from_slice(&0x00002710u32.to_be_bytes()); // retrans_timer = 10000
        data.extend_from_slice(&[0x01, 0x01]); // options

        let pkt = Icmpv6Packet::new(&data).unwrap();
        match pkt.message() {
            Icmpv6Message::RouterAdvertisement {
                hop_limit, flags, router_lifetime,
                reachable_time, retrans_timer, options,
            } => {
                assert_eq!(hop_limit, 64);
                assert_eq!(flags, 0x08);
                assert_eq!(router_lifetime, 3600);
                assert_eq!(reachable_time, 60000);
                assert_eq!(retrans_timer, 10000);
                assert_eq!(options.len(), 2);
            }
            _ => panic!("expected RouterAdvertisement"),
        }
    }

    #[test]
    fn parse_icmpv6_too_short() {
        assert!(Icmpv6Packet::new(&[]).is_none());
        assert!(Icmpv6Packet::new(&[0u8; 7]).is_none());
        assert!(Icmpv6Packet::new(&[0u8; 8]).is_some());
    }

    #[test]
    fn icmpv6_echo_build_and_verify_checksum() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let pkt_bytes = Icmpv6PacketBuilder::echo_request()
            .identifier(0x42)
            .sequence_number(1)
            .build(src, dst);

        let pkt = Icmpv6Packet::new(&pkt_bytes).unwrap();
        assert!(pkt.verify_checksum(src, dst));
        match pkt.message() {
            Icmpv6Message::EchoRequest { identifier, sequence_number, .. } => {
                assert_eq!(identifier, 0x42);
                assert_eq!(sequence_number, 1);
            }
            _ => panic!("expected EchoRequest"),
        }
    }
}
