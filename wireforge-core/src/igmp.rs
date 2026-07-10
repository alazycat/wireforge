//! IGMP (Internet Group Management Protocol) packet parser and builder.
//! Supports IGMPv1 (RFC 1112), IGMPv2 (RFC 2236), and IGMPv3 basic (RFC 3376).

use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::util::{internet_checksum, seal_internet_checksum, read_u16be, PacketBuilder};

pub const IGMP_MIN_LEN: usize = 8;

// Message type constants
const TYPE_QUERY: u8 = 0x11;
const TYPE_REPORT_V1: u8 = 0x12;
const TYPE_REPORT_V2: u8 = 0x16;
const TYPE_LEAVE_V2: u8 = 0x17;
const TYPE_REPORT_V3: u8 = 0x22;

/// Parsed IGMP message variant.
#[derive(Debug, Clone)]
pub enum IgmpMessage<'a> {
    /// IGMPv1 Membership Query (general query to 0.0.0.0).
    MembershipQueryV1 {
        group_address: Ipv4Addr,
    },
    /// IGMPv2 Membership Query (group-specific or general with max response time).
    MembershipQueryV2 {
        max_response: u8,
        group_address: Ipv4Addr,
    },
    /// IGMPv3 Membership Query with robust-ness, interval, and source list.
    MembershipQueryV3 {
        max_response: u8,
        group_address: Ipv4Addr,
        /// Suppress Router-Side Processing flag
        supress_router_side: bool,
        /// Querier's Robustness Variable
        robustness: u8,
        /// Querier's Query Interval Code
        query_interval: u8,
        /// Source addresses (N × 4 bytes)
        sources: &'a [u8],
    },
    MembershipReportV1 {
        group_address: Ipv4Addr,
    },
    MembershipReportV2 {
        max_response: u8,
        group_address: Ipv4Addr,
    },
    LeaveGroup {
        max_response: u8,
        group_address: Ipv4Addr,
    },
    MembershipReportV3 {
        group_records: &'a [u8],
    },
    Unknown {
        type_: u8,
        data: &'a [u8],
    },
}

/// Zero-copy IGMP packet parser.
#[derive(Debug, Clone)]
pub struct IgmpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> IgmpPacket<'a> {
    crate::parser_new!(IGMP_MIN_LEN);

    /// Raw bytes backing this packet.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] { self.buf }

    #[inline] pub fn type_(&self) -> u8 { self.buf[0] }
    #[inline] pub fn max_response(&self) -> u8 { self.buf[1] }
    #[inline] pub fn checksum(&self) -> u16 { read_u16be(&self.buf[2..4]) }
    #[inline] pub fn group_address(&self) -> Ipv4Addr {
        let b = &self.buf[4..8];
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    }
    #[inline] pub fn payload(&self) -> &'a [u8] { &self.buf[IGMP_MIN_LEN..] }

    pub fn verify_checksum(&self) -> bool {
        internet_checksum(self.buf) == 0
    }

    pub fn message(&self) -> IgmpMessage<'a> {
        let payload = self.payload();
        match self.type_() {
            TYPE_QUERY => {
                let grp = self.group_address();
                let max_resp = self.max_response();
                // v3 query: payload contains reserved(2) + #sources(2) + sources(N×4)
                if payload.len() >= 4 && (payload.len() - 4).is_multiple_of(4) {
                    let sr_flags = payload[0];
                    IgmpMessage::MembershipQueryV3 {
                        max_response: max_resp,
                        group_address: grp,
                        supress_router_side: (sr_flags & 0x08) != 0,
                        robustness: sr_flags & 0x07,
                        query_interval: payload[1],
                        sources: &payload[4..],
                    }
                } else if grp == Ipv4Addr::UNSPECIFIED && max_resp == 0 {
                    IgmpMessage::MembershipQueryV1 {
                        group_address: grp,
                    }
                } else {
                    IgmpMessage::MembershipQueryV2 {
                        max_response: max_resp,
                        group_address: grp,
                    }
                }
            }
            TYPE_REPORT_V1 => IgmpMessage::MembershipReportV1 {
                group_address: self.group_address(),
            },
            TYPE_REPORT_V2 => IgmpMessage::MembershipReportV2 {
                max_response: self.max_response(),
                group_address: self.group_address(),
            },
            TYPE_LEAVE_V2 => IgmpMessage::LeaveGroup {
                max_response: self.max_response(),
                group_address: self.group_address(),
            },
            TYPE_REPORT_V3 => IgmpMessage::MembershipReportV3 {
                group_records: payload,
            },
            t => IgmpMessage::Unknown {
                type_: t,
                data: payload,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub struct IgmpPacketBuilder {
    buf: Vec<u8>,
    payload: Option<Vec<u8>>,
}

impl Default for IgmpPacketBuilder {
    fn default() -> Self { Self::new(TYPE_QUERY, 0) }
}

impl IgmpPacketBuilder {
    pub fn new(type_: u8, max_response: u8) -> Self {
        let mut buf = vec![0u8; IGMP_MIN_LEN];
        buf[0] = type_;
        buf[1] = max_response;
        Self { buf, payload: None }
    }

    pub fn query_v1() -> Self { Self::new(TYPE_QUERY, 0) }
    pub fn query_v2(max_resp: u8) -> Self { Self::new(TYPE_QUERY, max_resp) }
    pub fn report_v2(addr: Ipv4Addr) -> Self {
        let mut s = Self::new(TYPE_REPORT_V2, 0);
        s.buf[4..8].copy_from_slice(&addr.octets());
        s
    }
    pub fn leave_v2(addr: Ipv4Addr) -> Self {
        let mut s = Self::new(TYPE_LEAVE_V2, 0);
        s.buf[4..8].copy_from_slice(&addr.octets());
        s
    }

    pub fn group_address(mut self, addr: Ipv4Addr) -> Self {
        self.buf[4..8].copy_from_slice(&addr.octets());
        self
    }

    pub fn max_response(mut self, v: u8) -> Self {
        self.buf[1] = v;
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }

    pub fn build(self) -> Vec<u8> {
        <Self as PacketBuilder>::build(self)
    }
}

impl PacketBuilder for IgmpPacketBuilder {
    type Output = Vec<u8>;

    fn build(self) -> Vec<u8> {
        let mut pkt = self.buf;
        if let Some(p) = self.payload {
            pkt.extend_from_slice(&p);
        }
        seal_internet_checksum(&mut pkt, 2);
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
    fn parse_v1_query() {
        let data = &[0x11u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let pkt = IgmpPacket::new(data).unwrap();
        assert_eq!(pkt.type_(), TYPE_QUERY);
        match pkt.message() {
            IgmpMessage::MembershipQueryV1 { group_address } => {
                assert_eq!(group_address, Ipv4Addr::UNSPECIFIED);
            }
            _ => panic!("expected MembershipQueryV1"),
        }
    }

    #[test]
    fn parse_v2_query() {
        let mut data = vec![0x11u8, 100, 0x00, 0x00];
        data.extend_from_slice(&[224u8, 0, 0, 1]); // group=224.0.0.1
        let pkt = IgmpPacket::new(&data).unwrap();
        assert_eq!(pkt.max_response(), 100);
        match pkt.message() {
            IgmpMessage::MembershipQueryV2 { max_response, group_address } => {
                assert_eq!(max_response, 100);
                let _ = group_address;
            }
            _ => panic!("expected MembershipQueryV2"),
        }
    }

    #[test]
    fn parse_v2_report() {
        let data = &[0x16u8, 0x00, 0x00, 0x00, 224, 0, 0, 1];
        let pkt = IgmpPacket::new(data).unwrap();
        match pkt.message() {
            IgmpMessage::MembershipReportV2 { group_address, .. } => {
                assert_eq!(group_address, Ipv4Addr::new(224, 0, 0, 1));
            }
            _ => panic!("expected MembershipReportV2"),
        }
    }

    #[test]
    fn parse_v2_leave() {
        let data = &[0x17u8, 0x00, 0x00, 0x00, 224, 0, 0, 1];
        let pkt = IgmpPacket::new(data).unwrap();
        match pkt.message() {
            IgmpMessage::LeaveGroup { group_address, .. } => {
                assert_eq!(group_address, Ipv4Addr::new(224, 0, 0, 1));
            }
            _ => panic!("expected LeaveGroup"),
        }
    }

    #[test]
    fn parse_too_short() {
        assert!(IgmpPacket::new(&[]).is_none());
        assert!(IgmpPacket::new(&[0u8; 7]).is_none());
    }

    #[test]
    fn verify_checksum() {
        let pkt = IgmpPacketBuilder::query_v1().build();
        let parsed = IgmpPacket::new(&pkt).unwrap();
        assert!(parsed.verify_checksum());
    }

    #[test]
    fn build_roundtrip() {
        let addr = Ipv4Addr::new(224, 0, 0, 1);
        let pkt = IgmpPacketBuilder::report_v2(addr)
            .payload(&[0xAA, 0xBB])
            .build();
        let parsed = IgmpPacket::new(&pkt).unwrap();
        assert_eq!(parsed.type_(), TYPE_REPORT_V2);
        assert_eq!(parsed.group_address(), addr);
        assert_eq!(parsed.payload(), &[0xAA, 0xBB]);
        assert!(parsed.verify_checksum());
    }
}
