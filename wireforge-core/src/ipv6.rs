//! IPv6 packet parser and builder.

use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv6Addr;

use crate::types::IpProtocol;
use crate::util::{read_u16be, read_u32be, write_u16be, write_u32be, BuildError};

/// IPv6 fixed header length (40 bytes).
pub const IPV6_HEADER_LEN: usize = 40;

/// Maximum extension header chain depth before we stop (prevents loops).
const MAX_EXTENSION_DEPTH: usize = 8;

/// Zero-copy IPv6 packet parser.
#[derive(Debug, Clone)]
pub struct Ipv6Packet<'a> {
    buf: &'a [u8],
}

impl<'a> Ipv6Packet<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < IPV6_HEADER_LEN {
            return None;
        }
        Some(Self { buf })
    }

    #[inline]
    pub fn version(&self) -> u8 {
        self.buf[0] >> 4
    }

    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((self.buf[0] & 0x0F) << 4) | (self.buf[1] >> 4)
    }

    #[inline]
    pub fn flow_label(&self) -> u32 {
        read_u32be(&self.buf[..4]) & 0x000F_FFFF
    }

    #[inline]
    pub fn payload_length(&self) -> u16 {
        read_u16be(&self.buf[4..6])
    }

    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.buf[6])
    }

    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.buf[7]
    }

    #[inline]
    pub fn source(&self) -> Ipv6Addr {
        let b: [u8; 16] = self.buf[8..24].try_into().unwrap();
        Ipv6Addr::from(b)
    }

    #[inline]
    pub fn destination(&self) -> Ipv6Addr {
        let b: [u8; 16] = self.buf[24..40].try_into().unwrap();
        Ipv6Addr::from(b)
    }

    /// Iterate over IPv6 extension headers.
    pub fn extension_headers(&self) -> Ipv6ExtensionHeadersIter<'a> {
        Ipv6ExtensionHeadersIter {
            next_header: self.next_header(),
            data: &self.buf[IPV6_HEADER_LEN..],
            depth: 0,
        }
    }

    /// The final upper-layer protocol after skipping all extension headers.
    pub fn final_protocol(&self) -> IpProtocol {
        let mut next = self.next_header();
        let mut remaining = &self.buf[IPV6_HEADER_LEN..];
        for _ in 0..MAX_EXTENSION_DEPTH {
            if !is_extension_header(next) {
                return next;
            }
            if remaining.len() < 2 {
                break;
            }
            let hdr_len = extension_header_len(next, remaining);
            if hdr_len == 0 {
                break;
            }
            next = IpProtocol::from(remaining[0]);
            if remaining.len() < hdr_len {
                break;
            }
            remaining = &remaining[hdr_len..];
        }
        next
    }

    /// Payload after all extension headers.
    pub fn payload(&self) -> &'a [u8] {
        let mut remaining = &self.buf[IPV6_HEADER_LEN..];
        let mut next = self.next_header();
        for _ in 0..MAX_EXTENSION_DEPTH {
            if !is_extension_header(next) {
                return remaining;
            }
            if remaining.len() < 2 {
                return &[];
            }
            let hdr_len = extension_header_len(next, remaining);
            if remaining.len() < hdr_len {
                return &[];
            }
            next = IpProtocol::from(remaining[0]);
            remaining = &remaining[hdr_len..];
        }
        remaining
    }
}

fn is_extension_header(proto: IpProtocol) -> bool {
    matches!(proto, IpProtocol::Unknown(0 | 43 | 44 | 60))
}

fn extension_header_len(proto: IpProtocol, data: &[u8]) -> usize {
    match proto {
        IpProtocol::Unknown(0 | 60) => (data[1] as usize + 1) * 8,
        IpProtocol::Unknown(43) => (data[1] as usize + 1) * 8,
        IpProtocol::Unknown(44) => 8,
        _ => 0,
    }
}

/// IPv6 extension header variant.
#[derive(Debug, Clone)]
pub enum Ipv6ExtensionHeader<'a> {
    HopByHop { next_header: IpProtocol, data: &'a [u8] },
    Routing { next_header: IpProtocol, routing_type: u8, segments_left: u8, data: &'a [u8] },
    Fragment { next_header: IpProtocol, fragment_offset: u16, more_fragments: bool, id: u32 },
    Destination { next_header: IpProtocol, data: &'a [u8] },
}

/// Iterator over IPv6 extension headers.
pub struct Ipv6ExtensionHeadersIter<'a> {
    next_header: IpProtocol,
    data: &'a [u8],
    depth: usize,
}

impl<'a> Iterator for Ipv6ExtensionHeadersIter<'a> {
    type Item = Ipv6ExtensionHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.depth >= MAX_EXTENSION_DEPTH || !is_extension_header(self.next_header) {
            return None;
        }
        if self.data.len() < 2 {
            return None;
        }

        let current_next = IpProtocol::from(self.data[0]);
        let hdr_len = extension_header_len(self.next_header, self.data);
        if self.data.len() < hdr_len || hdr_len == 0 {
            return None;
        }

        let hdr_data = &self.data[..hdr_len];
        let item = match self.next_header {
            IpProtocol::Unknown(0) => Ipv6ExtensionHeader::HopByHop {
                next_header: current_next,
                data: hdr_data,
            },
            IpProtocol::Unknown(43) => Ipv6ExtensionHeader::Routing {
                next_header: current_next,
                routing_type: hdr_data[2],
                segments_left: hdr_data[3],
                data: hdr_data,
            },
            IpProtocol::Unknown(44) => {
                let offset = read_u16be(&hdr_data[2..4]);
                Ipv6ExtensionHeader::Fragment {
                    next_header: current_next,
                    fragment_offset: (offset >> 3) & 0x1FFF,
                    more_fragments: offset & 0x01 != 0,
                    id: read_u32be(&hdr_data[4..8]),
                }
            }
            IpProtocol::Unknown(60) => Ipv6ExtensionHeader::Destination {
                next_header: current_next,
                data: hdr_data,
            },
            _ => return None,
        };

        self.next_header = current_next;
        self.data = &self.data[hdr_len..];
        self.depth += 1;

        Some(item)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub struct Ipv6PacketBuilder {
    buf: Vec<u8>,
    ext_headers: Vec<(IpProtocol, Vec<u8>)>,
    payload: Option<Vec<u8>>,
}

impl Default for Ipv6PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv6PacketBuilder {
    pub fn new() -> Self {
        let mut buf = vec![0u8; IPV6_HEADER_LEN];
        buf[0] = 0x60; // version=6
        Self { buf, ext_headers: Vec::new(), payload: None }
    }

    pub fn traffic_class(mut self, tc: u8) -> Self {
        self.buf[0] = (self.buf[0] & 0xF0) | (tc >> 4);
        self.buf[1] = (tc & 0x0F) << 4 | (self.buf[1] & 0x0F);
        self
    }

    pub fn flow_label(mut self, label: u32) -> Self {
        let val = read_u32be(&self.buf[..4]);
        let updated = (val & 0xFFF0_0000) | (label & 0x000F_FFFF);
        write_u32be(&mut self.buf[..4], updated);
        self
    }

    pub fn next_header(mut self, proto: IpProtocol) -> Self {
        self.buf[6] = proto.into();
        self
    }

    pub fn hop_limit(mut self, hl: u8) -> Self {
        self.buf[7] = hl;
        self
    }

    pub fn source(mut self, addr: Ipv6Addr) -> Self {
        self.buf[8..24].copy_from_slice(&addr.octets());
        self
    }

    pub fn destination(mut self, addr: Ipv6Addr) -> Self {
        self.buf[24..40].copy_from_slice(&addr.octets());
        self
    }

    pub fn add_extension_header(mut self, proto: IpProtocol, data: &[u8]) -> Self {
        // Fragment header is always 8 bytes per RFC 8200.
        if proto == IpProtocol::Unknown(44) && data.len() != 8 {
            return self;
        }
        // Minimum 2 bytes (next_header + hdr_ext_len), practical minimum is 8.
        if data.len() < 2 {
            return self;
        }
        self.ext_headers.push((proto, data.to_vec()));
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Result<Self, BuildError> {
        if data.len() > 65535 {
            return Err(BuildError::PayloadTooLarge { max: 65535, actual: data.len() });
        }
        self.payload = Some(data.to_vec());
        Ok(self)
    }

    pub fn build(mut self) -> Vec<u8> {
        // Cap extension headers at MAX_EXTENSION_DEPTH to match parser limits.
        if self.ext_headers.len() > MAX_EXTENSION_DEPTH {
            self.ext_headers.truncate(MAX_EXTENSION_DEPTH);
        }

        let final_proto: u8 = self.buf[6];

        let mut total_ext_len = 0usize;
        let mut ext_data = Vec::new();

        // Build extension header chain: each header's next_header field
        // points to the next header in the chain (or the final upper-layer proto).
        if !self.ext_headers.is_empty() {
            // Fixed header's next_header → first extension header
            self.buf[6] = self.ext_headers[0].0.into();

            for i in 0..self.ext_headers.len() {
                let (_proto, ref data) = self.ext_headers[i];
                let mut hdr = Vec::with_capacity(data.len());
                hdr.push(if i + 1 < self.ext_headers.len() {
                    self.ext_headers[i + 1].0.into()
                } else {
                    final_proto
                });
                hdr.extend_from_slice(&data[1..]); // skip the first byte of data (next_header)
                ext_data.extend_from_slice(&hdr);
                total_ext_len += hdr.len();
            }
        }

        let payload_len = total_ext_len + self.payload.as_ref().map_or(0, |p| p.len());
        write_u16be(&mut self.buf[4..6], payload_len as u16);

        let mut packet = self.buf;
        packet.extend_from_slice(&ext_data);
        if let Some(p) = self.payload {
            packet.extend_from_slice(&p);
        }
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // IPv6 header: src=::1, dst=::1, next=ICMPv6, hop_limit=64
    const SAMPLE_IPV6: &[u8] = &[
        0x60, 0x00, 0x00, 0x00, // version, TC, flow label
        0x00, 0x08, // payload length: 8
        0x3A, // next header: ICMPv6 (58)
        0x40, // hop limit: 64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // src: ::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dst: ::1
    ];

    #[test]
    fn parse_ipv6() {
        let pkt = Ipv6Packet::new(SAMPLE_IPV6).unwrap();
        assert_eq!(pkt.version(), 6);
        assert_eq!(pkt.next_header(), IpProtocol::Icmpv6);
        assert_eq!(pkt.hop_limit(), 64);
        assert_eq!(pkt.source(), Ipv6Addr::LOCALHOST);
        assert_eq!(pkt.destination(), Ipv6Addr::LOCALHOST);
        assert_eq!(pkt.payload_length(), 8);
    }

    #[test]
    fn parse_too_short() {
        assert!(Ipv6Packet::new(&[0u8; 39]).is_none());
        assert!(Ipv6Packet::new(&[]).is_none());
    }

    #[test]
    fn build_and_parse_roundtrip() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let pkt_bytes = Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .hop_limit(128)
            .next_header(IpProtocol::Tcp)
            .payload(&[0xAA, 0xBB])
            .unwrap()
            .build();

        let pkt = Ipv6Packet::new(&pkt_bytes).unwrap();
        assert_eq!(pkt.source(), src);
        assert_eq!(pkt.destination(), dst);
        assert_eq!(pkt.hop_limit(), 128);
        assert_eq!(pkt.next_header(), IpProtocol::Tcp);
        assert_eq!(pkt.payload(), &[0xAA, 0xBB]);
    }

    #[test]
    fn no_ext_headers() {
        let pkt = Ipv6Packet::new(SAMPLE_IPV6).unwrap();
        let headers: Vec<_> = pkt.extension_headers().collect();
        assert!(headers.is_empty());
        assert_eq!(pkt.final_protocol(), IpProtocol::Icmpv6);
    }

    /// Build an IPv6 packet with a Hop-by-Hop extension header, then parse it back.
    #[test]
    fn single_ext_header_hop_by_hop() {
        // Hop-by-Hop: next_header=ICMPv6, hdr_ext_len=0 (8 bytes), padding
        let hbh_data: &[u8] = &[
            0x3A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let payload = &[0xAA, 0xBB, 0xCC, 0xDD];
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        let pkt_bytes = Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .hop_limit(64)
            .next_header(IpProtocol::Icmpv6)
            .add_extension_header(IpProtocol::Unknown(0), hbh_data)
            .payload(payload)
            .unwrap()
            .build();

        let pkt = Ipv6Packet::new(&pkt_bytes).unwrap();
        assert_eq!(pkt.next_header(), IpProtocol::Unknown(0));
        assert_eq!(pkt.final_protocol(), IpProtocol::Icmpv6);
        assert_eq!(pkt.payload(), payload);

        let ext: Vec<_> = pkt.extension_headers().collect();
        assert_eq!(ext.len(), 1);
        match &ext[0] {
            Ipv6ExtensionHeader::HopByHop { next_header, .. } => {
                assert_eq!(*next_header, IpProtocol::Icmpv6);
            }
            _ => panic!("expected HopByHop"),
        }
    }

    /// IPv6 with a 3-extension header chain: HopByHop → Routing → Fragment → TCP.
    #[test]
    fn multi_ext_header_chain() {
        let hbh: &[u8] = &[0x2B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // next=Routing(43)
        let routing: &[u8] = &[0x2C, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]; // next=Fragment(44), hdr_ext_len=0 (8 bytes), routing_type=0, segments_left=2
        let fragment: &[u8] = &[0x06, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x42]; // next=TCP(6), offset=1 (8 bytes), MF=1

        let pkt_bytes = Ipv6PacketBuilder::new()
            .source(Ipv6Addr::LOCALHOST)
            .destination(Ipv6Addr::LOCALHOST)
            .next_header(IpProtocol::Tcp)
            .add_extension_header(IpProtocol::Unknown(0), hbh)
            .add_extension_header(IpProtocol::Unknown(43), routing)
            .add_extension_header(IpProtocol::Unknown(44), fragment)
            .payload(&[0x01, 0x02])
            .unwrap()
            .build();

        let pkt = Ipv6Packet::new(&pkt_bytes).unwrap();
        assert_eq!(pkt.final_protocol(), IpProtocol::Tcp);

        let ext: Vec<_> = pkt.extension_headers().collect();
        assert_eq!(ext.len(), 3);
        assert!(matches!(ext[0], Ipv6ExtensionHeader::HopByHop { .. }));
        match &ext[1] {
            Ipv6ExtensionHeader::Routing { routing_type, segments_left, .. } => {
                assert_eq!(*routing_type, 0);
                assert_eq!(*segments_left, 2);
            }
            _ => panic!("expected Routing"),
        }
        match &ext[2] {
            Ipv6ExtensionHeader::Fragment { fragment_offset, more_fragments, id, .. } => {
                assert_eq!(*fragment_offset, 1);
                assert!(more_fragments);
                assert_eq!(*id, 0x42);
            }
            _ => panic!("expected Fragment"),
        }
    }

    /// Verify the max-depth guard: extension header chain with 8+ hops should stop.
    #[test]
    fn extension_header_depth_limit() {
        // Build a packet with 9 HopByHop headers chained to test depth limit.
        // hdr_ext_len=0 means 8 bytes per header.
        let mut pkt_bytes = Ipv6PacketBuilder::new()
            .source(Ipv6Addr::LOCALHOST)
            .destination(Ipv6Addr::LOCALHOST)
            .next_header(IpProtocol::Tcp);
        for _ in 0..9 {
            pkt_bytes = pkt_bytes.add_extension_header(
                IpProtocol::Unknown(0),
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            );
        }
        let pkt_bytes = pkt_bytes.payload(&[0x99]).unwrap().build();

        let pkt = Ipv6Packet::new(&pkt_bytes).unwrap();
        // Iterator should stop at depth 8; final_protocol will be Unknown(0) (next to 9th).
        let count = pkt.extension_headers().count();
        assert_eq!(count, 8, "iterator should stop at MAX_EXTENSION_DEPTH (8)");
    }

    /// Builder silently drops extension headers with invalid data (too short or wrong Fragment length).
    #[test]
    fn builder_rejects_invalid_ext_header_data() {
        // Fragment header must be exactly 8 bytes; shorter data is dropped.
        let pkt = Ipv6PacketBuilder::new()
            .source(Ipv6Addr::LOCALHOST)
            .destination(Ipv6Addr::LOCALHOST)
            .next_header(IpProtocol::Tcp)
            .add_extension_header(IpProtocol::Unknown(44), &[0x06, 0x00, 0x00]) // only 3 bytes
            .payload(&[0xAA])
            .unwrap()
            .build();
        let parsed = Ipv6Packet::new(&pkt).unwrap();
        assert_eq!(parsed.extension_headers().count(), 0);

        // Data shorter than 2 bytes is dropped.
        let pkt = Ipv6PacketBuilder::new()
            .source(Ipv6Addr::LOCALHOST)
            .destination(Ipv6Addr::LOCALHOST)
            .next_header(IpProtocol::Tcp)
            .add_extension_header(IpProtocol::Unknown(0), &[0x06]) // only 1 byte
            .payload(&[0xAA])
            .unwrap()
            .build();
        let parsed = Ipv6Packet::new(&pkt).unwrap();
        assert_eq!(parsed.extension_headers().count(), 0);
    }

    /// Build and parse roundtrip with valid Fragment extension header (exactly 8 bytes).
    #[test]
    fn builder_fragment_ext_header_roundtrip() {
        let frag: &[u8] = &[0x06, 0x00, 0x00, 0x09, 0x12, 0x34, 0x56, 0x78];
        let pkt = Ipv6PacketBuilder::new()
            .source(Ipv6Addr::LOCALHOST)
            .destination(Ipv6Addr::LOCALHOST)
            .next_header(IpProtocol::Tcp)
            .add_extension_header(IpProtocol::Unknown(44), frag)
            .payload(&[0xCC])
            .unwrap()
            .build();
        let parsed = Ipv6Packet::new(&pkt).unwrap();
        let ext: Vec<_> = parsed.extension_headers().collect();
        assert_eq!(ext.len(), 1);
        match &ext[0] {
            Ipv6ExtensionHeader::Fragment { fragment_offset, more_fragments, id, .. } => {
                assert_eq!(*fragment_offset, 1);
                assert!(more_fragments);
                assert_eq!(*id, 0x12345678);
            }
            _ => panic!("expected Fragment"),
        }
    }

    /// Parse a manually constructed IPv6 packet with a single extension header.
    #[test]
    fn parse_single_ext_header() {
        // Construct manually: fixed header + HopByHop + payload
        let mut data = vec![
            0x60, 0x00, 0x00, 0x00, // version, TC, flow label
            0x00, 0x00, // payload_length (will fix up)
            0x00, // next_header = HopByHop (0)
            0x40, // hop_limit = 64
            // src: ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // dst: ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // HopByHop: next=ICMPv6(58), hdr_ext_len=0, padding
            0x3A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // payload
            0xAA, 0xBB,
        ];
        // Fix payload_length = 8 (HBH) + 2 (payload) = 10
        data[4] = 0x00;
        data[5] = 10;

        let pkt = Ipv6Packet::new(&data).unwrap();
        assert_eq!(pkt.next_header(), IpProtocol::Unknown(0));
        assert_eq!(pkt.final_protocol(), IpProtocol::Icmpv6);
        assert_eq!(pkt.payload(), &[0xAA, 0xBB]);

        let ext: Vec<_> = pkt.extension_headers().collect();
        assert_eq!(ext.len(), 1);
    }
}
