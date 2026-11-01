//! IPv4 packet parser and builder.

use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::types::IpProtocol;
use crate::util::{
    internet_checksum, read_u16be, read_u32be, seal_internet_checksum, write_u16be, write_u32be,
    BuildError, PacketBuilder,
};

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

    /// Raw bytes backing this packet.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
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

    /// Iterate over the typed IP options in the header.
    pub fn options_iter(&self) -> Ipv4OptionsIter<'a> {
        Ipv4OptionsIter::new(self.options())
    }
}

// ---------------------------------------------------------------------------
// IP options
// ---------------------------------------------------------------------------

/// IPv4 option type numbers.
mod opt {
    pub const END: u8 = 0;
    pub const NOP: u8 = 1;
    pub const RECORD_ROUTE: u8 = 7;
    pub const TIMESTAMP: u8 = 68;
    pub const SECURITY: u8 = 130;
    pub const LSR: u8 = 131;
    pub const SSR: u8 = 137;
    pub const ROUTER_ALERT: u8 = 148;
}

/// A typed IPv4 option.
///
/// The borrowed variants reference the option payload (everything after the
/// kind/length bytes) in the source buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4Option<'a> {
    /// Option type 0 — terminates the option list.
    EndOfOptions,
    /// Option type 1 — no operation (padding).
    NoOperation,
    /// Option type 7 — record route.
    RecordRoute {
        /// Byte offset (starting at 4) of the next free route slot.
        pointer: u8,
        /// Route area; recorded hops occupy whole 4-byte slots.
        route: &'a [u8],
    },
    /// Option type 68 — internet timestamp.
    Timestamp {
        /// Byte offset (starting at 5) of the next free timestamp slot.
        pointer: u8,
        /// Number of overflowed slots (0–15).
        overflow: u8,
        /// Timestamp format flags (0–15).
        flags: u8,
        /// Timestamp area (raw, format depends on `flags`).
        data: &'a [u8],
    },
    /// Option type 130 — security.
    Security {
        security: u16,
        compartments: u16,
        handling: u16,
        tcc: u16,
    },
    /// Option type 131 — loose source route.
    LooseSourceRoute {
        pointer: u8,
        route: &'a [u8],
    },
    /// Option type 137 — strict source route.
    StrictSourceRoute {
        pointer: u8,
        route: &'a [u8],
    },
    /// Option type 148 — router alert (RFC 2113).
    RouterAlert,
    /// Any other or malformed option.
    Unknown {
        kind: u8,
        data: &'a [u8],
    },
}

impl Ipv4Option<'_> {
    /// Number of bytes this option occupies on the wire.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::EndOfOptions => 1,
            Self::NoOperation => 1,
            Self::RecordRoute { route, .. }
            | Self::LooseSourceRoute { route, .. }
            | Self::StrictSourceRoute { route, .. } => 3 + route.len(),
            Self::Timestamp { data, .. } => 4 + data.len(),
            Self::Security { .. } => 11,
            Self::RouterAlert => 4,
            Self::Unknown { data, .. } => 2 + data.len(),
        }
    }

    /// Append the wire encoding of this option to `out`.
    ///
    /// Returns an error if a route area is not a multiple of 4 bytes.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), BuildError> {
        match self {
            Self::EndOfOptions => out.push(opt::END),
            Self::NoOperation => out.push(opt::NOP),
            Self::RecordRoute { pointer, route }
            | Self::LooseSourceRoute { pointer, route }
            | Self::StrictSourceRoute { pointer, route } => {
                let kind = match self {
                    Self::RecordRoute { .. } => opt::RECORD_ROUTE,
                    Self::LooseSourceRoute { .. } => opt::LSR,
                    _ => opt::SSR,
                };
                if !route.len().is_multiple_of(4) {
                    return Err(BuildError::InvalidField {
                        field: "options",
                        reason: "route area must be a multiple of 4 bytes",
                    });
                }
                out.push(kind);
                out.push(3 + route.len() as u8);
                out.push(*pointer);
                out.extend_from_slice(route);
            }
            Self::Timestamp {
                pointer,
                overflow,
                flags,
                data,
            } => {
                out.push(opt::TIMESTAMP);
                out.push(4 + data.len() as u8);
                out.push(*pointer);
                out.push((*overflow & 0x0F) << 4 | (*flags & 0x0F));
                out.extend_from_slice(data);
            }
            Self::Security {
                security,
                compartments,
                handling,
                tcc,
            } => {
                out.push(opt::SECURITY);
                out.push(11);
                out.extend_from_slice(&security.to_be_bytes());
                out.extend_from_slice(&compartments.to_be_bytes());
                out.extend_from_slice(&handling.to_be_bytes());
                out.extend_from_slice(&tcc.to_be_bytes());
                out.push(0); // padding
            }
            Self::RouterAlert => {
                out.push(opt::ROUTER_ALERT);
                out.push(4);
                out.extend_from_slice(&0u16.to_be_bytes());
            }
            Self::Unknown { kind, data } => {
                out.push(*kind);
                out.push(2 + data.len() as u8);
                out.extend_from_slice(data);
            }
        }
        Ok(())
    }
}

/// Iterator over the typed IP options in an IPv4 header.
#[derive(Debug, Clone)]
pub struct Ipv4OptionsIter<'a> {
    data: &'a [u8],
}

impl<'a> Ipv4OptionsIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for Ipv4OptionsIter<'a> {
    type Item = Ipv4Option<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&kind, rest) = self.data.split_first()?;
        match kind {
            opt::END => {
                self.data = &[];
                Some(Ipv4Option::EndOfOptions)
            }
            opt::NOP => {
                self.data = rest;
                Some(Ipv4Option::NoOperation)
            }
            _ => {
                let len = match rest.first() {
                    Some(&len) if len >= 2 && len as usize <= rest.len() => len as usize,
                    // Malformed option: report everything remaining as unknown.
                    _ => {
                        let data = self.data;
                        self.data = &[];
                        return Some(Ipv4Option::Unknown { kind, data });
                    }
                };
                let body = &self.data[2..len];
                self.data = &self.data[len..];
                let option = match kind {
                    opt::RECORD_ROUTE => Ipv4Option::RecordRoute {
                        pointer: body.first().copied().unwrap_or(0),
                        route: body.get(1..).unwrap_or(&[]),
                    },
                    opt::TIMESTAMP => Ipv4Option::Timestamp {
                        pointer: body.first().copied().unwrap_or(0),
                        overflow: body.get(1).copied().unwrap_or(0) >> 4,
                        flags: body.get(1).copied().unwrap_or(0) & 0x0F,
                        data: body.get(2..).unwrap_or(&[]),
                    },
                    opt::SECURITY if len >= 11 => Ipv4Option::Security {
                        security: read_u16be(&body[1..3]),
                        compartments: read_u16be(&body[3..5]),
                        handling: read_u16be(&body[5..7]),
                        tcc: read_u16be(&body[7..9]),
                    },
                    opt::LSR => Ipv4Option::LooseSourceRoute {
                        pointer: body.first().copied().unwrap_or(0),
                        route: body.get(1..).unwrap_or(&[]),
                    },
                    opt::SSR => Ipv4Option::StrictSourceRoute {
                        pointer: body.first().copied().unwrap_or(0),
                        route: body.get(1..).unwrap_or(&[]),
                    },
                    opt::ROUTER_ALERT => Ipv4Option::RouterAlert,
                    _ => Ipv4Option::Unknown {
                        kind,
                        data: body,
                    },
                };
                Some(option)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for IPv4 packets.
#[derive(Debug, Clone)]
pub struct Ipv4PacketBuilder {
    buf: Vec<u8>,
    options: Vec<u8>,
    payload: Option<Vec<u8>>,
}

/// Maximum IP options length in bytes (IHL max 15 → 60 − 20).
pub const IPV4_MAX_OPTIONS_LEN: usize = 40;

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
        Self {
            buf,
            options: Vec::new(),
            payload: None,
        }
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

    /// Set raw IPv4 options (kind/length/value format), replacing any
    /// previously configured options.
    ///
    /// The options are validated as a TLV stream and padded to a 4-byte
    /// boundary with End-of-Options (0x00) when built. IHL, total length and
    /// the header checksum are computed automatically.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if the options exceed 40 bytes or contain a
    /// truncated/invalid option.
    pub fn options(mut self, data: &[u8]) -> Result<Self, BuildError> {
        validate_options(data)?;
        if self.options.len() + data.len() > IPV4_MAX_OPTIONS_LEN {
            return Err(BuildError::PayloadTooLarge {
                max: IPV4_MAX_OPTIONS_LEN,
                actual: self.options.len() + data.len(),
            });
        }
        self.options.clear();
        self.options.extend_from_slice(data);
        Ok(self)
    }

    /// Append a typed IPv4 option.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if the option cannot be encoded (e.g. a route
    /// area that is not a multiple of 4) or if the total options exceed 40 bytes.
    pub fn add_option(mut self, option: &Ipv4Option<'_>) -> Result<Self, BuildError> {
        if self.options.len() + option.encoded_len() > IPV4_MAX_OPTIONS_LEN {
            return Err(BuildError::PayloadTooLarge {
                max: IPV4_MAX_OPTIONS_LEN,
                actual: self.options.len() + option.encoded_len(),
            });
        }
        option.encode_into(&mut self.options)?;
        Ok(self)
    }

    /// Convenience: append a Router Alert option (RFC 2113).
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if the total options exceed 40 bytes.
    pub fn router_alert(self) -> Result<Self, BuildError> {
        self.add_option(&Ipv4Option::RouterAlert)
    }

    /// Convenience: append a Record Route option.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] if `route` is not a multiple of 4 bytes or the
    /// total options exceed 40 bytes.
    pub fn record_route(self, pointer: u8, route: &[u8]) -> Result<Self, BuildError> {
        if !route.len().is_multiple_of(4) {
            return Err(BuildError::InvalidField {
                field: "options",
                reason: "route area must be a multiple of 4 bytes",
            });
        }
        self.add_option(&Ipv4Option::RecordRoute { pointer, route })
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
    pub fn build(self) -> Vec<u8> {
        <Self as PacketBuilder>::build(self)
    }
}

impl PacketBuilder for Ipv4PacketBuilder {
    type Output = Vec<u8>;

    fn build(mut self) -> Vec<u8> {
        // Pad options to a 4-byte boundary with End-of-Options and update IHL.
        while !self.options.len().is_multiple_of(4) {
            self.options.push(opt::END);
        }
        let header_len = IPV4_MIN_HEADER_LEN + self.options.len();
        self.buf[0] = 0x40 | (header_len / 4) as u8;

        let total_len = header_len + self.payload.as_ref().map_or(0, |p| p.len());
        write_u16be(&mut self.buf[2..4], total_len as u16);

        // Checksum covers the full header including options.
        self.buf.extend_from_slice(&self.options);
        seal_internet_checksum(&mut self.buf, 10);

        let mut packet = self.buf;
        if let Some(p) = self.payload {
            packet.extend_from_slice(&p);
        }
        packet
    }
}

/// Validate a raw IPv4 options TLV stream.
fn validate_options(data: &[u8]) -> Result<(), BuildError> {
    let mut rest = data;
    while !rest.is_empty() {
        let kind = rest[0];
        if kind == opt::END {
            break; // everything after EOL is padding
        }
        if kind == opt::NOP {
            rest = &rest[1..];
            continue;
        }
        let len = rest
            .get(1)
            .copied()
            .ok_or(BuildError::InvalidField {
                field: "options",
                reason: "truncated option header",
            })? as usize;
        if len < 2 {
            return Err(BuildError::InvalidField {
                field: "options",
                reason: "option length must be at least 2",
            });
        }
        if len > rest.len() {
            return Err(BuildError::InvalidField {
                field: "options",
                reason: "option length exceeds available bytes",
            });
        }
        rest = &rest[len..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real IPv4 header: 192.168.10.99 → 172.16.10.12, TCP, TTL=64
    const SAMPLE_IPV4: &[u8] = &[
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xAC, 0x10, 0x0A,
        0x63, 0xAC, 0x10, 0x0A, 0x0C,
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
        let mut data = vec![
            0x46u8, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8,
            0x01, 0x01, 0xC0, 0xA8, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04, // options
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

    #[test]
    fn build_with_router_alert() {
        let pkt_bytes = Ipv4PacketBuilder::new()
            .source(Ipv4Addr::new(10, 0, 0, 1))
            .destination(Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Udp)
            .router_alert()
            .unwrap()
            .payload(&[0xDE, 0xAD])
            .unwrap()
            .build();

        let pkt = Ipv4Packet::new(&pkt_bytes).unwrap();
        assert_eq!(pkt.ihl(), 6);
        assert_eq!(pkt.header_length(), 24);
        assert_eq!(pkt.options(), &[0x94, 0x04, 0x00, 0x00]);
        assert_eq!(pkt.payload(), &[0xDE, 0xAD]);
        assert!(pkt.verify_checksum());
    }

    #[test]
    fn build_with_raw_options() {
        let pkt_bytes = Ipv4PacketBuilder::new()
            .source(Ipv4Addr::new(10, 0, 0, 1))
            .destination(Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            // 3-byte option stream: NOP, NOP, NOP → padded to 4 with EOL
            .options(&[0x01, 0x01, 0x01])
            .unwrap()
            .build();

        let pkt = Ipv4Packet::new(&pkt_bytes).unwrap();
        assert_eq!(pkt.ihl(), 6);
        assert_eq!(pkt.options(), &[0x01, 0x01, 0x01, 0x00]);
        assert!(pkt.verify_checksum());

        let opts: Vec<_> = pkt.options_iter().collect();
        assert_eq!(
            opts,
            vec![
                Ipv4Option::NoOperation,
                Ipv4Option::NoOperation,
                Ipv4Option::NoOperation,
                Ipv4Option::EndOfOptions,
            ]
        );
    }

    #[test]
    fn build_with_record_route() {
        let route = [10, 0, 0, 1, 10, 0, 0, 2];
        let pkt_bytes = Ipv4PacketBuilder::new()
            .source(Ipv4Addr::new(10, 0, 0, 1))
            .destination(Ipv4Addr::new(10, 0, 0, 3))
            .protocol(IpProtocol::Udp)
            .record_route(4, &route)
            .unwrap()
            .build();

        let pkt = Ipv4Packet::new(&pkt_bytes).unwrap();
        // 11 bytes of options → padded to 12 → IHL=8
        assert_eq!(pkt.ihl(), 8);
        assert_eq!(pkt.options()[0], 7); // Record Route kind
        assert_eq!(pkt.options()[1], 11); // length
        assert!(pkt.verify_checksum());

        let opts: Vec<_> = pkt.options_iter().collect();
        // trailing EndOfOptions is the padding byte
        assert_eq!(
            opts,
            vec![
                Ipv4Option::RecordRoute {
                    pointer: 4,
                    route: &route,
                },
                Ipv4Option::EndOfOptions,
            ]
        );
    }

    #[test]
    fn options_typed_roundtrip() {
        let route = [0u8; 4];
        let pkt_bytes = Ipv4PacketBuilder::new()
            .source(Ipv4Addr::new(10, 0, 0, 1))
            .destination(Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Udp)
            .add_option(&Ipv4Option::RouterAlert)
            .unwrap()
            .add_option(&Ipv4Option::Timestamp {
                pointer: 5,
                overflow: 0,
                flags: 1,
                data: &[0u8, 0, 0, 42],
            })
            .unwrap()
            .add_option(&Ipv4Option::StrictSourceRoute { pointer: 4, route: &route })
            .unwrap()
            .build();

        let pkt = Ipv4Packet::new(&pkt_bytes).unwrap();
        // 4 + 8 + 7 = 19 bytes of options → padded to 20 → IHL=10
        assert_eq!(pkt.ihl(), 10);
        assert!(pkt.verify_checksum());

        let opts: Vec<_> = pkt.options_iter().collect();
        // trailing EndOfOptions is the padding byte
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0], Ipv4Option::RouterAlert);
        assert_eq!(
            opts[1],
            Ipv4Option::Timestamp {
                pointer: 5,
                overflow: 0,
                flags: 1,
                data: &[0u8, 0, 0, 42],
            }
        );
        assert_eq!(
            opts[2],
            Ipv4Option::StrictSourceRoute { pointer: 4, route: &route }
        );
    }

    #[test]
    fn options_reject_too_long() {
        let err = Ipv4PacketBuilder::new()
            .options(&[0x01; 41])
            .unwrap_err();
        assert!(matches!(err, BuildError::PayloadTooLarge { max: 40, actual: 41 }));
    }

    #[test]
    fn options_reject_truncated_tlv() {
        // kind=7 (Record Route) claims length 8 but only 1 byte follows
        let err = Ipv4PacketBuilder::new()
            .options(&[0x07, 0x08, 0x00])
            .unwrap_err();
        assert!(matches!(err, BuildError::InvalidField { field: "options", .. }));
    }

    #[test]
    fn options_reject_bad_route_alignment() {
        let err = Ipv4PacketBuilder::new()
            .record_route(4, &[0u8; 3])
            .unwrap_err();
        assert!(matches!(err, BuildError::InvalidField { field: "options", .. }));
    }

    #[test]
    fn parse_malformed_option_is_unknown() {
        // kind=99, length=8, but only 4 bytes of options present (IHL=6)
        let mut data = vec![0x46u8, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01, 0xC0, 0xA8, 0x01, 0x02,
            99, 8, 1, 2];
        let csum = internet_checksum(&data[..24]);
        data[10..12].copy_from_slice(&csum.to_be_bytes());

        let pkt = Ipv4Packet::new(&data).unwrap();
        let opts: Vec<_> = pkt.options_iter().collect();
        assert_eq!(
            opts,
            vec![Ipv4Option::Unknown {
                kind: 99,
                data: &[99u8, 8, 1, 2],
            }]
        );
    }

    #[test]
    fn mutable_packet_options_accessors() {
        let mut pkt_bytes = Ipv4PacketBuilder::new()
            .source(Ipv4Addr::new(10, 0, 0, 1))
            .destination(Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Udp)
            .router_alert()
            .unwrap()
            .build();

        {
            let mut pkt = MutableIpv4Packet::new(&mut pkt_bytes).unwrap();
            assert_eq!(pkt.options(), &[0x94, 0x04, 0x00, 0x00]);
            pkt.options_mut()[2..4].copy_from_slice(&0x1234u16.to_be_bytes());
            pkt.update_checksum();
        }

        let pkt = Ipv4Packet::new(&pkt_bytes).unwrap();
        assert_eq!(pkt.options(), &[0x94, 0x04, 0x12, 0x34]);
        assert!(pkt.verify_checksum());
    }
}

crate::impl_mutable_packet!(MutableIpv4Packet, IPV4_MIN_HEADER_LEN);

impl<'a> MutableIpv4Packet<'a> {
    fn view(&self) -> Ipv4Packet<'_> {
        Ipv4Packet::new(&*self.buf).expect("validated in MutableIpv4Packet::new")
    }

    fn payload_offset(&self) -> usize {
        self.view().header_length()
    }

    /// Header length in bytes (IHL × 4).
    pub fn header_length(&self) -> usize {
        self.view().header_length()
    }

    /// DSCP field.
    pub fn dscp(&self) -> u8 {
        self.view().dscp()
    }

    /// Set the DSCP field.
    pub fn set_dscp(&mut self, dscp: u8) {
        self.buf[1] = (self.buf[1] & 0x03) | ((dscp & 0x3F) << 2);
    }

    /// ECN field.
    pub fn ecn(&self) -> u8 {
        self.view().ecn()
    }

    /// Set the ECN field.
    pub fn set_ecn(&mut self, ecn: u8) {
        self.buf[1] = (self.buf[1] & 0xFC) | (ecn & 0x03);
    }

    /// Total packet length.
    pub fn total_length(&self) -> u16 {
        self.view().total_length()
    }

    /// Set the total packet length.
    pub fn set_total_length(&mut self, length: u16) {
        write_u16be(&mut self.buf[2..4], length);
    }

    /// Identification field.
    pub fn identification(&self) -> u16 {
        self.view().identification()
    }

    /// Set the identification field.
    pub fn set_identification(&mut self, id: u16) {
        write_u16be(&mut self.buf[4..6], id);
    }

    /// Whether the Don't Fragment flag is set.
    pub fn dont_fragment(&self) -> bool {
        self.view().dont_fragment()
    }

    /// Set the Don't Fragment flag.
    pub fn set_dont_fragment(&mut self, on: bool) {
        if on {
            self.buf[6] |= 0x40;
        } else {
            self.buf[6] &= !0x40;
        }
    }

    /// Whether the More Fragments flag is set.
    pub fn more_fragments(&self) -> bool {
        self.view().more_fragments()
    }

    /// Set the More Fragments flag.
    pub fn set_more_fragments(&mut self, on: bool) {
        if on {
            self.buf[6] |= 0x20;
        } else {
            self.buf[6] &= !0x20;
        }
    }

    /// Fragment offset.
    pub fn fragment_offset(&self) -> u16 {
        self.view().fragment_offset()
    }

    /// Set the fragment offset, preserving the flag bits.
    pub fn set_fragment_offset(&mut self, offset: u16) {
        let flags = read_u16be(&self.buf[6..8]) & 0xE000;
        write_u16be(&mut self.buf[6..8], flags | (offset & 0x1FFF));
    }

    /// Time to live.
    pub fn ttl(&self) -> u8 {
        self.view().ttl()
    }

    /// Set the time to live.
    pub fn set_ttl(&mut self, ttl: u8) {
        self.buf[8] = ttl;
    }

    /// Upper-layer protocol.
    pub fn protocol(&self) -> IpProtocol {
        self.view().protocol()
    }

    /// Set the upper-layer protocol.
    pub fn set_protocol(&mut self, protocol: IpProtocol) {
        self.buf[9] = protocol.into();
    }

    /// Header checksum.
    pub fn checksum(&self) -> u16 {
        self.view().checksum()
    }

    /// Set the header checksum directly.
    pub fn set_checksum(&mut self, checksum: u16) {
        write_u16be(&mut self.buf[10..12], checksum);
    }

    /// Source address.
    pub fn source(&self) -> Ipv4Addr {
        self.view().source()
    }

    /// Set the source address.
    pub fn set_source(&mut self, source: Ipv4Addr) {
        self.buf[12..16].copy_from_slice(&source.octets());
    }

    /// Destination address.
    pub fn destination(&self) -> Ipv4Addr {
        self.view().destination()
    }

    /// Set the destination address.
    pub fn set_destination(&mut self, destination: Ipv4Addr) {
        self.buf[16..20].copy_from_slice(&destination.octets());
    }

    /// Raw IP options bytes.
    pub fn options(&self) -> &[u8] {
        self.view().options()
    }

    /// Mutable raw IP options bytes (the header length stays unchanged).
    pub fn options_mut(&mut self) -> &mut [u8] {
        let hdr_len = self.view().header_length();
        &mut self.buf[IPV4_MIN_HEADER_LEN..hdr_len]
    }

    /// Recompute the IPv4 header checksum in place.
    pub fn update_checksum(&mut self) {
        let header_len = self.header_length();
        self.set_checksum(0);
        let checksum = internet_checksum(&self.buf[..header_len]);
        self.set_checksum(checksum);
    }
}
