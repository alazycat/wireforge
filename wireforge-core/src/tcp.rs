//! TCP packet parser and builder with option parsing.

use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::util::{pseudo_header_checksum, read_u16be, read_u32be, write_u16be, write_u32be};

pub const TCP_MIN_HEADER_LEN: usize = 20;

// TCP flag bit positions
const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;
const FLAG_URG: u8 = 0x20;

// TCP option kinds
const OPT_END: u8 = 0;
const OPT_NOOP: u8 = 1;
const OPT_MSS: u8 = 2;
const OPT_WINDOW_SCALE: u8 = 3;
const OPT_SACK_PERMITTED: u8 = 4;
const OPT_SACK: u8 = 5;
const OPT_TIMESTAMP: u8 = 8;

/// Parsed TCP option.
#[derive(Debug, Clone)]
pub enum TcpOption {
    EndOfList,
    NoOp,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(Vec<(u32, u32)>),
    Timestamp { ts_val: u32, ts_ecr: u32 },
    Unknown { kind: u8, data: Vec<u8> },
}

/// Iterator over TCP options in the header.
pub struct TcpOptionsIter<'a> {
    data: &'a [u8],
}

impl<'a> TcpOptionsIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = TcpOption;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let kind = self.data[0];
        match kind {
            OPT_END => {
                self.data = &[];
                Some(TcpOption::EndOfList)
            }
            OPT_NOOP => {
                self.data = &self.data[1..];
                Some(TcpOption::NoOp)
            }
            OPT_MSS => {
                if self.data.len() < 4 {
                    self.data = &[];
                    return Some(TcpOption::Unknown { kind, data: self.data.to_vec() });
                }
                let mss = read_u16be(&self.data[2..4]);
                self.data = &self.data[4..];
                Some(TcpOption::MaximumSegmentSize(mss))
            }
            OPT_WINDOW_SCALE => {
                if self.data.len() < 3 {
                    self.data = &[];
                    return Some(TcpOption::Unknown { kind, data: self.data.to_vec() });
                }
                let shift = self.data[2];
                self.data = &self.data[3..];
                Some(TcpOption::WindowScale(shift))
            }
            OPT_SACK_PERMITTED => {
                if self.data.len() < 2 {
                    self.data = &[];
                    return Some(TcpOption::Unknown { kind, data: self.data.to_vec() });
                }
                self.data = &self.data[2..];
                Some(TcpOption::SackPermitted)
            }
            OPT_SACK => {
                let len = self.data.get(1).copied().unwrap_or(0) as usize;
                if len < 2 || self.data.len() < len {
                    self.data = &[];
                    return Some(TcpOption::Unknown { kind, data: self.data.to_vec() });
                }
                let blocks_data = &self.data[2..len];
                let mut blocks = Vec::new();
                for chunk in blocks_data.chunks(8) {
                    if chunk.len() == 8 {
                        blocks.push((read_u32be(&chunk[..4]), read_u32be(&chunk[4..8])));
                    }
                }
                self.data = &self.data[len..];
                Some(TcpOption::Sack(blocks))
            }
            OPT_TIMESTAMP => {
                if self.data.len() < 10 {
                    self.data = &[];
                    return Some(TcpOption::Unknown { kind, data: self.data.to_vec() });
                }
                let ts_val = read_u32be(&self.data[2..6]);
                let ts_ecr = read_u32be(&self.data[6..10]);
                self.data = &self.data[10..];
                Some(TcpOption::Timestamp { ts_val, ts_ecr })
            }
            _ => {
                let len = self.data.get(1).copied().unwrap_or(0) as usize;
                if kind > 1 && len >= 2 && self.data.len() >= len {
                    let data = self.data[..len].to_vec();
                    self.data = &self.data[len..];
                    Some(TcpOption::Unknown { kind, data })
                } else {
                    let remaining = self.data.to_vec();
                    self.data = &[];
                    Some(TcpOption::Unknown { kind, data: remaining })
                }
            }
        }
    }
}

/// Zero-copy TCP packet parser.
#[derive(Debug, Clone)]
pub struct TcpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> TcpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < TCP_MIN_HEADER_LEN {
            return None;
        }
        let data_offset = (buf[12] >> 4) as usize * 4;
        if data_offset < TCP_MIN_HEADER_LEN || buf.len() < data_offset {
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
    pub fn sequence(&self) -> u32 {
        read_u32be(&self.buf[4..8])
    }

    #[inline]
    pub fn ack_number(&self) -> u32 {
        read_u32be(&self.buf[8..12])
    }

    #[inline]
    pub fn data_offset(&self) -> u8 {
        self.buf[12] >> 4
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.buf[13] & 0x3F
    }

    #[inline]
    pub fn fin(&self) -> bool {
        self.flags() & FLAG_FIN != 0
    }

    #[inline]
    pub fn syn(&self) -> bool {
        self.flags() & FLAG_SYN != 0
    }

    #[inline]
    pub fn rst(&self) -> bool {
        self.flags() & FLAG_RST != 0
    }

    #[inline]
    pub fn psh(&self) -> bool {
        self.flags() & FLAG_PSH != 0
    }

    #[inline]
    pub fn ack(&self) -> bool {
        self.flags() & FLAG_ACK != 0
    }

    #[inline]
    pub fn urg(&self) -> bool {
        self.flags() & FLAG_URG != 0
    }

    #[inline]
    pub fn window(&self) -> u16 {
        read_u16be(&self.buf[14..16])
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        read_u16be(&self.buf[16..18])
    }

    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        read_u16be(&self.buf[18..20])
    }

    /// TCP options (if data_offset > 5).
    pub fn options(&self) -> TcpOptionsIter<'a> {
        let hdr_len = self.header_length();
        if hdr_len > TCP_MIN_HEADER_LEN {
            TcpOptionsIter::new(&self.buf[TCP_MIN_HEADER_LEN..hdr_len])
        } else {
            TcpOptionsIter::new(&[])
        }
    }

    /// Payload after the TCP header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.header_length()..]
    }

    #[inline]
    pub fn header_length(&self) -> usize {
        self.data_offset() as usize * 4
    }

    /// Verify the TCP checksum (includes IPv4 pseudo-header).
    pub fn verify_checksum(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        pseudo_header_checksum(
            &src.octets(),
            &dst.octets(),
            6, // TCP protocol number
            &self.buf[..self.header_length() + self.payload().len()],
        ) == 0
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub struct TcpPacketBuilder {
    buf: Vec<u8>,
    options: Vec<u8>,
    payload: Option<Vec<u8>>,
}

impl Default for TcpPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpPacketBuilder {
    pub fn new() -> Self {
        let mut buf = vec![0u8; TCP_MIN_HEADER_LEN];
        buf[12] = 0x50; // data_offset = 5, reserved
        Self { buf, options: Vec::new(), payload: None }
    }

    pub fn source_port(mut self, port: u16) -> Self {
        write_u16be(&mut self.buf[..2], port);
        self
    }

    pub fn destination_port(mut self, port: u16) -> Self {
        write_u16be(&mut self.buf[2..4], port);
        self
    }

    pub fn sequence(mut self, seq: u32) -> Self {
        write_u32be(&mut self.buf[4..8], seq);
        self
    }

    pub fn ack_number(mut self, ack: u32) -> Self {
        write_u32be(&mut self.buf[8..12], ack);
        self
    }

    pub fn window(mut self, w: u16) -> Self {
        write_u16be(&mut self.buf[14..16], w);
        self
    }

    pub fn urgent_pointer(mut self, up: u16) -> Self {
        write_u16be(&mut self.buf[18..20], up);
        self
    }

    pub fn syn(mut self, on: bool) -> Self {
        if on { self.buf[13] |= FLAG_SYN; } else { self.buf[13] &= !FLAG_SYN; }
        self
    }

    pub fn ack(mut self, on: bool) -> Self {
        if on { self.buf[13] |= FLAG_ACK; } else { self.buf[13] &= !FLAG_ACK; }
        self
    }

    pub fn fin(mut self, on: bool) -> Self {
        if on { self.buf[13] |= FLAG_FIN; } else { self.buf[13] &= !FLAG_FIN; }
        self
    }

    pub fn rst(mut self, on: bool) -> Self {
        if on { self.buf[13] |= FLAG_RST; } else { self.buf[13] &= !FLAG_RST; }
        self
    }

    pub fn psh(mut self, on: bool) -> Self {
        if on { self.buf[13] |= FLAG_PSH; } else { self.buf[13] &= !FLAG_PSH; }
        self
    }

    pub fn urg(mut self, on: bool) -> Self {
        if on { self.buf[13] |= FLAG_URG; } else { self.buf[13] &= !FLAG_URG; }
        self
    }

    /// Add a TCP option as raw bytes (kind + length + data).
    pub fn add_option(mut self, data: &[u8]) -> Self {
        self.options.extend_from_slice(data);
        self
    }

    /// Convenience: add MSS option.
    pub fn mss(mut self, mss: u16) -> Self {
        self.options.push(OPT_MSS);
        self.options.push(4);
        self.options.extend_from_slice(&mss.to_be_bytes());
        self
    }

    /// Convenience: add Window Scale option.
    pub fn window_scale(mut self, shift: u8) -> Self {
        self.options.push(OPT_WINDOW_SCALE);
        self.options.push(3);
        self.options.push(shift);
        self
    }

    /// Convenience: add SACK Permitted option.
    pub fn sack_permitted(mut self) -> Self {
        self.options.push(OPT_SACK_PERMITTED);
        self.options.push(2);
        self
    }

    /// Convenience: add Timestamp option.
    pub fn timestamp(mut self, ts_val: u32, ts_ecr: u32) -> Self {
        self.options.push(OPT_TIMESTAMP);
        self.options.push(10);
        self.options.extend_from_slice(&ts_val.to_be_bytes());
        self.options.extend_from_slice(&ts_ecr.to_be_bytes());
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }

    /// Build the TCP packet, computing the checksum (IPv4 pseudo-header).
    pub fn build(mut self, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        // Pad options to 4-byte boundary with NoOps
        while self.options.len() % 4 != 0 {
            self.options.push(OPT_NOOP);
        }
        // Update data_offset
        let total_hdr_words = (TCP_MIN_HEADER_LEN + self.options.len()) / 4;
        self.buf[12] = (total_hdr_words as u8) << 4;

        // Zero checksum
        self.buf[16] = 0;
        self.buf[17] = 0;

        let mut packet = self.buf;
        if !self.options.is_empty() {
            packet.extend_from_slice(&self.options);
        }
        if let Some(ref p) = self.payload {
            packet.extend_from_slice(p);
        }

        let csum = pseudo_header_checksum(
            &src.octets(),
            &dst.octets(),
            6, // TCP
            &packet,
        );
        write_u16be(&mut packet[16..18], csum);

        packet
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal TCP header: src=1234, dst=80, seq=1, ack=0, data_offset=5, flags=SYN
    fn sample_tcp_syn() -> Vec<u8> {
        let mut data = vec![0u8; TCP_MIN_HEADER_LEN];
        write_u16be(&mut data[..2], 1234);
        write_u16be(&mut data[2..4], 80);
        write_u32be(&mut data[4..8], 1);      // seq
        write_u32be(&mut data[8..12], 0);      // ack
        data[12] = 0x50; // data_offset=5
        data[13] = FLAG_SYN;
        write_u16be(&mut data[14..16], 65535); // window
        data
    }

    #[test]
    fn parse_tcp_no_options() {
        let data = sample_tcp_syn();
        let pkt = TcpPacket::new(&data).unwrap();
        assert_eq!(pkt.source_port(), 1234);
        assert_eq!(pkt.destination_port(), 80);
        assert_eq!(pkt.sequence(), 1);
        assert_eq!(pkt.ack_number(), 0);
        assert_eq!(pkt.data_offset(), 5);
        assert_eq!(pkt.header_length(), 20);
        assert!(pkt.syn());
        assert!(!pkt.ack());
        assert!(!pkt.fin());
        assert!(!pkt.rst());
        assert_eq!(pkt.window(), 65535);
    }

    #[test]
    fn parse_tcp_too_short() {
        assert!(TcpPacket::new(&[]).is_none());
        assert!(TcpPacket::new(&[0u8; 19]).is_none());
        // 20 bytes with data_offset=5 is valid
        let mut d = [0u8; 20];
        d[12] = 0x50;
        assert!(TcpPacket::new(&d).is_some());
    }

    #[test]
    fn parse_tcp_data_offset_exceeds_buffer() {
        let mut data = vec![0u8; 22];
        data[12] = 0x60; // data_offset=6 (24 bytes)
        assert!(TcpPacket::new(&data).is_none());
    }

    #[test]
    fn tcp_options_mss_and_window_scale() {
        let mut data = sample_tcp_syn();
        // MSS: kind=2, len=4, mss=1460
        data.extend_from_slice(&[OPT_MSS, 4, 0x05, 0xB4]);
        // Window Scale: kind=3, len=3, shift=7
        data.extend_from_slice(&[OPT_WINDOW_SCALE, 3, 7]);
        // Pad to 4-byte boundary with NoOps (1 byte padding)
        data.push(OPT_NOOP);
        // data_offset: (20 + 8) / 4 = 7
        data[12] = 0x70;

        let pkt = TcpPacket::new(&data).unwrap();
        assert_eq!(pkt.data_offset(), 7);
        assert_eq!(pkt.header_length(), 28);

        let opts: Vec<_> = pkt.options().collect();
        assert_eq!(opts.len(), 3); // MSS, WindowScale, NoOp
        match &opts[0] {
            TcpOption::MaximumSegmentSize(mss) => assert_eq!(*mss, 1460),
            _ => panic!("expected MSS"),
        }
        match &opts[1] {
            TcpOption::WindowScale(shift) => assert_eq!(*shift, 7),
            _ => panic!("expected WindowScale"),
        }
    }

    #[test]
    fn tcp_options_timestamp() {
        let mut data = sample_tcp_syn();
        data.extend_from_slice(&[OPT_TIMESTAMP, 10,
            0x00, 0x00, 0x00, 0x01,  // ts_val
            0x00, 0x00, 0x00, 0x02,  // ts_ecr
        ]);
        // Pad to 4-byte boundary (10 + 2 = 12)
        data.push(OPT_NOOP);
        data.push(OPT_NOOP);
        data[12] = 0x80; // data_offset=8 (32 bytes)

        let pkt = TcpPacket::new(&data).unwrap();
        let opts: Vec<_> = pkt.options().collect();
        match &opts[0] {
            TcpOption::Timestamp { ts_val, ts_ecr } => {
                assert_eq!(*ts_val, 1);
                assert_eq!(*ts_ecr, 2);
            }
            _ => panic!("expected Timestamp"),
        }
    }

    #[test]
    fn tcp_options_sack() {
        let mut data = sample_tcp_syn();
        // SACK: kind=5, len=18, 2 blocks (each 8 bytes: left_edge + right_edge)
        data.extend_from_slice(&[OPT_SACK, 18]);
        // Block 1: left=100, right=200
        data.extend_from_slice(&100u32.to_be_bytes());
        data.extend_from_slice(&200u32.to_be_bytes());
        // Block 2: left=300, right=400
        data.extend_from_slice(&300u32.to_be_bytes());
        data.extend_from_slice(&400u32.to_be_bytes());
        // Pad to 4-byte boundary (18 + 2 = 20)
        data.push(OPT_NOOP);
        data.push(OPT_NOOP);
        data[12] = 0xA0; // data_offset=10 (40 bytes)

        let pkt = TcpPacket::new(&data).unwrap();
        let opts: Vec<_> = pkt.options().collect();
        match &opts[0] {
            TcpOption::Sack(blocks) => {
                assert_eq!(blocks.len(), 2);
                assert_eq!(blocks[0], (100, 200));
                assert_eq!(blocks[1], (300, 400));
            }
            _ => panic!("expected SACK"),
        }
    }

    #[test]
    fn tcp_sack_permitted() {
        let mut data = sample_tcp_syn();
        data.extend_from_slice(&[OPT_SACK_PERMITTED, 2]);
        data.push(OPT_NOOP);
        data.push(OPT_NOOP);
        data[12] = 0x60; // data_offset=6

        let pkt = TcpPacket::new(&data).unwrap();
        let opts: Vec<_> = pkt.options().collect();
        assert!(matches!(opts[0], TcpOption::SackPermitted));
    }

    #[test]
    fn tcp_build_and_verify_checksum() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let pkt_bytes = TcpPacketBuilder::new()
            .source_port(12345)
            .destination_port(80)
            .sequence(1000)
            .syn(true)
            .window(65535)
            .mss(1460)
            .build(src, dst);

        let pkt = TcpPacket::new(&pkt_bytes).unwrap();
        assert!(pkt.syn());
        assert_eq!(pkt.source_port(), 12345);
        assert_eq!(pkt.destination_port(), 80);
        assert_eq!(pkt.sequence(), 1000);
        assert!(pkt.verify_checksum(src, dst));
    }

    #[test]
    fn tcp_build_roundtrip_with_options() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let pkt_bytes = TcpPacketBuilder::new()
            .source_port(54321)
            .destination_port(443)
            .sequence(0x12345678)
            .ack_number(0x87654321)
            .syn(true)
            .ack(true)
            .window(8192)
            .mss(1460)
            .window_scale(7)
            .sack_permitted()
            .timestamp(0x100, 0x200)
            .payload(&[0x01, 0x02, 0x03])
            .build(src, dst);

        let pkt = TcpPacket::new(&pkt_bytes).unwrap();
        assert_eq!(pkt.source_port(), 54321);
        assert_eq!(pkt.destination_port(), 443);
        assert_eq!(pkt.sequence(), 0x12345678);
        assert_eq!(pkt.ack_number(), 0x87654321);
        assert!(pkt.syn());
        assert!(pkt.ack());
        assert_eq!(pkt.window(), 8192);
        assert_eq!(pkt.payload(), &[0x01, 0x02, 0x03]);
        assert!(pkt.verify_checksum(src, dst));

        // Check options
        let opts: Vec<_> = pkt.options().collect();
        assert!(opts.iter().any(|o| matches!(o, TcpOption::MaximumSegmentSize(1460))));
        assert!(opts.iter().any(|o| matches!(o, TcpOption::WindowScale(7))));
        assert!(opts.iter().any(|o| matches!(o, TcpOption::SackPermitted)));
        assert!(opts.iter().any(|o| matches!(o, TcpOption::Timestamp { ts_val: 0x100, ts_ecr: 0x200 })));
    }

    #[test]
    fn tcp_end_of_list_option() {
        let mut data = sample_tcp_syn();
        data.push(OPT_END); // End of list
        data.extend_from_slice(&[OPT_MSS, 4, 0x05, 0xB4]); // should not be parsed
        data.push(OPT_NOOP);
        data.push(OPT_NOOP);
        data[12] = 0x60;

        let pkt = TcpPacket::new(&data).unwrap();
        let opts: Vec<_> = pkt.options().collect();
        assert_eq!(opts.len(), 1);
        assert!(matches!(opts[0], TcpOption::EndOfList));
    }
}
