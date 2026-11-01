//! DNS message parser (RFC 1035).

use core::net::{Ipv4Addr, Ipv6Addr};

use super::name::parse_name;
use super::types::{DnsClass, DnsOpcode, DnsRcode, DnsType};
use wireforge_core::util::{read_u16be, read_u32be};

/// Minimum DNS message length (12-byte header).
pub const DNS_HEADER_LEN: usize = 12;

/// Zero-copy DNS message parser.
#[derive(Debug, Clone)]
pub struct DnsPacket<'a> {
    buf: &'a [u8],
    /// Pre-computed byte offsets for each section (computed once in `new()`).
    answers_start: usize,
    authorities_start: usize,
    additionals_start: usize,
    questions_count: u16,
    answers_count: u16,
    authorities_count: u16,
    additionals_count: u16,
}

impl<'a> DnsPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < DNS_HEADER_LEN {
            return None;
        }
        // Walk all sections once to pre-compute start positions.
        let qc = read_u16be(&buf[4..6]) as usize;
        let ac = read_u16be(&buf[6..8]) as usize;
        let nc = read_u16be(&buf[8..10]) as usize;
        let dc = read_u16be(&buf[10..12]) as usize;

        let mut pos = DNS_HEADER_LEN;
        // Skip questions
        pos = skip_questions(buf, pos, qc);
        let answers_start = pos;
        // Skip answers
        pos = skip_records(buf, pos, ac);
        let authorities_start = pos;
        // Skip authorities
        pos = skip_records(buf, pos, nc);
        let additionals_start = pos;

        Some(Self {
            buf,
            answers_start,
            authorities_start,
            additionals_start,
            questions_count: qc as u16,
            answers_count: ac as u16,
            authorities_count: nc as u16,
            additionals_count: dc as u16,
        })
    }

    #[inline]
    pub fn transaction_id(&self) -> u16 {
        read_u16be(&self.buf[..2])
    }
    #[inline]
    pub fn flags(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }
    #[inline]
    pub fn qr(&self) -> bool {
        self.flags() & 0x8000 != 0
    }
    #[inline]
    pub fn opcode(&self) -> DnsOpcode {
        DnsOpcode::from(((self.flags() >> 11) & 0x0F) as u8)
    }
    #[inline]
    pub fn aa(&self) -> bool {
        self.flags() & 0x0400 != 0
    }
    #[inline]
    pub fn tc(&self) -> bool {
        self.flags() & 0x0200 != 0
    }
    #[inline]
    pub fn rd(&self) -> bool {
        self.flags() & 0x0100 != 0
    }
    #[inline]
    pub fn ra(&self) -> bool {
        self.flags() & 0x0080 != 0
    }
    #[inline]
    pub fn rcode(&self) -> DnsRcode {
        DnsRcode::from((self.flags() & 0x000F) as u8)
    }

    #[inline]
    pub fn questions_count(&self) -> u16 {
        self.questions_count
    }
    #[inline]
    pub fn answers_count(&self) -> u16 {
        self.answers_count
    }
    #[inline]
    pub fn authorities_count(&self) -> u16 {
        self.authorities_count
    }
    #[inline]
    pub fn additionals_count(&self) -> u16 {
        self.additionals_count
    }

    /// Iterate over the Question section.
    pub fn questions(&self) -> DnsQuestionIter<'a> {
        DnsQuestionIter {
            buf: self.buf,
            pos: DNS_HEADER_LEN,
            remaining: self.questions_count as usize,
        }
    }

    /// Iterate over the Answer section.
    pub fn answers(&self) -> DnsRecordIter<'a> {
        DnsRecordIter {
            buf: self.buf,
            pos: self.answers_start,
            remaining: self.answers_count as usize,
        }
    }

    /// Iterate over the Authority section.
    pub fn authorities(&self) -> DnsRecordIter<'a> {
        DnsRecordIter {
            buf: self.buf,
            pos: self.authorities_start,
            remaining: self.authorities_count as usize,
        }
    }

    /// Iterate over the Additional section.
    pub fn additionals(&self) -> DnsRecordIter<'a> {
        DnsRecordIter {
            buf: self.buf,
            pos: self.additionals_start,
            remaining: self.additionals_count as usize,
        }
    }
}

/// Walk past `count` question entries starting at `pos`. Returns new position.
fn skip_questions(buf: &[u8], mut pos: usize, count: usize) -> usize {
    for _ in 0..count {
        if let Some((_, next)) = parse_name(buf, pos) {
            pos = next + 4; // QTYPE(2) + QCLASS(2)
        }
    }
    pos
}

/// Walk past `count` resource record entries starting at `pos`. Returns new position.
fn skip_records(buf: &[u8], mut pos: usize, count: usize) -> usize {
    for _ in 0..count {
        if let Some((_, next)) = parse_name(buf, pos) {
            pos = next + 10; // TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2)
            if pos >= 2 {
                let rdlen = read_u16be(&buf[pos - 2..pos]) as usize;
                pos += rdlen;
            }
        }
    }
    pos
}

/// A DNS question entry.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

/// Iterator over DNS Question section.
pub struct DnsQuestionIter<'a> {
    buf: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for DnsQuestionIter<'a> {
    type Item = DnsQuestion;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (name, next) = parse_name(self.buf, self.pos)?;
        if next + 4 > self.buf.len() {
            return None;
        }
        let qtype = DnsType::from(read_u16be(&self.buf[next..next + 2]));
        let qclass = DnsClass::from(read_u16be(&self.buf[next + 2..next + 4]));
        self.pos = next + 4;
        self.remaining -= 1;
        Some(DnsQuestion {
            name,
            qtype,
            qclass,
        })
    }
}

/// A parsed DNS resource record.
#[derive(Debug, Clone)]
pub enum DnsRecord {
    A {
        name: String,
        ttl: u32,
        addr: Ipv4Addr,
    },
    AAAA {
        name: String,
        ttl: u32,
        addr: Ipv6Addr,
    },
    CNAME {
        name: String,
        ttl: u32,
        cname: String,
    },
    MX {
        name: String,
        ttl: u32,
        preference: u16,
        exchange: String,
    },
    NS {
        name: String,
        ttl: u32,
        nsdname: String,
    },
    PTR {
        name: String,
        ttl: u32,
        ptrdname: String,
    },
    SOA {
        name: String,
        ttl: u32,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    TXT {
        name: String,
        ttl: u32,
        data: Vec<u8>,
    },
    SRV {
        name: String,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Unknown {
        name: String,
        qtype: DnsType,
        ttl: u32,
        rdata: Vec<u8>,
    },
}

/// Iterator over DNS resource records.
pub struct DnsRecordIter<'a> {
    buf: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for DnsRecordIter<'a> {
    type Item = DnsRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (name, next) = parse_name(self.buf, self.pos)?;
        if next + 10 > self.buf.len() {
            return None;
        }

        let qtype = DnsType::from(read_u16be(&self.buf[next..next + 2]));
        // DNS class is read for offset tracking; type-specific parsing validates it implicitly.
        let _qclass = read_u16be(&self.buf[next + 2..next + 4]);
        let ttl = read_u32be(&self.buf[next + 4..next + 8]);
        let rdlen = read_u16be(&self.buf[next + 8..next + 10]) as usize;
        let rdata_start = next + 10;

        if rdata_start + rdlen > self.buf.len() {
            return None;
        }
        let rdata = &self.buf[rdata_start..rdata_start + rdlen];
        let record_end = rdata_start + rdlen;

        let record = match qtype {
            DnsType::A => match rdata.get(..4) {
                Some(bytes) => DnsRecord::A {
                    name,
                    ttl,
                    addr: Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                },
                None => unknown_record(name, qtype, ttl, rdata),
            },
            DnsType::AAAA => match rdata.get(..16).and_then(|b| <[u8; 16]>::try_from(b).ok()) {
                Some(addr) => DnsRecord::AAAA {
                    name,
                    ttl,
                    addr: Ipv6Addr::from(addr),
                },
                None => unknown_record(name, qtype, ttl, rdata),
            },
            DnsType::CNAME => match parse_name(self.buf, rdata_start) {
                Some((cname, _)) => DnsRecord::CNAME { name, ttl, cname },
                None => unknown_record(name, qtype, ttl, rdata),
            },
            DnsType::MX => {
                if rdata.len() >= 3 {
                    let preference = read_u16be(&rdata[..2]);
                    match parse_name(self.buf, rdata_start + 2) {
                        Some((exchange, _)) => DnsRecord::MX {
                            name,
                            ttl,
                            preference,
                            exchange,
                        },
                        None => unknown_record(name, qtype, ttl, rdata),
                    }
                } else {
                    unknown_record(name, qtype, ttl, rdata)
                }
            }
            DnsType::NS => match parse_name(self.buf, rdata_start) {
                Some((nsdname, _)) => DnsRecord::NS { name, ttl, nsdname },
                None => unknown_record(name, qtype, ttl, rdata),
            },
            DnsType::PTR => match parse_name(self.buf, rdata_start) {
                Some((ptrdname, _)) => DnsRecord::PTR {
                    name,
                    ttl,
                    ptrdname,
                },
                None => unknown_record(name, qtype, ttl, rdata),
            },
            DnsType::SOA => parse_soa_rdata(self.buf, rdata_start, rdlen, name, ttl, qtype),
            DnsType::TXT => DnsRecord::TXT {
                name,
                ttl,
                data: rdata.to_vec(),
            },
            DnsType::SRV => {
                if rdata.len() >= 6 {
                    let priority = read_u16be(&rdata[..2]);
                    let weight = read_u16be(&rdata[2..4]);
                    let port = read_u16be(&rdata[4..6]);
                    match parse_name(self.buf, rdata_start + 6) {
                        Some((target, _)) => DnsRecord::SRV {
                            name,
                            ttl,
                            priority,
                            weight,
                            port,
                            target,
                        },
                        None => unknown_record(name, qtype, ttl, rdata),
                    }
                } else {
                    unknown_record(name, qtype, ttl, rdata)
                }
            }
            DnsType::Unknown(_) => unknown_record(name, qtype, ttl, rdata),
        };

        self.pos = record_end;
        self.remaining -= 1;
        Some(record)
    }
}

/// Build an [`DnsRecord::Unknown`] fallback for unparseable RDATA.
fn unknown_record(name: String, qtype: DnsType, ttl: u32, rdata: &[u8]) -> DnsRecord {
    DnsRecord::Unknown {
        name,
        qtype,
        ttl,
        rdata: rdata.to_vec(),
    }
}

/// Parse the rdata of an SOA record into a [`DnsRecord::SOA`].
fn parse_soa_rdata(
    buf: &[u8],
    rdata_start: usize,
    rdlen: usize,
    name: String,
    ttl: u32,
    qtype: DnsType,
) -> DnsRecord {
    let rdata = &buf[rdata_start..rdata_start + rdlen];
    if rdata.len() < 20 {
        return unknown_record(name, qtype, ttl, rdata);
    }
    let (mname, mname_end) = match parse_name(buf, rdata_start) {
        Some((mname, next)) => (mname, next),
        None => (String::new(), rdata_start),
    };
    let (rname, rname_end) = match parse_name(buf, mname_end) {
        Some((rname, next)) => (rname, next),
        None => (String::new(), mname_end),
    };
    if rname_end + 20 > rdata_start + rdlen {
        return unknown_record(name, qtype, ttl, rdata);
    }
    let nums = &buf[rname_end..rname_end + 20];
    DnsRecord::SOA {
        name,
        ttl,
        mname,
        rname,
        serial: read_u32be(&nums[..4]),
        refresh: read_u32be(&nums[4..8]),
        retry: read_u32be(&nums[8..12]),
        expire: read_u32be(&nums[12..16]),
        minimum: read_u32be(&nums[16..20]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::builder::DnsPacketBuilder;
    use crate::dns::name::encode_name;
    use crate::dns::types::DnsClass;

    // A minimal DNS query: id=0x1234, 1 question (example.com A)
    fn sample_query() -> Vec<u8> {
        DnsPacketBuilder::query()
            .transaction_id(0x1234)
            .add_question("example.com", DnsType::A, DnsClass::IN)
            .build()
    }

    #[test]
    fn parse_query_header() {
        let data = sample_query();
        let pkt = DnsPacket::new(&data).unwrap();
        assert_eq!(pkt.transaction_id(), 0x1234);
        assert!(!pkt.qr());
        assert!(pkt.rd());
        assert_eq!(pkt.questions_count(), 1);
        assert_eq!(pkt.answers_count(), 0);
    }

    #[test]
    fn parse_query_questions() {
        let data = sample_query();
        let pkt = DnsPacket::new(&data).unwrap();
        let qs: Vec<_> = pkt.questions().collect();
        assert_eq!(qs.len(), 1);
        assert_eq!(qs[0].name, "example.com");
        assert_eq!(qs[0].qtype, DnsType::A);
        assert_eq!(qs[0].qclass, DnsClass::IN);
    }

    #[test]
    fn parse_too_short() {
        assert!(DnsPacket::new(&[]).is_none());
        assert!(DnsPacket::new(&[0u8; 11]).is_none());
    }

    #[test]
    fn build_and_parse_roundtrip() {
        // Build a response with an A record
        let a_rdata = [192u8, 168, 1, 1];
        let data = DnsPacketBuilder::response()
            .transaction_id(0x5678)
            .add_question("www.example.com", DnsType::A, DnsClass::IN)
            .add_raw_answer("www.example.com", DnsType::A, 300, &a_rdata)
            .build();

        let pkt = DnsPacket::new(&data).unwrap();
        assert!(pkt.qr());
        assert_eq!(pkt.answers_count(), 1);

        let answers: Vec<_> = pkt.answers().collect();
        assert_eq!(answers.len(), 1);
        match &answers[0] {
            DnsRecord::A { name, ttl, addr } => {
                assert_eq!(name, "www.example.com");
                assert_eq!(*ttl, 300);
                assert_eq!(*addr, Ipv4Addr::new(192, 168, 1, 1));
            }
            _ => panic!("expected A record"),
        }
    }

    /// Build a response containing one answer with the given RDATA.
    fn parse_single_answer(qtype: DnsType, ttl: u32, rdata: &[u8]) -> DnsRecord {
        let data = DnsPacketBuilder::response()
            .add_raw_answer("owner.example.com", qtype, ttl, rdata)
            .build();
        let pkt = DnsPacket::new(&data).unwrap();
        let answers: Vec<_> = pkt.answers().collect();
        assert_eq!(answers.len(), 1, "expected exactly one answer");
        answers.into_iter().next().unwrap()
    }

    #[test]
    fn parse_aaaa_record() {
        let rdata = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        match parse_single_answer(DnsType::AAAA, 60, &rdata) {
            DnsRecord::AAAA { name, ttl, addr } => {
                assert_eq!(name, "owner.example.com");
                assert_eq!(ttl, 60);
                assert_eq!(addr, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
            }
            other => panic!("expected AAAA record, got {other:?}"),
        }
    }

    #[test]
    fn parse_cname_record() {
        let rdata = encode_name("target.example.com");
        match parse_single_answer(DnsType::CNAME, 120, &rdata) {
            DnsRecord::CNAME { name, ttl, cname } => {
                assert_eq!(name, "owner.example.com");
                assert_eq!(ttl, 120);
                assert_eq!(cname, "target.example.com");
            }
            other => panic!("expected CNAME record, got {other:?}"),
        }
    }

    #[test]
    fn parse_cname_compressed_rdata() {
        // CNAME RDATA is a pointer to the question name at offset 12.
        let data = DnsPacketBuilder::response()
            .add_question("www.example.com", DnsType::CNAME, DnsClass::IN)
            .add_raw_answer("www.example.com", DnsType::CNAME, 60, &[0xC0, 0x0C])
            .build();
        let pkt = DnsPacket::new(&data).unwrap();
        let answers: Vec<_> = pkt.answers().collect();
        match &answers[0] {
            DnsRecord::CNAME { cname, .. } => assert_eq!(cname, "www.example.com"),
            other => panic!("expected CNAME record, got {other:?}"),
        }
    }

    #[test]
    fn parse_mx_record() {
        let mut rdata = 10u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&encode_name("mail.example.com"));
        match parse_single_answer(DnsType::MX, 300, &rdata) {
            DnsRecord::MX {
                name,
                ttl,
                preference,
                exchange,
            } => {
                assert_eq!(name, "owner.example.com");
                assert_eq!(ttl, 300);
                assert_eq!(preference, 10);
                assert_eq!(exchange, "mail.example.com");
            }
            other => panic!("expected MX record, got {other:?}"),
        }
    }

    #[test]
    fn parse_ns_and_ptr_records() {
        let rdata = encode_name("ns1.example.com");
        match parse_single_answer(DnsType::NS, 60, &rdata) {
            DnsRecord::NS { name, ttl, nsdname } => {
                assert_eq!(name, "owner.example.com");
                assert_eq!(ttl, 60);
                assert_eq!(nsdname, "ns1.example.com");
            }
            other => panic!("expected NS record, got {other:?}"),
        }

        let rdata = encode_name("host.example.com");
        match parse_single_answer(DnsType::PTR, 60, &rdata) {
            DnsRecord::PTR {
                name,
                ttl,
                ptrdname,
            } => {
                assert_eq!(name, "owner.example.com");
                assert_eq!(ttl, 60);
                assert_eq!(ptrdname, "host.example.com");
            }
            other => panic!("expected PTR record, got {other:?}"),
        }
    }

    #[test]
    fn parse_srv_record() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority
        rdata.extend_from_slice(&2u16.to_be_bytes()); // weight
        rdata.extend_from_slice(&443u16.to_be_bytes()); // port
        rdata.extend_from_slice(&encode_name("svc.example.com"));
        match parse_single_answer(DnsType::SRV, 60, &rdata) {
            DnsRecord::SRV {
                name,
                ttl,
                priority,
                weight,
                port,
                target,
            } => {
                assert_eq!(name, "owner.example.com");
                assert_eq!(ttl, 60);
                assert_eq!(priority, 1);
                assert_eq!(weight, 2);
                assert_eq!(port, 443);
                assert_eq!(target, "svc.example.com");
            }
            other => panic!("expected SRV record, got {other:?}"),
        }
    }

    #[test]
    fn parse_soa_record() {
        let mut rdata = encode_name("ns.example.com");
        rdata.extend_from_slice(&encode_name("admin.example.com"));
        for n in [1u32, 2, 3, 4, 5] {
            rdata.extend_from_slice(&n.to_be_bytes());
        }
        match parse_single_answer(DnsType::SOA, 900, &rdata) {
            DnsRecord::SOA {
                name,
                ttl,
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                assert_eq!(name, "owner.example.com");
                assert_eq!(ttl, 900);
                assert_eq!(mname, "ns.example.com");
                assert_eq!(rname, "admin.example.com");
                assert_eq!(serial, 1);
                assert_eq!(refresh, 2);
                assert_eq!(retry, 3);
                assert_eq!(expire, 4);
                assert_eq!(minimum, 5);
            }
            other => panic!("expected SOA record, got {other:?}"),
        }
    }

    #[test]
    fn parse_txt_and_unknown_records() {
        match parse_single_answer(DnsType::TXT, 60, b"hello world") {
            DnsRecord::TXT { name, ttl, data } => {
                assert_eq!(name, "owner.example.com");
                assert_eq!(ttl, 60);
                assert_eq!(data, b"hello world");
            }
            other => panic!("expected TXT record, got {other:?}"),
        }

        match parse_single_answer(DnsType::Unknown(99), 60, &[1, 2, 3]) {
            DnsRecord::Unknown {
                name,
                qtype,
                ttl,
                rdata,
            } => {
                assert_eq!(name, "owner.example.com");
                assert_eq!(qtype, DnsType::Unknown(99));
                assert_eq!(ttl, 60);
                assert_eq!(rdata, vec![1, 2, 3]);
            }
            other => panic!("expected Unknown record, got {other:?}"),
        }
    }

    #[test]
    fn short_rdata_falls_back_to_unknown() {
        for (qtype, rdata) in [
            (DnsType::A, &[1u8, 2, 3][..]),
            (DnsType::AAAA, &[0u8; 15][..]),
            (DnsType::MX, &[0u8, 10][..]),
            (DnsType::SRV, &[0u8; 5][..]),
            (DnsType::CNAME, &[][..]),
        ] {
            match parse_single_answer(qtype, 60, rdata) {
                DnsRecord::Unknown { qtype: got, .. } => assert_eq!(got, qtype),
                other => panic!("expected Unknown for {qtype:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn short_soa_rdata_falls_back_to_unknown() {
        match parse_single_answer(DnsType::SOA, 60, &[0u8; 19]) {
            DnsRecord::Unknown { qtype, .. } => assert_eq!(qtype, DnsType::SOA),
            other => panic!("expected Unknown for SOA, got {other:?}"),
        }
    }

    /// Characterization: when the SOA owner names are unparseable but 20 bytes
    /// of numeric data are present, names default to empty strings and the
    /// numeric fields are read from the start of the RDATA.
    #[test]
    fn malformed_soa_names_are_empty_and_numbers_read_from_start() {
        let mut rdata = vec![64u8]; // invalid label length (> 63)
        rdata.extend_from_slice(&[0u8; 19]);
        match parse_single_answer(DnsType::SOA, 60, &rdata) {
            DnsRecord::SOA {
                mname,
                rname,
                serial,
                ..
            } => {
                assert_eq!(mname, "");
                assert_eq!(rname, "");
                assert_eq!(serial, u32::from_be_bytes([64, 0, 0, 0]));
            }
            other => panic!("expected SOA record, got {other:?}"),
        }
    }

    #[test]
    fn parse_all_sections() {
        let ns_rdata = encode_name("ns.example.com");
        let data = DnsPacketBuilder::response()
            .add_question("q.example.com", DnsType::A, DnsClass::IN)
            .add_raw_answer("q.example.com", DnsType::A, 60, &[1, 2, 3, 4])
            .add_raw_authority("example.com", DnsType::NS, 60, &ns_rdata)
            .add_raw_additional("ns.example.com", DnsType::A, 60, &[5, 6, 7, 8])
            .build();

        let pkt = DnsPacket::new(&data).unwrap();
        assert_eq!(pkt.questions_count(), 1);
        assert_eq!(pkt.answers_count(), 1);
        assert_eq!(pkt.authorities_count(), 1);
        assert_eq!(pkt.additionals_count(), 1);

        assert_eq!(pkt.questions().count(), 1);
        assert!(matches!(
            pkt.answers().next(),
            Some(DnsRecord::A { addr, .. }) if addr == Ipv4Addr::new(1, 2, 3, 4)
        ));
        assert!(matches!(
            pkt.authorities().next(),
            Some(DnsRecord::NS { nsdname, .. }) if nsdname == "ns.example.com"
        ));
        assert!(matches!(
            pkt.additionals().next(),
            Some(DnsRecord::A { addr, .. }) if addr == Ipv4Addr::new(5, 6, 7, 8)
        ));
    }
}
