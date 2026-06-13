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
}

impl<'a> DnsPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < DNS_HEADER_LEN {
            return None;
        }
        Some(Self { buf })
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
        read_u16be(&self.buf[4..6])
    }

    #[inline]
    pub fn answers_count(&self) -> u16 {
        read_u16be(&self.buf[6..8])
    }

    #[inline]
    pub fn authorities_count(&self) -> u16 {
        read_u16be(&self.buf[8..10])
    }

    #[inline]
    pub fn additionals_count(&self) -> u16 {
        read_u16be(&self.buf[10..12])
    }

    /// Iterate over the Question section.
    pub fn questions(&self) -> DnsQuestionIter<'a> {
        DnsQuestionIter {
            buf: self.buf,
            pos: DNS_HEADER_LEN,
            remaining: self.questions_count() as usize,
        }
    }

    /// Iterate over the Answer section.
    pub fn answers(&self) -> DnsRecordIter<'a> {
        // Skip questions first
        let mut pos = DNS_HEADER_LEN;
        let qcount = self.questions_count() as usize;
        for _ in 0..qcount {
            if let Some((_, next)) = parse_name(self.buf, pos) {
                pos = next + 4; // QTYPE(2) + QCLASS(2)
            }
        }
        DnsRecordIter {
            buf: self.buf,
            pos,
            remaining: self.answers_count() as usize,
        }
    }

    /// Iterate over the Authority section.
    pub fn authorities(&self) -> DnsRecordIter<'a> {
        let mut pos = DNS_HEADER_LEN;
        let qcount = self.questions_count() as usize;
        let acount = self.answers_count() as usize;
        for _ in 0..qcount {
            if let Some((_, next)) = parse_name(self.buf, pos) {
                pos = next + 4;
            }
        }
        for _ in 0..acount {
            if let Some((_, next)) = parse_name(self.buf, pos) {
                pos = next + 10; // TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2)
                let rdlen = read_u16be(&self.buf[pos - 2..pos]) as usize;
                pos += rdlen;
            }
        }
        DnsRecordIter {
            buf: self.buf,
            pos,
            remaining: self.authorities_count() as usize,
        }
    }

    /// Iterate over the Additional section.
    pub fn additionals(&self) -> DnsRecordIter<'a> {
        let total_before = self.questions_count() as usize
            + self.answers_count() as usize
            + self.authorities_count() as usize;
        let mut pos = DNS_HEADER_LEN;
        let mut skipped = 0usize;
        let qc = self.questions_count() as usize;
        while skipped < total_before {
            if let Some((_, next)) = parse_name(self.buf, pos) {
                if skipped < qc {
                    pos = next + 4;
                } else {
                    pos = next + 10;
                    if pos <= self.buf.len() {
                        let rdlen = read_u16be(&self.buf[pos - 2..pos]) as usize;
                        pos += rdlen;
                    }
                }
                skipped += 1;
            } else {
                break;
            }
        }
        DnsRecordIter {
            buf: self.buf,
            pos,
            remaining: self.additionals_count() as usize,
        }
    }
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
        Some(DnsQuestion { name, qtype, qclass })
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
            DnsType::A => {
                if rdata.len() >= 4 {
                    let addr = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                    DnsRecord::A { name, ttl, addr }
                } else {
                    DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() }
                }
            }
            DnsType::AAAA => {
                if rdata.len() >= 16 {
                    let b: [u8; 16] = rdata[..16].try_into().unwrap();
                    DnsRecord::AAAA { name, ttl, addr: Ipv6Addr::from(b) }
                } else {
                    DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() }
                }
            }
            DnsType::CNAME => {
                parse_name(self.buf, rdata_start)
                    .map(|(cn, _)| DnsRecord::CNAME { name: name.clone(), ttl, cname: cn })
                    .unwrap_or(DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() })
            }
            DnsType::MX => {
                if rdata.len() >= 3 {
                    let preference = read_u16be(&rdata[..2]);
                    parse_name(self.buf, rdata_start + 2)
                        .map(|(ex, _)| DnsRecord::MX { name: name.clone(), ttl, preference, exchange: ex })
                        .unwrap_or(DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() })
                } else {
                    DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() }
                }
            }
            DnsType::NS => {
                parse_name(self.buf, rdata_start)
                    .map(|(ns, _)| DnsRecord::NS { name: name.clone(), ttl, nsdname: ns })
                    .unwrap_or(DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() })
            }
            DnsType::PTR => {
                parse_name(self.buf, rdata_start)
                    .map(|(pt, _)| DnsRecord::PTR { name: name.clone(), ttl, ptrdname: pt })
                    .unwrap_or(DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() })
            }
            DnsType::SOA => {
                if rdata.len() >= 20 {
                    let mname = parse_name(self.buf, rdata_start).map(|(m, _)| m).unwrap_or_default();
                    let mut mname_end = rdata_start;
                    if let Some((_, nxt)) = parse_name(self.buf, rdata_start) { mname_end = nxt; }
                    let rname = parse_name(self.buf, mname_end).map(|(r, _)| r).unwrap_or_default();
                    let mut rname_end = mname_end;
                    if let Some((_, nxt)) = parse_name(self.buf, mname_end) { rname_end = nxt; }
                    if rname_end + 20 <= rdata_start + rdlen {
                        let nums = &self.buf[rname_end..rname_end + 20];
                        DnsRecord::SOA {
                            name, ttl, mname, rname,
                            serial: read_u32be(&nums[..4]),
                            refresh: read_u32be(&nums[4..8]),
                            retry: read_u32be(&nums[8..12]),
                            expire: read_u32be(&nums[12..16]),
                            minimum: read_u32be(&nums[16..20]),
                        }
                    } else {
                        DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() }
                    }
                } else {
                    DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() }
                }
            }
            DnsType::TXT => {
                DnsRecord::TXT { name, ttl, data: rdata.to_vec() }
            }
            DnsType::SRV => {
                if rdata.len() >= 6 {
                    let priority = read_u16be(&rdata[..2]);
                    let weight = read_u16be(&rdata[2..4]);
                    let port = read_u16be(&rdata[4..6]);
                    parse_name(self.buf, rdata_start + 6)
                        .map(|(tgt, _)| DnsRecord::SRV { name: name.clone(), ttl, priority, weight, port, target: tgt })
                        .unwrap_or(DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() })
                } else {
                    DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() }
                }
            }
            DnsType::Unknown(_) => {
                DnsRecord::Unknown { name, qtype, ttl, rdata: rdata.to_vec() }
            }
        };

        self.pos = record_end;
        self.remaining -= 1;
        Some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::builder::DnsPacketBuilder;
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
}
