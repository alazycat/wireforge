//! DNS message builder (RFC 1035).

use super::name::encode_name;
use super::parser::DNS_HEADER_LEN;
use super::types::{DnsClass, DnsRcode, DnsType};
use wireforge_core::util::write_u16be;

/// Builder for DNS messages.
pub struct DnsPacketBuilder {
    header: Vec<u8>,
    questions: Vec<Vec<u8>>,
    answers: Vec<Vec<u8>>,
    authorities: Vec<Vec<u8>>,
    additionals: Vec<Vec<u8>>,
}

impl Default for DnsPacketBuilder {
    fn default() -> Self { Self::new() }
}

impl DnsPacketBuilder {
    pub fn new() -> Self {
        Self {
            header: vec![0u8; DNS_HEADER_LEN],
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Preset for a standard query (QR=0, RD=1).
    pub fn query() -> Self {
        let mut s = Self::new();
        s.header[2] = 0x01; // RD=1
        s
    }

    /// Preset for a response (QR=1, RA=1).
    pub fn response() -> Self {
        let mut s = Self::new();
        s.header[2] = 0x80; // QR=1
        s.header[3] = 0x80; // RA=1
        s
    }

    pub fn transaction_id(mut self, id: u16) -> Self {
        write_u16be(&mut self.header[..2], id);
        self
    }

    pub fn authoritative(mut self, aa: bool) -> Self {
        if aa { self.header[2] |= 0x04; } else { self.header[2] &= !0x04; }
        self
    }

    pub fn truncated(mut self, tc: bool) -> Self {
        if tc { self.header[2] |= 0x02; } else { self.header[2] &= !0x02; }
        self
    }

    pub fn recursion_desired(mut self, rd: bool) -> Self {
        if rd { self.header[2] |= 0x01; } else { self.header[2] &= !0x01; }
        self
    }

    pub fn recursion_available(mut self, ra: bool) -> Self {
        if ra { self.header[3] |= 0x80; } else { self.header[3] &= !0x80; }
        self
    }

    pub fn rcode(mut self, rcode: DnsRcode) -> Self {
        let v: u8 = match rcode {
            DnsRcode::NoError => 0,
            DnsRcode::FormatError => 1,
            DnsRcode::ServerFailure => 2,
            DnsRcode::NameError => 3,
            DnsRcode::NotImplemented => 4,
            DnsRcode::Refused => 5,
            DnsRcode::Unknown(v) => v,
        };
        self.header[3] = (self.header[3] & 0xF0) | (v & 0x0F);
        self
    }

    /// Add a question entry.
    pub fn add_question(mut self, name: &str, qtype: DnsType, qclass: DnsClass) -> Self {
        let mut entry = encode_name(name);
        let qt: u16 = qtype.into();
        let qc: u16 = qclass.into();
        entry.extend_from_slice(&qt.to_be_bytes());
        entry.extend_from_slice(&qc.to_be_bytes());
        self.questions.push(entry);
        self
    }

    /// Add an answer record (pre-encoded RDATA).
    pub fn add_raw_answer(mut self, name: &str, qtype: DnsType, ttl: u32, rdata: &[u8]) -> Self {
        let mut entry = encode_name(name);
        let qt: u16 = qtype.into();
        entry.extend_from_slice(&qt.to_be_bytes());
        entry.extend_from_slice(&1u16.to_be_bytes()); // class IN
        entry.extend_from_slice(&ttl.to_be_bytes());
        entry.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        entry.extend_from_slice(rdata);
        self.answers.push(entry);
        self
    }

    /// Add an authority record.
    pub fn add_raw_authority(mut self, name: &str, qtype: DnsType, ttl: u32, rdata: &[u8]) -> Self {
        let mut entry = encode_name(name);
        let qt: u16 = qtype.into();
        entry.extend_from_slice(&qt.to_be_bytes());
        entry.extend_from_slice(&1u16.to_be_bytes());
        entry.extend_from_slice(&ttl.to_be_bytes());
        entry.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        entry.extend_from_slice(rdata);
        self.authorities.push(entry);
        self
    }

    /// Add an additional record.
    pub fn add_raw_additional(mut self, name: &str, qtype: DnsType, ttl: u32, rdata: &[u8]) -> Self {
        let mut entry = encode_name(name);
        let qt: u16 = qtype.into();
        entry.extend_from_slice(&qt.to_be_bytes());
        entry.extend_from_slice(&1u16.to_be_bytes());
        entry.extend_from_slice(&ttl.to_be_bytes());
        entry.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        entry.extend_from_slice(rdata);
        self.additionals.push(entry);
        self
    }

    /// Build the complete DNS message.
    pub fn build(mut self) -> Vec<u8> {
        write_u16be(&mut self.header[4..6], self.questions.len() as u16);
        write_u16be(&mut self.header[6..8], self.answers.len() as u16);
        write_u16be(&mut self.header[8..10], self.authorities.len() as u16);
        write_u16be(&mut self.header[10..12], self.additionals.len() as u16);

        let mut packet = self.header;
        for q in &self.questions {
            packet.extend_from_slice(q);
        }
        for a in &self.answers {
            packet.extend_from_slice(a);
        }
        for a in &self.authorities {
            packet.extend_from_slice(a);
        }
        for a in &self.additionals {
            packet.extend_from_slice(a);
        }
        packet
    }
}
