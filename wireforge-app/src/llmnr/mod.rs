//! LLMNR (Link-Local Multicast Name Resolution) parser — RFC 4795.
//!
//! LLMNR shares the DNS wire format. Unlike standard DNS, LLMNR queries
//! always contain exactly one question and the TC (truncation) bit has
//! different semantics (RFC 4795 §2.1.2).

use crate::dns::parser::{DnsPacket, DnsQuestionIter, DnsRecordIter};

/// LLMNR packet wrapper. Internally delegates to [`DnsPacket`] since
/// LLMNR uses the identical DNS wire format (RFC 4795 §2.1).
#[derive(Debug, Clone)]
pub struct LlmnrPacket<'a> {
    dns: DnsPacket<'a>,
}

impl<'a> LlmnrPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        DnsPacket::new(buf).map(|dns| Self { dns })
    }

    pub fn is_query(&self) -> bool { !self.dns.qr() }
    pub fn is_response(&self) -> bool { self.dns.qr() }

    /// LLMNR queries must contain exactly one question (RFC 4795 §2.3).
    pub fn is_valid_query(&self) -> bool {
        !self.dns.qr() && self.dns.questions_count() == 1
    }

    /// The C (conflict) bit in LLMNR responses (RFC 4795 §2.5).
    /// When set, multiple responders detected a name conflict.
    pub fn has_conflict(&self) -> bool {
        self.dns.qr() && (self.dns.flags() & 0x0040) != 0
    }

    pub fn questions(&self) -> DnsQuestionIter<'a> { self.dns.questions() }
    pub fn answers(&self) -> DnsRecordIter<'a> { self.dns.answers() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::builder::DnsPacketBuilder;
    use crate::dns::types::{DnsClass, DnsType};

    #[test]
    fn parse_llmnr_query() {
        let q = DnsPacketBuilder::query()
            .add_question("wpad", DnsType::A, DnsClass::IN)
            .build();
        let p = LlmnrPacket::new(&q).unwrap();
        assert!(p.is_query());
        assert!(p.is_valid_query());
    }

    #[test]
    fn parse_llmnr_response() {
        let r = DnsPacketBuilder::response()
            .add_raw_answer("wpad", DnsType::A, 30, &[10, 0, 0, 1])
            .build();
        assert!(LlmnrPacket::new(&r).unwrap().is_response());
    }
}
