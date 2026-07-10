//! mDNS (Multicast DNS) parser — RFC 6762.
//!
//! mDNS shares the DNS wire format but uses the top bit of qclass for
//! the unicast-response flag and the cache-flush flag in resource records.

use crate::dns::parser::{DnsPacket, DnsQuestionIter, DnsRecordIter};

/// mDNS packet wrapper. Internally delegates to [`DnsPacket`] since
/// mDNS uses the identical DNS wire format (RFC 6762 §18).
#[derive(Debug, Clone)]
pub struct MdnsPacket<'a> {
    dns: DnsPacket<'a>,
}

impl<'a> MdnsPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        DnsPacket::new(buf).map(|dns| Self { dns })
    }

    pub fn is_query(&self) -> bool { !self.dns.qr() }
    pub fn is_response(&self) -> bool { self.dns.qr() }

    /// The unicast-response (QU) bit in the first question's class field.
    /// When set, responders should send a unicast reply (RFC 6762 §5.4).
    pub fn unicast_response_requested(&self) -> bool {
        self.dns.questions().next()
            .map(|q| u16::from(q.qclass) & 0x8000 != 0)
            .unwrap_or(false)
    }

    pub fn questions(&self) -> DnsQuestionIter<'a> { self.dns.questions() }
    pub fn answers(&self) -> DnsRecordIter<'a> { self.dns.answers() }
    pub fn authorities(&self) -> DnsRecordIter<'a> { self.dns.authorities() }
    pub fn additionals(&self) -> DnsRecordIter<'a> { self.dns.additionals() }
}

/// Check whether the cache-flush bit is set in a record class field
/// (RFC 6762 §10.2). Top bit of the 16-bit class means "flush cache."
#[inline]
pub fn is_cache_flush(class: u16) -> bool {
    class & 0x8000 != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::builder::DnsPacketBuilder;
    use crate::dns::types::{DnsClass, DnsType};

    #[test]
    fn parse_mdns_query() {
        let q = DnsPacketBuilder::query()
            .add_question("_http._tcp.local", DnsType::PTR, DnsClass::IN)
            .build();
        let p = MdnsPacket::new(&q).unwrap();
        assert!(p.is_query());
        assert!(!p.unicast_response_requested());
        let qs: Vec<_> = p.questions().collect();
        assert_eq!(qs.len(), 1);
    }

    #[test]
    fn parse_mdns_response() {
        let r = DnsPacketBuilder::response()
            .add_question("printer.local", DnsType::A, DnsClass::IN)
            .add_raw_answer("printer.local", DnsType::A, 120, &[192, 168, 1, 100])
            .build();
        let p = MdnsPacket::new(&r).unwrap();
        assert!(p.is_response());
    }

    #[test]
    fn unicast_response_bit() {
        // mDNS queries can set the QU bit (0x8000 in class field)
        // Build a query with QU bit set via raw class value
        let qu_class = DnsClass::Unknown(0x8001); // IN(1) with QU bit
        let q = DnsPacketBuilder::query()
            .add_question("test.local", DnsType::A, qu_class)
            .build();
        let p = MdnsPacket::new(&q).unwrap();
        assert!(p.unicast_response_requested());
    }
}
