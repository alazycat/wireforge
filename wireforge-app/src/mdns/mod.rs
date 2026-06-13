//! mDNS (Multicast DNS) parser (RFC 6762). Internally delegates to DnsPacket.
use crate::dns::parser::{DnsPacket,DnsQuestionIter,DnsRecordIter};

pub struct MdnsPacket<'a> { dns: DnsPacket<'a> }
impl<'a> MdnsPacket<'a> {
    pub fn new(buf:&'a[u8])->Option<Self> { DnsPacket::new(buf).map(|dns|Self{dns}) }
    pub fn is_query(&self)->bool { !self.dns.qr() }
    pub fn is_response(&self)->bool { self.dns.qr() }
    pub fn questions(&self)->DnsQuestionIter<'a> { self.dns.questions() }
    pub fn answers(&self)->DnsRecordIter<'a> { self.dns.answers() }
    pub fn authorities(&self)->DnsRecordIter<'a> { self.dns.authorities() }
    pub fn additionals(&self)->DnsRecordIter<'a> { self.dns.additionals() }
}

#[cfg(test)]mod tests{use super::*;use crate::dns::builder::DnsPacketBuilder;use crate::dns::types::{DnsType,DnsClass};
    #[test]fn parse_mdns_query(){
        let q=DnsPacketBuilder::query().add_question("_http._tcp.local",DnsType::PTR,DnsClass::IN).build();
        let p=MdnsPacket::new(&q).unwrap();
        assert!(p.is_query());let qs:Vec<_>=p.questions().collect();assert_eq!(qs.len(),1);
    }
    #[test]fn parse_mdns_response(){
        let r=DnsPacketBuilder::response().add_question("printer.local",DnsType::A,DnsClass::IN).add_raw_answer("printer.local",DnsType::A,120,&[192,168,1,100]).build();
        let p=MdnsPacket::new(&r).unwrap();assert!(p.is_response());
    }
}
