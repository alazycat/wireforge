//! LLMNR (Link-Local Multicast Name Resolution) parser (RFC 4795).
use crate::dns::parser::{DnsPacket,DnsQuestionIter,DnsRecordIter};

pub struct LlmrPacket<'a> { dns: DnsPacket<'a> }
impl<'a> LlmrPacket<'a> {
    pub fn new(buf:&'a[u8])->Option<Self> { DnsPacket::new(buf).map(|dns|Self{dns}) }
    pub fn is_query(&self)->bool { !self.dns.qr() }
    pub fn is_response(&self)->bool { self.dns.qr() }
    pub fn questions(&self)->DnsQuestionIter<'a> { self.dns.questions() }
    pub fn answers(&self)->DnsRecordIter<'a> { self.dns.answers() }
}

#[cfg(test)]mod tests{use super::*;use crate::dns::builder::DnsPacketBuilder;use crate::dns::types::{DnsType,DnsClass};
    #[test]fn parse_llmnr_query(){
        let q=DnsPacketBuilder::query().add_question("wpad",DnsType::A,DnsClass::IN).build();
        let p=LlmrPacket::new(&q).unwrap();assert!(p.is_query());
    }
    #[test]fn parse_llmnr_response(){
        let r=DnsPacketBuilder::response().add_raw_answer("wpad",DnsType::A,30,&[10,0,0,1]).build();
        assert!(LlmrPacket::new(&r).unwrap().is_response());
    }
}
