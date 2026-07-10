use core::net::Ipv4Addr;
use super::types::RadiusCode;

pub const RADIUS_MIN_LEN: usize = 20;

#[derive(Debug, Clone)]
pub struct RadiusPacket<'a> { buf: &'a [u8] }
impl<'a> RadiusPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> { if buf.len()<RADIUS_MIN_LEN{return None;} Some(Self{buf}) }
    pub fn code(&self)->RadiusCode { RadiusCode::from(self.buf[0]) }
    pub fn identifier(&self)->u8 { self.buf[1] }
    pub fn length(&self)->u16 { u16::from_be_bytes([self.buf[2],self.buf[3]]) }
    /// 16-byte authenticator at offset 4. `new()` guarantees buf.len() >= 20.
    pub fn authenticator(&self) -> &[u8; 16] { self.buf[4..20].try_into().unwrap() }
    pub fn attributes(&self)->RadiusAttributeIter<'a> { RadiusAttributeIter{data:&self.buf[20..]} }
}

#[derive(Debug,Clone)]
pub enum RadiusAttribute { UserName(String),UserPassword(Vec<u8>),NasIpAddress(Ipv4Addr),NasPort(u32),ServiceType(u32),FramedProtocol(u32),CallingStationId(String),NasIdentifier(String),AcctStatusType(u32),AcctSessionId(String),Unknown{type_:u8,data:Vec<u8>} }

pub struct RadiusAttributeIter<'a> { data: &'a [u8] }
impl<'a> Iterator for RadiusAttributeIter<'a> {
    type Item = RadiusAttribute;
    fn next(&mut self)->Option<Self::Item> {
        if self.data.len()<2{return None;}
        let t=self.data[0];let len=self.data[1] as usize;
        if len<2||self.data.len()<len{return None;}
        let val=&self.data[2..len];self.data=&self.data[len..];
        Some(match t{
            1=>RadiusAttribute::UserName(String::from_utf8_lossy(val).into_owned()),
            2=>RadiusAttribute::UserPassword(val.to_vec()),
            4=>RadiusAttribute::NasIpAddress(Ipv4Addr::new(val[0],val[1],val[2],val[3])),
            5=>RadiusAttribute::NasPort(u32::from_be_bytes([val[0],val[1],val[2],val[3]])),
            6=>RadiusAttribute::ServiceType(u32::from_be_bytes([val[0],val[1],val[2],val[3]])),
            7=>RadiusAttribute::FramedProtocol(u32::from_be_bytes([val[0],val[1],val[2],val[3]])),
            31=>RadiusAttribute::CallingStationId(String::from_utf8_lossy(val).into_owned()),
            32=>RadiusAttribute::NasIdentifier(String::from_utf8_lossy(val).into_owned()),
            40=>RadiusAttribute::AcctStatusType(u32::from_be_bytes([val[0],val[1],val[2],val[3]])),
            44=>RadiusAttribute::AcctSessionId(String::from_utf8_lossy(val).into_owned()),
            _=>RadiusAttribute::Unknown{type_:t,data:val.to_vec()},
        })
    }
}

#[cfg(test)]mod tests{use super::*;
    fn build_pkt(code:u8,id:u8,attrs:&[u8])->Vec<u8>{
        let mut v=vec![code,id,0,20];v.extend_from_slice(&[0u8;16]);v.extend_from_slice(attrs);
        let l=v.len()as u16;v[2]=(l>>8)as u8;v[3]=l as u8;v
    }
    #[test]fn parse_access_request(){
        let attrs=[1u8,8,b't',b'e',b's',b't',b'e',b'r',2,4,0xAA,0xBB,0xCC,0xDD];
        let pkt=build_pkt(1,0,&attrs);
        let p=RadiusPacket::new(&pkt).unwrap();
        assert_eq!(p.code(),RadiusCode::AccessRequest);
        let avps:Vec<_>=p.attributes().collect();
        assert_eq!(avps.len(),2);
        match &avps[0]{RadiusAttribute::UserName(n)=>assert_eq!(n,"tester"),_=>panic!()}
    }
    #[test]fn parse_access_accept(){
        let attrs=[6u8,6,0,0,0,2,7,6,0,0,0,1];
        let b=build_pkt(2,1,&attrs);let p=RadiusPacket::new(&b).unwrap();
        assert_eq!(p.code(),RadiusCode::AccessAccept);
    }
    #[test]fn parse_accounting_request(){
        let attrs=[40u8,6,0,0,0,1,44,5,b'a',b'b',b'c'];
        let b=build_pkt(4,2,&attrs);let p=RadiusPacket::new(&b).unwrap();
        assert_eq!(p.code(),RadiusCode::AccountingRequest);
    }
    #[test]fn parse_too_short(){assert!(RadiusPacket::new(&[]).is_none());assert!(RadiusPacket::new(&[0u8;19]).is_none());}
}
