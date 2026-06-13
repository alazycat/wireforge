use super::types::NetbiosNameType;
use wireforge_core::util::read_u16be;

pub const NETBIOS_NS_MIN_LEN: usize = 12;

pub struct NetbiosNsPacket<'a> { buf: &'a [u8] }
impl<'a> NetbiosNsPacket<'a> {
    pub fn new(buf:&'a[u8])->Option<Self> { if buf.len()<NETBIOS_NS_MIN_LEN{return None;} Some(Self{buf}) }
    pub fn transaction_id(&self)->u16 { read_u16be(&self.buf[..2]) }
    pub fn flags(&self)->u16 { read_u16be(&self.buf[2..4]) }
    pub fn is_query(&self)->bool { self.flags()&0x8000==0 }
    pub fn opcode(&self)->u8 { ((self.flags()>>11)&0x0F)as u8 }
    pub fn is_broadcast(&self)->bool { self.flags()&0x0010!=0 }
    pub fn is_truncated(&self)->bool { self.flags()&0x0002!=0 }
    pub fn is_recursion_desired(&self)->bool { self.flags()&0x0100!=0 }
    pub fn question_name(&self)->String { decode_nb_name(&self.buf[12..44].try_into().unwrap_or([0u8;32])) }
    pub fn question_type(&self)->NetbiosNameType { NetbiosNameType::from(read_u16be(&self.buf[44..46])) }
}

fn decode_nb_name(encoded: &[u8;32]) -> String {
    let mut name=String::with_capacity(16);
    for i in 0..16 {
        let hi=encoded[i*2].wrapping_sub(b'A');
        let lo=encoded[i*2+1].wrapping_sub(b'A');
        name.push(((hi<<4)|lo)as char);
    }
    name.trim_end().to_string()
}

#[cfg(test)]mod tests{use super::*;
    #[test]fn decode_workstation(){
        let mut enc=[0u8;32];for(i,b)in b"WORKSTATION1    ".iter().enumerate(){enc[i*2]=(b>>4)+0x41;enc[i*2+1]=(b&0x0F)+0x41;}
        assert_eq!(decode_nb_name(&enc),"WORKSTATION1");
    }
    #[test]fn parse_name_query(){
        let mut data=vec![0x00,0x01,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00];
        let mut enc=[0u8;32];let name=b"HOST1           ";for(i,b)in name.iter().enumerate(){enc[i*2]=(b>>4)+0x41;enc[i*2+1]=(b&0x0F)+0x41;}
        data.extend_from_slice(&enc);data.extend_from_slice(&[0x00,0x20,0x00,0x01]);
        let p=NetbiosNsPacket::new(&data).unwrap();
        assert!(p.is_query());assert_eq!(p.question_name(),"HOST1");assert_eq!(p.question_type(),NetbiosNameType::NB);
    }
}
