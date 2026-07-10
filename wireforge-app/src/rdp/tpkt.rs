pub const TPKT_MIN_LEN: usize = 4;
#[derive(Debug, Clone)]
pub struct TpktHeader<'a> { buf: &'a [u8] }
impl<'a> TpktHeader<'a> {
    pub fn parse(buf:&'a[u8])->Option<Self>{
        if buf.len()<TPKT_MIN_LEN||buf[0]!=3{return None;}
        Some(Self{buf})
    }
    pub fn version(&self)->u8 { self.buf[0] }
    pub fn length(&self)->u16 { u16::from_be_bytes([self.buf[2],self.buf[3]]) }
    pub fn payload(&self)->&'a[u8] { &self.buf[TPKT_MIN_LEN..] }
}

#[cfg(test)]mod tests{use super::*;
    #[test]fn parse_tpkt(){
        let data=[0x03u8,0x00,0x00,0x2C,0xE0];
        let h=TpktHeader::parse(&data).unwrap();
        assert_eq!(h.version(),3);assert_eq!(h.length(),44);
        assert_eq!(h.payload(),&[0xE0]);
    }
}
