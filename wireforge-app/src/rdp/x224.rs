pub const X224_CR: u8 = 0xE0;
pub const X224_CC: u8 = 0xD0;
pub struct X224Header<'a> { buf: &'a [u8] }
impl<'a> X224Header<'a> {
    pub fn parse(buf:&'a[u8])->Option<Self>{
        if buf.is_empty(){return None;}
        Some(Self{buf})
    }
    pub fn length(&self)->u8 { self.buf[0] }
    pub fn type_(&self)->u8 { self.buf.get(1).copied().unwrap_or(0) }
    pub fn payload(&self)->&'a[u8] {
        let hdr_len=if self.type_()==X224_CR||self.type_()==X224_CC{7}else{3};
        &self.buf[hdr_len.min(self.buf.len())..]
    }
}

#[cfg(test)]mod tests{use super::*;
    #[test]fn parse_x224_cr(){
        let data=[0x2Au8,0xE0,0x00,0x00,0x00,0x00,0x00,0x01]; // len=42, type=CR(0xE0)
        let h=X224Header::parse(&data).unwrap();
        assert_eq!(h.length(),42);assert_eq!(h.type_(),X224_CR);
    }
}
