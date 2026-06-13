pub struct RdpNegotiationRequest<'a> { buf: &'a [u8] }
impl<'a> RdpNegotiationRequest<'a> {
    pub fn parse(buf:&'a[u8])->Option<Self>{
        if buf.len()<8||buf[0]!=0{return None;} // type must be RDP_NEG_REQ(0)
        Some(Self{buf})
    }
    pub fn flags(&self)->u8 { self.buf[1] }
    pub fn requested_protocols(&self)->u32 { u32::from_le_bytes([self.buf[4],self.buf[5],self.buf[6],self.buf[7]]) }
}

#[cfg(test)]mod tests{use super::*;
    #[test]fn parse_rdp_negotiation(){
        let data=[0x00u8,0x00,0x00,0x08,0x07,0x00,0x00,0x00]; // type=0, len=8, protocols=0x07(RDP+TLS+NLA)
        let n=RdpNegotiationRequest::parse(&data).unwrap();
        assert_eq!(n.requested_protocols(),0x07);
    }
}
