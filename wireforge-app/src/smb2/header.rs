use super::types::Smb2Command;
pub const SMB2_HEADER_LEN: usize = 64;
pub struct Smb2Header<'a> { buf: &'a [u8] }
impl<'a> Smb2Header<'a> {
    pub fn parse(buf:&'a[u8])->Option<Self>{ if buf.len()<SMB2_HEADER_LEN{None}else if &buf[4..8]!=b"\xfeSMB"{None}else{Some(Self{buf})} }
    pub fn command(&self)->Smb2Command { Smb2Command::from(u16::from_le_bytes([self.buf[12],self.buf[13]])) }
    pub fn status(&self)->u32 { u32::from_le_bytes([self.buf[8],self.buf[9],self.buf[10],self.buf[11]]) }
    pub fn credits(&self)->u16 { u16::from_le_bytes([self.buf[14],self.buf[15]]) }
    pub fn message_id(&self)->u64 { u64::from_le_bytes(self.buf[24..32].try_into().unwrap()) }
    pub fn session_id(&self)->u64 { u64::from_le_bytes(self.buf[40..48].try_into().unwrap()) }
    pub fn body(&self)->&'a[u8] { &self.buf[SMB2_HEADER_LEN..] }
}

#[cfg(test)]mod tests{use super::*;
    #[test]fn parse_smb2_header(){
        let mut hdr=[0u8;64];hdr[4..8].copy_from_slice(b"\xfeSMB");hdr[12]=0; // Negotiate
        let h=Smb2Header::parse(&hdr).unwrap();
        assert_eq!(h.command(),Smb2Command::Negotiate);
    }
}
