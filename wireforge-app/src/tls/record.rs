//! TLS Record layer parser (RFC 8446 §5.1).

pub struct TlsRecord<'a> { buf: &'a [u8] }

impl<'a> TlsRecord<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 5 { return None; }
        Some(Self { buf })
    }

    pub fn content_type(&self) -> u8 { self.buf[0] }
    pub fn version(&self) -> u16 { u16::from_be_bytes([self.buf[1], self.buf[2]]) }
    pub fn length(&self) -> u16 { u16::from_be_bytes([self.buf[3], self.buf[4]]) }
    pub fn fragment(&self) -> &'a [u8] {
        let end = (5 + self.length() as usize).min(self.buf.len());
        &self.buf[5..end]
    }
}
