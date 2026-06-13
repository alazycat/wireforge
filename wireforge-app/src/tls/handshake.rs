//! TLS Handshake layer parser (RFC 8446 §4).

pub struct TlsHandshake<'a> { buf: &'a [u8] }

impl<'a> TlsHandshake<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 4 { return None; }
        Some(Self { buf })
    }

    pub fn handshake_type(&self) -> u8 { self.buf[0] }
    /// 3-byte big-endian length (RFC 8446: handshake length is u24)
    pub fn length(&self) -> u32 {
        u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]])
    }
    pub fn body(&self) -> &'a [u8] {
        let end = (4 + self.length() as usize).min(self.buf.len());
        &self.buf[4..end]
    }
}
