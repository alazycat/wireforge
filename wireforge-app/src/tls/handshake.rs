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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_client_hello_handshake() {
        // handshake_type=1 (client_hello), length=3 (u24: 0x000003), body=3 bytes
        let data = &[0x01u8, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let hs = TlsHandshake::parse(data).unwrap();
        assert_eq!(hs.handshake_type(), 1);
        assert_eq!(hs.length(), 3);
        assert_eq!(hs.body(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn parse_too_short() {
        assert!(TlsHandshake::parse(&[]).is_none());
        assert!(TlsHandshake::parse(&[0x01, 0x00, 0x00]).is_none());
    }
}
