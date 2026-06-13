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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_record() {
        let data = &[0x16u8, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        let rec = TlsRecord::parse(data).unwrap();
        assert_eq!(rec.content_type(), 0x16);
        assert_eq!(rec.version(), 0x0303);
        assert_eq!(rec.length(), 4);
        assert_eq!(rec.fragment(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn parse_too_short() {
        assert!(TlsRecord::parse(&[]).is_none());
        assert!(TlsRecord::parse(&[0x16, 0x03, 0x03, 0x00]).is_none());
    }
}
