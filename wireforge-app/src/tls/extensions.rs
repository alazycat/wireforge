//! TLS extensions parser.

/// A single TLS extension (type + data).
#[derive(Debug, Clone)]
pub struct TlsExtension<'a> {
    pub extension_type: u16,
    pub data: &'a [u8],
}

/// Iterator over TLS extensions.
pub struct TlsExtensionsIter<'a> { data: &'a [u8] }

impl<'a> TlsExtensionsIter<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data } }
}

impl<'a> Iterator for TlsExtensionsIter<'a> {
    type Item = TlsExtension<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < 4 { return None; }
        let ext_type = u16::from_be_bytes([self.data[0], self.data[1]]);
        let len = u16::from_be_bytes([self.data[2], self.data[3]]) as usize;
        if self.data.len() < 4 + len { return None; }
        let ext_data = &self.data[4..4 + len];
        self.data = &self.data[4 + len..];
        Some(TlsExtension { extension_type: ext_type, data: ext_data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterate_two_extensions() {
        // ext1: type=0x0000 (SNI), len=2, data=[0xAA,0xBB]
        // ext2: type=0x002b (supported_versions), len=1, data=[0x04]
        let data = &[0x00u8, 0x00, 0x00, 0x02, 0xAA, 0xBB,
                     0x00, 0x2b, 0x00, 0x01, 0x04];
        let exts: Vec<_> = TlsExtensionsIter::new(data).collect();
        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0].extension_type, 0x0000);
        assert_eq!(exts[0].data, &[0xAA, 0xBB]);
        assert_eq!(exts[1].extension_type, 0x002b);
        assert_eq!(exts[1].data, &[0x04]);
    }

    #[test]
    fn iterator_empty() {
        let exts: Vec<_> = TlsExtensionsIter::new(&[]).collect();
        assert!(exts.is_empty());
    }

    #[test]
    fn iterator_truncated() {
        // len says 5 bytes but only 2 remain
        let data = &[0x00u8, 0x00, 0x00, 0x05, 0xAA];
        let exts: Vec<_> = TlsExtensionsIter::new(data).collect();
        assert!(exts.is_empty());
    }
}
