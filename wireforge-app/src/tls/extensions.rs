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
