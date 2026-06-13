//! HTTP header parsing.

/// A parsed HTTP header (name, value pair).
#[derive(Debug, Clone)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a [u8],
}

/// Iterator over HTTP headers.
pub struct HeaderIter<'a> {
    data: &'a [u8],
}

impl<'a> HeaderIter<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data } }
}

impl<'a> Iterator for HeaderIter<'a> {
    type Item = Header<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() || self.data == b"\r\n" || self.data.starts_with(b"\r\n") {
            return None;
        }
        let end = self.data.windows(2).position(|w| w == b"\r\n")?;
        let line = &self.data[..end];
        self.data = &self.data[end + 2..];

        let colon = line.iter().position(|&b| b == b':')?;
        let name = core::str::from_utf8(&line[..colon]).ok()?.trim_end();
        let value = &line[colon + 1..];
        let value = if value.first() == Some(&b' ') { &value[1..] } else { value };

        Some(Header { name, value })
    }
}
