//! HTTP/1.1 request line parser.

use super::headers::HeaderIter;

/// Parsed HTTP request (method, URI, version, headers, body).
#[derive(Debug, Clone)]
pub struct HttpRequest<'a> {
    buf: &'a [u8],
    method_end: usize,
    uri_end: usize,
    version_end: usize,
    headers_start: usize,
    body_start: usize,
}

impl<'a> HttpRequest<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        // Find "METHOD SP URI SP VERSION\r\n"
        let request_line_end = buf.windows(2).position(|w| w == b"\r\n")?;
        let line = &buf[..request_line_end];

        let sp1 = line.iter().position(|&b| b == b' ')?;
        let sp2 = line[sp1 + 1..].iter().position(|&b| b == b' ')?;
        let sp2 = sp1 + 1 + sp2;

        let headers_start = request_line_end + 2;
        let body_start = find_body_start(&buf[headers_start..]).map(|p| headers_start + p);

        Some(Self {
            buf,
            method_end: sp1,
            uri_end: sp2,
            version_end: request_line_end,
            headers_start,
            body_start: body_start.unwrap_or(buf.len()),
        })
    }

    pub fn method(&self) -> &str { core::str::from_utf8(&self.buf[..self.method_end]).unwrap_or("") }
    pub fn uri(&self) -> &str { core::str::from_utf8(&self.buf[self.method_end + 1..self.uri_end]).unwrap_or("") }
    pub fn version(&self) -> &str { core::str::from_utf8(&self.buf[self.uri_end + 1..self.version_end]).unwrap_or("") }
    pub fn headers(&self) -> HeaderIter<'a> { HeaderIter::new(&self.buf[self.headers_start..self.body_start]) }
    pub fn body(&self) -> &[u8] { &self.buf[self.body_start..] }
}

fn find_body_start(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}
