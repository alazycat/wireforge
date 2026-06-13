//! HTTP/1.1 response line parser.

use super::headers::HeaderIter;

/// Parsed HTTP response (version, status code, reason, headers, body).
#[derive(Debug, Clone)]
pub struct HttpResponse<'a> {
    buf: &'a [u8],
    version_end: usize,
    status_start: usize,
    status_end: usize,
    reason_end: usize,
    headers_start: usize,
    body_start: usize,
}

impl<'a> HttpResponse<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        let response_line_end = buf.windows(2).position(|w| w == b"\r\n")?;
        let line = &buf[..response_line_end];

        let sp1 = line.iter().position(|&b| b == b' ')?;
        let sp2 = line[sp1 + 1..].iter().position(|&b| b == b' ')?;
        let sp2 = sp1 + 1 + sp2;

        let headers_start = response_line_end + 2;
        let body_start = find_body_start(&buf[headers_start..]).map(|p| headers_start + p);

        Some(Self {
            buf,
            version_end: sp1,
            status_start: sp1 + 1,
            status_end: sp2,
            reason_end: response_line_end,
            headers_start,
            body_start: body_start.unwrap_or(buf.len()),
        })
    }

    pub fn version(&self) -> &str { core::str::from_utf8(&self.buf[..self.version_end]).unwrap_or("") }
    pub fn status_code(&self) -> u16 {
        core::str::from_utf8(&self.buf[self.status_start..self.status_end])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
    pub fn reason(&self) -> &str { core::str::from_utf8(&self.buf[self.status_end + 1..self.reason_end]).unwrap_or("") }
    pub fn headers(&self) -> HeaderIter<'a> { HeaderIter::new(&self.buf[self.headers_start..self.body_start]) }
    pub fn body(&self) -> &[u8] { &self.buf[self.body_start..] }
}

fn find_body_start(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_200_ok() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<body>hello</body>";
        let resp = HttpResponse::parse(data).unwrap();
        assert_eq!(resp.version(), "HTTP/1.1");
        assert_eq!(resp.status_code(), 200);
        assert_eq!(resp.reason(), "OK");
        assert_eq!(resp.body(), b"<body>hello</body>");

        let headers: Vec<_> = resp.headers().collect();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, "Content-Type");
    }

    #[test]
    fn parse_404() {
        let data = b"HTTP/1.0 404 Not Found\r\n\r\n";
        let resp = HttpResponse::parse(data).unwrap();
        assert_eq!(resp.status_code(), 404);
        assert_eq!(resp.reason(), "Not Found");
        assert_eq!(resp.body(), b"");
    }

    #[test]
    fn parse_get_request() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req = crate::http::HttpRequest::parse(data).unwrap();
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/index.html");
        assert_eq!(req.version(), "HTTP/1.1");
        assert_eq!(req.body(), b"");

        let headers: Vec<_> = req.headers().collect();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, "Host");
    }
}
