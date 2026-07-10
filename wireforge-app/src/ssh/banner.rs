//! SSH banner line parser (RFC 4253 §4.2).

use std::str;

#[derive(Debug, Clone)]
pub struct SshBanner<'a> { buf: &'a [u8], proto_end: usize, sw_end: usize }

impl<'a> SshBanner<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        let text = str::from_utf8(buf).ok()?;
        if !text.starts_with("SSH-") { return None; }
        let line = if let Some(pos) = text.find("\r\n") { &text[..pos] } else { text };
        let proto = &line[4..]; // after "SSH-"
        let dash = proto.find('-')?;
        let proto_end = 4 + dash;
        let sw_end = line.len();
        Some(Self { buf, proto_end, sw_end })
    }

    pub fn protocol_version(&self) -> &str {
        str::from_utf8(&self.buf[4..self.proto_end]).unwrap_or("")
    }

    pub fn software(&self) -> &str {
        str::from_utf8(&self.buf[self.proto_end + 1..self.sw_end]).unwrap_or("")
    }

    pub fn raw(&self) -> &str {
        str::from_utf8(&self.buf[..self.sw_end]).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openssh_banner() {
        let data = b"SSH-2.0-OpenSSH_8.9\r\n";
        let b = SshBanner::parse(data).unwrap();
        assert_eq!(b.protocol_version(), "2.0");
        assert_eq!(b.software(), "OpenSSH_8.9");
    }

    #[test]
    fn parse_dropbear_banner() {
        let data = b"SSH-2.0-dropbear_2022.83\r\n";
        let b = SshBanner::parse(data).unwrap();
        assert_eq!(b.software(), "dropbear_2022.83");
    }

    #[test]
    fn parse_not_ssh() {
        assert!(SshBanner::parse(b"GET / HTTP/1.1\r\n").is_none());
    }
}
