//! SSH protocol identification — banner and key exchange init parsing (RFC 4253).

mod banner;
mod kex;

pub use banner::SshBanner;
pub use kex::{SshBinaryPacket, SshKexInit};

/// Unified SSH identification payload.
///
/// SSH traffic on port 22 starts with either a plaintext banner line
/// (`SSH-2.0-...`) or, after the banner, a binary packet containing
/// `SSH_MSG_KEXINIT`. This enum wraps both possibilities so that a single
/// port-based dispatch can return either one.
#[derive(Debug, Clone)]
pub enum SshPacket<'a> {
    Banner(SshBanner<'a>),
    KexInit(SshKexInit<'a>),
}

impl<'a> SshPacket<'a> {
    /// Try to parse an SSH payload.
    ///
    /// First attempts to parse a banner line; if that fails, attempts to
    /// parse a binary `SSH_MSG_KEXINIT` packet.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        SshBanner::parse(buf)
            .map(SshPacket::Banner)
            .or_else(|| SshKexInit::parse(buf).map(SshPacket::KexInit))
    }
}
