/// I/O error type for wireforge-io.
#[derive(Debug)]
pub enum IoError {
    /// Underlying socket error.
    Socket(std::io::Error),
    /// Packet parse failure.
    Parse(&'static str),
    /// Operation timed out.
    Timeout,
    /// Invalid pcap magic number.
    InvalidMagic(u32),
    /// Unsupported pcap/pcapng version.
    UnsupportedVersion { major: u16, minor: u16 },
    /// Truncated pcap record.
    TruncatedRecord { expected: u32, got: usize },
    /// DNS name label exceeds 63 bytes.
    NameTooLong(usize),
    /// DNS name compression pointer loop detected.
    CompressionLoop,
}

impl core::fmt::Display for IoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Socket(e) => write!(f, "socket error: {e}"),
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
            Self::Timeout => write!(f, "timeout"),
            Self::InvalidMagic(m) => write!(f, "invalid pcap magic number: 0x{m:08X}"),
            Self::UnsupportedVersion { major, minor } => {
                write!(f, "unsupported pcap version: {major}.{minor}")
            }
            Self::TruncatedRecord { expected, got } => {
                write!(f, "truncated pcap record: expected {expected} bytes, got {got}")
            }
            Self::NameTooLong(len) => write!(f, "DNS name label too long: {len} bytes (max 63)"),
            Self::CompressionLoop => write!(f, "DNS name compression loop detected"),
        }
    }
}

impl std::error::Error for IoError {}

impl From<std::io::Error> for IoError {
    fn from(e: std::io::Error) -> Self {
        IoError::Socket(e)
    }
}
