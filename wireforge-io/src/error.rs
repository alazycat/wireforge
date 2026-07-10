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
    /// Specified interface does not exist.
    InterfaceNotFound(String),
    /// Permission denied (root or Administrator required).
    PermissionDenied,
    /// BPF-specific error (macOS/BSD).
    Bpf(&'static str),
    /// NPcap-specific error (Windows).
    Npcap(String),
    /// Operation not supported on the current platform.
    UnsupportedPlatform,
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
            Self::InterfaceNotFound(name) => write!(f, "interface not found: {name}"),
            Self::PermissionDenied => write!(f, "permission denied (root/Administrator required)"),
            Self::Bpf(msg) => write!(f, "BPF error: {msg}"),
            Self::Npcap(msg) => write!(f, "NPcap error: {msg}"),
            Self::UnsupportedPlatform => write!(f, "operation not supported on this platform"),
        }
    }
}

impl std::error::Error for IoError {}

impl From<std::io::Error> for IoError {
    fn from(e: std::io::Error) -> Self {
        IoError::Socket(e)
    }
}
