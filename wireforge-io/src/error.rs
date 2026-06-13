/// I/O error type for wireforge-io.
#[derive(Debug)]
pub enum IoError {
    /// Underlying socket error.
    Socket(std::io::Error),
    /// Packet parse failure.
    Parse(&'static str),
    /// Operation timed out.
    Timeout,
}

impl core::fmt::Display for IoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Socket(e) => write!(f, "socket error: {e}"),
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
            Self::Timeout => write!(f, "timeout"),
        }
    }
}

impl std::error::Error for IoError {}

impl From<std::io::Error> for IoError {
    fn from(e: std::io::Error) -> Self {
        IoError::Socket(e)
    }
}
