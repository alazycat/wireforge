//! NTP protocol type definitions (RFC 5905).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtpMode {
    Reserved,
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    Control,
    Unknown(u8),
}

impl From<u8> for NtpMode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Reserved,
            1 => Self::SymmetricActive,
            2 => Self::SymmetricPassive,
            3 => Self::Client,
            4 => Self::Server,
            5 => Self::Broadcast,
            6 => Self::Control,
            _ => Self::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtpLeapIndicator {
    NoWarning,
    LastMinute61,
    LastMinute59,
    Alarm,
}

impl From<u8> for NtpLeapIndicator {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::NoWarning,
            1 => Self::LastMinute61,
            2 => Self::LastMinute59,
            3 => Self::Alarm,
            _ => Self::NoWarning,
        }
    }
}
