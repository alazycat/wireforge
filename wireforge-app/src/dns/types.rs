//! DNS protocol type definitions.

/// DNS record type (QTYPE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    SRV,
    Unknown(u16),
}

impl From<u16> for DnsType {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            12 => Self::PTR,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            33 => Self::SRV,
            _ => Self::Unknown(v),
        }
    }
}

impl From<DnsType> for u16 {
    fn from(t: DnsType) -> u16 {
        match t {
            DnsType::A => 1,
            DnsType::NS => 2,
            DnsType::CNAME => 5,
            DnsType::SOA => 6,
            DnsType::PTR => 12,
            DnsType::MX => 15,
            DnsType::TXT => 16,
            DnsType::AAAA => 28,
            DnsType::SRV => 33,
            DnsType::Unknown(v) => v,
        }
    }
}

/// DNS class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsClass {
    IN,
    CS,
    CH,
    HS,
    Unknown(u16),
}

impl From<u16> for DnsClass {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            _ => Self::Unknown(v),
        }
    }
}

impl From<DnsClass> for u16 {
    fn from(c: DnsClass) -> u16 {
        match c {
            DnsClass::IN => 1,
            DnsClass::CS => 2,
            DnsClass::CH => 3,
            DnsClass::HS => 4,
            DnsClass::Unknown(v) => v,
        }
    }
}

/// DNS opcode (from header flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOpcode {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Unknown(u8),
}

impl From<u8> for DnsOpcode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            _ => Self::Unknown(v),
        }
    }
}

/// DNS response code (from header flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Unknown(u8),
}

impl From<u8> for DnsRcode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            _ => Self::Unknown(v),
        }
    }
}
