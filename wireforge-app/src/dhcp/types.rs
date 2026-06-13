//! DHCP protocol type definitions (RFC 2131/2132).

use core::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Declined,
    Ack,
    Nak,
    Release,
    Inform,
    Unknown(u8),
}

impl From<u8> for DhcpMessageType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Declined,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => Self::Unknown(v),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DnsServer(Vec<Ipv4Addr>),
    HostName(String),
    DomainName(String),
    BroadcastAddr(Ipv4Addr),
    RequestedIp(Ipv4Addr),
    LeaseTime(u32),
    MessageType(DhcpMessageType),
    ServerId(Ipv4Addr),
    ParameterList(Vec<u8>),
    RenewalTime(u32),
    RebindingTime(u32),
    End,
    Unknown { code: u8, data: Vec<u8> },
}
