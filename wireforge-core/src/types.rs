//! Common protocol type definitions used across all protocol modules.

/// Ethernet frame type (EtherType) — identifies the protocol encapsulated in an Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    /// 802.1Q VLAN tag
    Vlan,
    /// 802.1ad double VLAN tag (QinQ)
    VlanDouble,
    WakeOnLan,
    Rarp,
    /// Any other EtherType value
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(v: u16) -> Self {
        match v {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86DD => Self::Ipv6,
            0x8100 => Self::Vlan,
            0x88A8 => Self::VlanDouble,
            0x0842 => Self::WakeOnLan,
            0x8035 => Self::Rarp,
            _ => Self::Unknown(v),
        }
    }
}

impl From<EtherType> for u16 {
    fn from(et: EtherType) -> u16 {
        match et {
            EtherType::Ipv4 => 0x0800,
            EtherType::Arp => 0x0806,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Vlan => 0x8100,
            EtherType::VlanDouble => 0x88A8,
            EtherType::WakeOnLan => 0x0842,
            EtherType::Rarp => 0x8035,
            EtherType::Unknown(v) => v,
        }
    }
}

/// IP protocol number — identifies the transport-layer protocol carried in an IP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpProtocol {
    Icmp,
    Igmp,
    Tcp,
    Udp,
    Icmpv6,
    Gre,
    /// Any other IP protocol number
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Icmp,
            2 => Self::Igmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            47 => Self::Gre,
            _ => Self::Unknown(v),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(p: IpProtocol) -> u8 {
        match p {
            IpProtocol::Icmp => 1,
            IpProtocol::Igmp => 2,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Icmpv6 => 58,
            IpProtocol::Gre => 47,
            IpProtocol::Unknown(v) => v,
        }
    }
}

/// ARP operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArpOperation {
    Request,
    Reply,
    RarpRequest,
    RarpReply,
    Unknown(u16),
}

impl From<u16> for ArpOperation {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::Request,
            2 => Self::Reply,
            3 => Self::RarpRequest,
            4 => Self::RarpReply,
            _ => Self::Unknown(v),
        }
    }
}

impl From<ArpOperation> for u16 {
    fn from(op: ArpOperation) -> u16 {
        match op {
            ArpOperation::Request => 1,
            ArpOperation::Reply => 2,
            ArpOperation::RarpRequest => 3,
            ArpOperation::RarpReply => 4,
            ArpOperation::Unknown(v) => v,
        }
    }
}

/// ARP hardware type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArpHardwareType {
    Ethernet,
    Unknown(u16),
}

impl From<u16> for ArpHardwareType {
    fn from(v: u16) -> Self {
        match v {
            1 => Self::Ethernet,
            _ => Self::Unknown(v),
        }
    }
}

impl From<ArpHardwareType> for u16 {
    fn from(ht: ArpHardwareType) -> u16 {
        match ht {
            ArpHardwareType::Ethernet => 1,
            ArpHardwareType::Unknown(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethertype_ipv4() {
        assert_eq!(EtherType::from(0x0800u16), EtherType::Ipv4);
        assert_eq!(u16::from(EtherType::Ipv4), 0x0800);
    }

    #[test]
    fn ethertype_unknown() {
        assert_eq!(EtherType::from(0x1234u16), EtherType::Unknown(0x1234));
        assert_eq!(u16::from(EtherType::Unknown(0x5678)), 0x5678);
    }

    #[test]
    fn ip_protocol_roundtrip() {
        assert_eq!(IpProtocol::from(6u8), IpProtocol::Tcp);
        assert_eq!(u8::from(IpProtocol::Tcp), 6);
        assert_eq!(IpProtocol::from(17u8), IpProtocol::Udp);
        assert_eq!(u8::from(IpProtocol::Udp), 17);
    }

    #[test]
    fn arp_operation_roundtrip() {
        assert_eq!(ArpOperation::from(1u16), ArpOperation::Request);
        assert_eq!(u16::from(ArpOperation::Request), 1);
        assert_eq!(ArpOperation::from(2u16), ArpOperation::Reply);
    }
}
