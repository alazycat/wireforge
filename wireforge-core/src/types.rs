//! Common protocol type definitions used across all protocol modules.

/// A 48-bit IEEE 802 MAC address.
///
/// # Examples
///
/// ```
/// use wireforge_core::types::MacAddr;
/// use core::str::FromStr;
///
/// let mac = MacAddr::from_str("aa:bb:cc:dd:ee:ff").unwrap();
/// assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
/// assert_eq!(mac.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// The broadcast address `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);
    /// The unspecified (all-zero) address `00:00:00:00:00:00`.
    pub const UNSPECIFIED: Self = Self([0x00; 6]);

    /// The six octets of this address.
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> Self {
        mac.0
    }
}

impl core::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let o = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

impl core::fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MacAddr({})", self)
    }
}

/// Error returned when parsing a MAC address from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddrParseError(());

impl core::fmt::Display for MacAddrParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid MAC address")
    }
}

impl core::str::FromStr for MacAddr {
    type Err = MacAddrParseError;

    /// Parses a MAC address in one of the common textual forms:
    /// `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` or `aabbccddeeff`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut digits = [0u8; 12];
        let mut n = 0usize;
        for c in s.chars() {
            if c == ':' || c == '-' || c == '.' {
                continue;
            }
            let d = c.to_digit(16).ok_or(MacAddrParseError(()))? as u8;
            if n >= 12 {
                return Err(MacAddrParseError(()));
            }
            digits[n] = d;
            n += 1;
        }
        if n != 12 {
            return Err(MacAddrParseError(()));
        }
        let mut octets = [0u8; 6];
        for (i, o) in octets.iter_mut().enumerate() {
            *o = digits[2 * i] << 4 | digits[2 * i + 1];
        }
        Ok(Self(octets))
    }
}

#[cfg(feature = "serde")]
mod serde_impls {
    use super::MacAddr;

    impl serde::Serialize for MacAddr {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            if serializer.is_human_readable() {
                serializer.collect_str(self)
            } else {
                serializer.serialize_bytes(&self.0)
            }
        }
    }

    impl<'de> serde::Deserialize<'de> for MacAddr {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = MacAddr;

                fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str("a MAC address string or 6-byte array")
                }

                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<MacAddr, E> {
                    v.parse().map_err(E::custom)
                }

                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<MacAddr, E> {
                    if v.len() == 6 {
                        Ok(MacAddr([v[0], v[1], v[2], v[3], v[4], v[5]]))
                    } else {
                        Err(E::invalid_length(v.len(), &"6 bytes"))
                    }
                }

                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<MacAddr, A::Error> {
                    let mut octets = [0u8; 6];
                    for (i, o) in octets.iter_mut().enumerate() {
                        *o = seq
                            .next_element::<u8>()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &"6 bytes"))?;
                    }
                    Ok(MacAddr(octets))
                }
            }

            if deserializer.is_human_readable() {
                // Accept both the string form and a 6-element byte array.
                deserializer.deserialize_any(Visitor)
            } else {
                deserializer.deserialize_bytes(Visitor)
            }
        }
    }
}

/// Ethernet frame type (EtherType) — identifies the protocol encapsulated in an Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    AppleTalk,
    Ipx,
    /// Slow Protocols (LACP/802.3ad)
    SlowProtocols,
    Ppp,
    /// MPLS unicast
    MplsUnicast,
    /// MPLS multicast
    MplsMulticast,
    /// PPPoE discovery stage
    PppoeDiscovery,
    /// PPPoE session stage
    PppoeSession,
    /// EAP over LAN (802.1X)
    Eapol,
    /// Link Layer Discovery Protocol
    Lldp,
    /// MAC security (802.1AE)
    Macsec,
    /// Precision Time Protocol
    Ptp,
    /// Fibre Channel over Ethernet
    Fcoe,
    /// Ethernet loopback testing
    Loopback,
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
            0x809B => Self::AppleTalk,
            0x8137 => Self::Ipx,
            0x8809 => Self::SlowProtocols,
            0x880B => Self::Ppp,
            0x8847 => Self::MplsUnicast,
            0x8848 => Self::MplsMulticast,
            0x8863 => Self::PppoeDiscovery,
            0x8864 => Self::PppoeSession,
            0x888E => Self::Eapol,
            0x88CC => Self::Lldp,
            0x88E5 => Self::Macsec,
            0x88F7 => Self::Ptp,
            0x8906 => Self::Fcoe,
            0x9000 => Self::Loopback,
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
            EtherType::AppleTalk => 0x809B,
            EtherType::Ipx => 0x8137,
            EtherType::SlowProtocols => 0x8809,
            EtherType::Ppp => 0x880B,
            EtherType::MplsUnicast => 0x8847,
            EtherType::MplsMulticast => 0x8848,
            EtherType::PppoeDiscovery => 0x8863,
            EtherType::PppoeSession => 0x8864,
            EtherType::Eapol => 0x888E,
            EtherType::Lldp => 0x88CC,
            EtherType::Macsec => 0x88E5,
            EtherType::Ptp => 0x88F7,
            EtherType::Fcoe => 0x8906,
            EtherType::Loopback => 0x9000,
            EtherType::Unknown(v) => v,
        }
    }
}

/// IP protocol number — identifies the transport-layer protocol carried in an IP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpProtocol {
    /// IPv6 hop-by-hop option (0)
    Hopopt,
    Icmp,
    Igmp,
    /// Exterior Gateway Protocol (8)
    Egp,
    /// Interior Gateway Protocol (9)
    Igp,
    Tcp,
    Udp,
    Icmpv6,
    Gre,
    /// Reliable Data Protocol (27, RFC 908)
    Rdp,
    /// IPv6 encapsulation (41)
    Ipv6,
    /// Routing header for IPv6 (43)
    Ipv6Route,
    /// Fragment header for IPv6 (44)
    Ipv6Fragment,
    /// Resource Reservation Protocol (46)
    Rsvp,
    /// Encapsulating Security Payload (50)
    Esp,
    /// Authentication Header (51)
    Ah,
    /// No Next Header for IPv6 (59)
    NoNextHeader,
    /// Destination Options for IPv6 (60)
    Ipv6DestinationOptions,
    /// Cisco EIGRP (88)
    Eigrp,
    /// Open Shortest Path First (89)
    Ospf,
    /// Ethernet-in-IP tunneling (97)
    EtherIp,
    /// IP-within-IP encapsulation (98)
    Encap,
    /// Protocol Independent Multicast (103)
    Pim,
    /// Layer Two Tunneling Protocol (115)
    L2tp,
    /// Stream Control Transmission Protocol (132)
    Sctp,
    /// UDP-Lite (136)
    Udplite,
    /// MPLS-in-IP (137)
    MplsInIp,
    /// Host Identity Protocol (139)
    Hip,
    /// Shim6: Level 3 Multihoming Shim Protocol for IPv6 (140)
    Shim6,
    /// Any other IP protocol number
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Hopopt,
            1 => Self::Icmp,
            2 => Self::Igmp,
            6 => Self::Tcp,
            8 => Self::Egp,
            9 => Self::Igp,
            17 => Self::Udp,
            27 => Self::Rdp,
            41 => Self::Ipv6,
            43 => Self::Ipv6Route,
            44 => Self::Ipv6Fragment,
            46 => Self::Rsvp,
            47 => Self::Gre,
            50 => Self::Esp,
            51 => Self::Ah,
            58 => Self::Icmpv6,
            59 => Self::NoNextHeader,
            60 => Self::Ipv6DestinationOptions,
            88 => Self::Eigrp,
            89 => Self::Ospf,
            97 => Self::EtherIp,
            98 => Self::Encap,
            103 => Self::Pim,
            115 => Self::L2tp,
            132 => Self::Sctp,
            136 => Self::Udplite,
            137 => Self::MplsInIp,
            139 => Self::Hip,
            140 => Self::Shim6,
            _ => Self::Unknown(v),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(p: IpProtocol) -> u8 {
        match p {
            IpProtocol::Hopopt => 0,
            IpProtocol::Icmp => 1,
            IpProtocol::Igmp => 2,
            IpProtocol::Tcp => 6,
            IpProtocol::Egp => 8,
            IpProtocol::Igp => 9,
            IpProtocol::Udp => 17,
            IpProtocol::Rdp => 27,
            IpProtocol::Ipv6 => 41,
            IpProtocol::Ipv6Route => 43,
            IpProtocol::Ipv6Fragment => 44,
            IpProtocol::Rsvp => 46,
            IpProtocol::Gre => 47,
            IpProtocol::Esp => 50,
            IpProtocol::Ah => 51,
            IpProtocol::Icmpv6 => 58,
            IpProtocol::NoNextHeader => 59,
            IpProtocol::Ipv6DestinationOptions => 60,
            IpProtocol::Eigrp => 88,
            IpProtocol::Ospf => 89,
            IpProtocol::EtherIp => 97,
            IpProtocol::Encap => 98,
            IpProtocol::Pim => 103,
            IpProtocol::L2tp => 115,
            IpProtocol::Sctp => 132,
            IpProtocol::Udplite => 136,
            IpProtocol::MplsInIp => 137,
            IpProtocol::Hip => 139,
            IpProtocol::Shim6 => 140,
            IpProtocol::Unknown(v) => v,
        }
    }
}

/// ARP operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    use alloc::string::ToString;

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

    #[test]
    fn macaddr_display_and_parse() {
        use core::str::FromStr;

        let mac = MacAddr::from_str("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(mac.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // dash, dot and compact separators are all accepted
        assert_eq!(MacAddr::from_str("aa-bb-cc-dd-ee-ff").unwrap(), mac);
        assert_eq!(MacAddr::from_str("aabb.ccdd.eeff").unwrap(), mac);
        assert_eq!(MacAddr::from_str("aabbccddeeff").unwrap(), mac);

        assert_eq!(MacAddr::from(MacAddr::BROADCAST.octets()), MacAddr::BROADCAST);
        assert_eq!(<[u8; 6]>::from(MacAddr::UNSPECIFIED), [0, 0, 0, 0, 0, 0]);
        assert_eq!(MacAddr::BROADCAST.to_string(), "ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn macaddr_parse_errors() {
        use core::str::FromStr;

        assert!(MacAddr::from_str("").is_err());
        assert!(MacAddr::from_str("aa:bb:cc:dd:ee").is_err());
        assert!(MacAddr::from_str("aa:bb:cc:dd:ee:ff:00").is_err());
        assert!(MacAddr::from_str("zz:bb:cc:dd:ee:ff").is_err());
        assert!(MacAddr::from_str("aa:bb:cc:dd:ee:fg").is_err());
    }

    #[test]
    fn ethertype_extended_constants() {
        for (raw, expected) in [
            (0x809Bu16, EtherType::AppleTalk),
            (0x8137, EtherType::Ipx),
            (0x8809, EtherType::SlowProtocols),
            (0x880B, EtherType::Ppp),
            (0x8847, EtherType::MplsUnicast),
            (0x8863, EtherType::PppoeDiscovery),
            (0x8864, EtherType::PppoeSession),
            (0x888E, EtherType::Eapol),
            (0x88CC, EtherType::Lldp),
            (0x88E5, EtherType::Macsec),
            (0x88F7, EtherType::Ptp),
            (0x8906, EtherType::Fcoe),
            (0x9000, EtherType::Loopback),
        ] {
            assert_eq!(EtherType::from(raw), expected);
            assert_eq!(u16::from(expected), raw);
        }
    }

    #[test]
    fn ip_protocol_extended_constants() {
        for (raw, expected) in [
            (0u8, IpProtocol::Hopopt),
            (8, IpProtocol::Egp),
            (9, IpProtocol::Igp),
            (27, IpProtocol::Rdp),
            (41, IpProtocol::Ipv6),
            (43, IpProtocol::Ipv6Route),
            (44, IpProtocol::Ipv6Fragment),
            (46, IpProtocol::Rsvp),
            (50, IpProtocol::Esp),
            (51, IpProtocol::Ah),
            (59, IpProtocol::NoNextHeader),
            (60, IpProtocol::Ipv6DestinationOptions),
            (88, IpProtocol::Eigrp),
            (89, IpProtocol::Ospf),
            (97, IpProtocol::EtherIp),
            (98, IpProtocol::Encap),
            (103, IpProtocol::Pim),
            (115, IpProtocol::L2tp),
            (132, IpProtocol::Sctp),
            (136, IpProtocol::Udplite),
            (137, IpProtocol::MplsInIp),
            (139, IpProtocol::Hip),
            (140, IpProtocol::Shim6),
        ] {
            assert_eq!(IpProtocol::from(raw), expected);
            assert_eq!(u8::from(expected), raw);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn macaddr_serde_roundtrip() {
        // Human-readable: MAC addresses serialize as strings.
        let json = serde_json::to_string(&MacAddr::BROADCAST).unwrap();
        assert_eq!(json, "\"ff:ff:ff:ff:ff:ff\"");
        let parsed: MacAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, MacAddr::BROADCAST);

        // A MAC address deserialized from a 6-element array also works.
        let from_array: MacAddr = serde_json::from_str("[1,2,3,4,5,6]").unwrap();
        assert_eq!(from_array.octets(), [1, 2, 3, 4, 5, 6]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn type_enums_serde_roundtrip() {
        for et in [EtherType::Ipv4, EtherType::Vlan, EtherType::Unknown(0x9999)] {
            let json = serde_json::to_string(&et).unwrap();
            assert_eq!(serde_json::from_str::<EtherType>(&json).unwrap(), et);
        }
        for p in [IpProtocol::Tcp, IpProtocol::Sctp, IpProtocol::Unknown(254)] {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(serde_json::from_str::<IpProtocol>(&json).unwrap(), p);
        }
    }
}
