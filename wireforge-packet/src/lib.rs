//! WireForge Packet — unified packet enum and protocol dispatch.
//!
//! This crate provides a single `Packet` enum that can represent any
//! supported protocol layer, plus helper functions to automatically
//! dispatch from raw bytes to the correct protocol parser.

use wireforge_core::arp::ArpPacket;
use wireforge_core::ether::EthernetPacket;
use wireforge_core::icmp::{IcmpPacket, Icmpv6Packet};
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::ipv6::Ipv6Packet;
use wireforge_core::tcp::TcpPacket;
use wireforge_core::udp::UdpPacket;
use wireforge_core::types::{EtherType, IpProtocol};

/// Unified packet enum covering all supported L2–L4 protocols.
#[derive(Debug, Clone)]
pub enum Packet<'a> {
    Ethernet(EthernetPacket<'a>),
    Arp(ArpPacket<'a>),
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Icmp(IcmpPacket<'a>),
    Icmpv6(Icmpv6Packet<'a>),
}

// From impls for easy conversion
impl<'a> From<EthernetPacket<'a>> for Packet<'a> {
    fn from(p: EthernetPacket<'a>) -> Self { Packet::Ethernet(p) }
}

impl<'a> From<ArpPacket<'a>> for Packet<'a> {
    fn from(p: ArpPacket<'a>) -> Self { Packet::Arp(p) }
}

impl<'a> From<Ipv4Packet<'a>> for Packet<'a> {
    fn from(p: Ipv4Packet<'a>) -> Self { Packet::Ipv4(p) }
}

impl<'a> From<Ipv6Packet<'a>> for Packet<'a> {
    fn from(p: Ipv6Packet<'a>) -> Self { Packet::Ipv6(p) }
}

impl<'a> From<TcpPacket<'a>> for Packet<'a> {
    fn from(p: TcpPacket<'a>) -> Self { Packet::Tcp(p) }
}

impl<'a> From<UdpPacket<'a>> for Packet<'a> {
    fn from(p: UdpPacket<'a>) -> Self { Packet::Udp(p) }
}

impl<'a> From<IcmpPacket<'a>> for Packet<'a> {
    fn from(p: IcmpPacket<'a>) -> Self { Packet::Icmp(p) }
}

impl<'a> From<Icmpv6Packet<'a>> for Packet<'a> {
    fn from(p: Icmpv6Packet<'a>) -> Self { Packet::Icmpv6(p) }
}

/// Parse an Ethernet frame and dispatch the encapsulated protocol.
///
/// Returns the parsed `EthernetPacket` and, if the EtherType matches a
/// known protocol, the inner `Packet` as well.
pub fn parse_ethernet_frame(buf: &[u8]) -> Option<(EthernetPacket<'_>, Option<Packet<'_>>)> {
    let eth = EthernetPacket::new(buf)?;
    let inner = match eth.ethertype() {
        EtherType::Arp => ArpPacket::new(eth.payload()).map(Packet::Arp),
        EtherType::Ipv4 => Ipv4Packet::new(eth.payload()).map(Packet::Ipv4),
        EtherType::Ipv6 => Ipv6Packet::new(eth.payload()).map(Packet::Ipv6),
        _ => None,
    };
    Some((eth, inner))
}

/// Dispatch the payload of an IPv4 packet to the correct transport-layer parser.
pub fn parse_ipv4_payload<'a>(ip: &Ipv4Packet<'a>) -> Option<Packet<'a>> {
    match ip.protocol() {
        IpProtocol::Icmp => IcmpPacket::new(ip.payload()).map(Packet::Icmp),
        IpProtocol::Tcp => TcpPacket::new(ip.payload()).map(Packet::Tcp),
        IpProtocol::Udp => UdpPacket::new(ip.payload()).map(Packet::Udp),
        _ => None,
    }
}

/// Dispatch the payload of an IPv6 packet (skipping extension headers).
pub fn parse_ipv6_payload<'a>(ip: &Ipv6Packet<'a>) -> Option<Packet<'a>> {
    match ip.final_protocol() {
        IpProtocol::Icmpv6 => Icmpv6Packet::new(ip.payload()).map(Packet::Icmpv6),
        IpProtocol::Tcp => TcpPacket::new(ip.payload()).map(Packet::Tcp),
        IpProtocol::Udp => UdpPacket::new(ip.payload()).map(Packet::Udp),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireforge_core::ipv4::Ipv4PacketBuilder;
    use wireforge_core::udp::UdpPacketBuilder;

    #[test]
    fn dispatch_ethernet_to_ipv4_to_tcp() {
        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .ttl(64)
            .build();

        let mut frame = vec![0xFFu8; 12]; // dst + src mac
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType::Ipv4
        frame.extend_from_slice(&ip_bytes);

        let (eth, inner) = parse_ethernet_frame(&frame).unwrap();
        assert_eq!(eth.ethertype(), EtherType::Ipv4);
        assert!(matches!(inner, Some(Packet::Ipv4(_))));
    }

    #[test]
    fn dispatch_ethernet_to_arp() {
        // Build a valid ARP request (28 bytes minimum)
        let mut arp_bytes = vec![0x00u8, 0x01]; // hw_type=Ethernet
        arp_bytes.extend_from_slice(&[0x08, 0x00]); // proto_type=IPv4
        arp_bytes.push(6);  // hw_addr_len
        arp_bytes.push(4);  // proto_addr_len
        arp_bytes.extend_from_slice(&[0x00, 0x01]); // operation=Request
        arp_bytes.extend_from_slice(&[0x00u8; 20]); // addresses (6+4+6+4)

        let mut frame = vec![0xFFu8; 12];
        frame.extend_from_slice(&[0x08, 0x06]); // EtherType::Arp
        frame.extend_from_slice(&arp_bytes);

        let (eth, inner) = parse_ethernet_frame(&frame).unwrap();
        assert_eq!(eth.ethertype(), EtherType::Arp);
        assert!(matches!(inner, Some(Packet::Arp(_))));
    }

    #[test]
    fn dispatch_ethernet_to_ipv6() {
        // Build a minimal IPv6 header (40 bytes)
        let mut frame = vec![0xFFu8; 12];
        frame.extend_from_slice(&[0x86, 0xDD]); // EtherType::Ipv6
        let mut ip6 = vec![0x60u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x40]; // TC+flow=0, payload=0, next=ICMPv6, hop=64
        ip6.extend_from_slice(&[0u8; 32]); // src + dst = ::
        frame.extend_from_slice(&ip6);

        let (eth, inner) = parse_ethernet_frame(&frame).unwrap();
        assert_eq!(eth.ethertype(), EtherType::Ipv6);
        assert!(matches!(inner, Some(Packet::Ipv6(_))));
    }

    #[test]
    fn dispatch_ipv4_to_udp() {
        let udp_bytes = UdpPacketBuilder::new()
            .source_port(12345)
            .destination_port(53)
            .payload(&[0x01])
            .build(std::net::Ipv4Addr::new(10, 0, 0, 1), std::net::Ipv4Addr::new(10, 0, 0, 2));

        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Udp)
            .ttl(64)
            .payload(&udp_bytes).unwrap()
            .build();

        let ip = Ipv4Packet::new(&ip_bytes).unwrap();
        let inner = parse_ipv4_payload(&ip);
        assert!(matches!(inner, Some(Packet::Udp(_))));
    }

    #[test]
    fn dispatch_ipv4_to_icmp() {
        use wireforge_core::icmp::IcmpPacketBuilder;
        let icmp_bytes = IcmpPacketBuilder::echo_request()
            .identifier(1).sequence_number(1)
            .payload(b"ping")
            .build();

        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Icmp)
            .ttl(64)
            .payload(&icmp_bytes).unwrap()
            .build();

        let ip = Ipv4Packet::new(&ip_bytes).unwrap();
        let inner = parse_ipv4_payload(&ip);
        assert!(matches!(inner, Some(Packet::Icmp(_))));
    }
}
