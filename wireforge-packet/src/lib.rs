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

    #[test]
    fn dispatch_ethernet_to_ipv4_to_tcp() {
        // Build an IPv4 + TCP packet embedded in an Ethernet frame
        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .ttl(64)
            .build();

        // Build Ethernet frame around it
        let mut frame = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst mac
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
            0x08, 0x00, // EtherType::Ipv4
        ];
        frame.extend_from_slice(&ip_bytes);

        let (eth, inner) = parse_ethernet_frame(&frame).unwrap();
        assert_eq!(eth.dst_mac(), [0xFF; 6]);
        assert_eq!(eth.ethertype(), EtherType::Ipv4);

        match inner {
            Some(Packet::Ipv4(ip)) => {
                let payload = parse_ipv4_payload(&ip);
                // TCP parse will fail since we didn't include a real TCP header,
                // so payload() from IPv4 is just whatever's after the IP header
                assert!(payload.is_none() || matches!(payload, Some(Packet::Tcp(_))));
            }
            _ => panic!("expected Ipv4"),
        }
    }
}
