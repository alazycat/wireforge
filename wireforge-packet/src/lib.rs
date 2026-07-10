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
#[non_exhaustive]
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

// ===========================================================================
// Visitor pattern — add operations on Packet without modifying the enum
// ===========================================================================

/// Visitor for type-safe dispatch across all [`Packet`] variants.
///
/// Implement this trait to add new operations over the packet hierarchy
/// without modifying the `Packet` enum itself (Open-Closed Principle).
/// Each `visit_*` method receives a reference to a concrete packet type.
pub trait PacketVisitor {
    type Output;

    fn visit_ethernet(&mut self, pkt: &EthernetPacket<'_>) -> Self::Output;
    fn visit_arp(&mut self, pkt: &ArpPacket<'_>) -> Self::Output;
    fn visit_ipv4(&mut self, pkt: &Ipv4Packet<'_>) -> Self::Output;
    fn visit_ipv6(&mut self, pkt: &Ipv6Packet<'_>) -> Self::Output;
    fn visit_tcp(&mut self, pkt: &TcpPacket<'_>) -> Self::Output;
    fn visit_udp(&mut self, pkt: &UdpPacket<'_>) -> Self::Output;
    fn visit_icmp(&mut self, pkt: &IcmpPacket<'_>) -> Self::Output;
    fn visit_icmpv6(&mut self, pkt: &Icmpv6Packet<'_>) -> Self::Output;
}

impl<'a> Packet<'a> {
    /// Accept a visitor — the double-dispatch entry point.
    ///
    /// This is the Visitor pattern's core mechanism: the `Packet` dispatches
    /// to the correct `visit_*` method based on its variant at runtime.
    pub fn accept<V: PacketVisitor>(&self, visitor: &mut V) -> V::Output {
        match self {
            Packet::Ethernet(p) => visitor.visit_ethernet(p),
            Packet::Arp(p) => visitor.visit_arp(p),
            Packet::Ipv4(p) => visitor.visit_ipv4(p),
            Packet::Ipv6(p) => visitor.visit_ipv6(p),
            Packet::Tcp(p) => visitor.visit_tcp(p),
            Packet::Udp(p) => visitor.visit_udp(p),
            Packet::Icmp(p) => visitor.visit_icmp(p),
            Packet::Icmpv6(p) => visitor.visit_icmpv6(p),
        }
    }

    // =======================================================================
    // Composite pattern — recursive protocol nesting
    // =======================================================================

    /// Return the encapsulated inner protocol, if any.
    ///
    /// This is the Composite pattern: each protocol layer can contain
    /// another, forming a recursive tree. Walk the full stack with:
    ///
    /// ```ignore
    /// let mut current = Some(packet);
    /// while let Some(p) = current {
    ///     println!("{}", p.protocol_name());
    ///     current = p.inner();
    /// }
    /// ```
    pub fn inner(&self) -> Option<Packet<'a>> {
        match self {
            Packet::Ethernet(eth) => {
                parse_ethernet_frame(eth.as_bytes()).and_then(|(_, inner)| inner)
            }
            Packet::Ipv4(ip) => parse_ipv4_payload(ip),
            Packet::Ipv6(ip) => parse_ipv6_payload(ip),
            // Leaf protocols — no further nesting
            Packet::Arp(_) | Packet::Tcp(_) | Packet::Udp(_)
            | Packet::Icmp(_) | Packet::Icmpv6(_) => None,
        }
    }

    /// Human-readable protocol name for this packet layer.
    pub fn protocol_name(&self) -> &'static str {
        match self {
            Packet::Ethernet(_) => "Ethernet",
            Packet::Arp(_) => "ARP",
            Packet::Ipv4(_) => "IPv4",
            Packet::Ipv6(_) => "IPv6",
            Packet::Tcp(_) => "TCP",
            Packet::Udp(_) => "UDP",
            Packet::Icmp(_) => "ICMP",
            Packet::Icmpv6(_) => "ICMPv6",
        }
    }
}

// ===========================================================================
// Concrete Visitors (built-in examples of the Visitor pattern)
// ===========================================================================

/// Visitor that collects the protocol stack as a Vec of human-readable names
/// (e.g. `["Ethernet", "IPv4", "TCP"]`).
pub struct ProtocolStackVisitor {
    pub stack: Vec<&'static str>,
}

impl ProtocolStackVisitor {
    pub fn new() -> Self { Self { stack: Vec::new() } }
}

impl Default for ProtocolStackVisitor {
    fn default() -> Self { Self::new() }
}

impl PacketVisitor for ProtocolStackVisitor {
    type Output = ();

    fn visit_ethernet(&mut self, _pkt: &EthernetPacket<'_>) {
        self.stack.push("Ethernet");
    }
    fn visit_arp(&mut self, _pkt: &ArpPacket<'_>) {
        self.stack.push("ARP");
    }
    fn visit_ipv4(&mut self, _pkt: &Ipv4Packet<'_>) {
        self.stack.push("IPv4");
    }
    fn visit_ipv6(&mut self, _pkt: &Ipv6Packet<'_>) {
        self.stack.push("IPv6");
    }
    fn visit_tcp(&mut self, _pkt: &TcpPacket<'_>) {
        self.stack.push("TCP");
    }
    fn visit_udp(&mut self, _pkt: &UdpPacket<'_>) {
        self.stack.push("UDP");
    }
    fn visit_icmp(&mut self, _pkt: &IcmpPacket<'_>) {
        self.stack.push("ICMP");
    }
    fn visit_icmpv6(&mut self, _pkt: &Icmpv6Packet<'_>) {
        self.stack.push("ICMPv6");
    }
}

/// Visitor that computes the total byte size of a packet and its payload.
pub struct PacketSizeVisitor {
    pub size: usize,
}

impl PacketSizeVisitor {
    pub fn new() -> Self { Self { size: 0 } }
}

impl Default for PacketSizeVisitor {
    fn default() -> Self { Self::new() }
}

impl PacketVisitor for PacketSizeVisitor {
    type Output = ();

    fn visit_ethernet(&mut self, pkt: &EthernetPacket<'_>) {
        self.size = pkt.as_bytes().len();
    }
    fn visit_arp(&mut self, pkt: &ArpPacket<'_>) {
        self.size = pkt.as_bytes().len();
    }
    fn visit_ipv4(&mut self, pkt: &Ipv4Packet<'_>) {
        self.size = pkt.as_bytes().len();
    }
    fn visit_ipv6(&mut self, pkt: &Ipv6Packet<'_>) {
        self.size = pkt.as_bytes().len();
    }
    fn visit_tcp(&mut self, pkt: &TcpPacket<'_>) {
        self.size = pkt.as_bytes().len();
    }
    fn visit_udp(&mut self, pkt: &UdpPacket<'_>) {
        self.size = pkt.as_bytes().len();
    }
    fn visit_icmp(&mut self, pkt: &IcmpPacket<'_>) {
        self.size = pkt.as_bytes().len();
    }
    fn visit_icmpv6(&mut self, pkt: &Icmpv6Packet<'_>) {
        self.size = pkt.as_bytes().len();
    }
}

/// Walk the full protocol stack recursively, collecting names at each layer.
///
/// This combines the **Composite** pattern (recursive `inner()` traversal)
/// with the **Visitor** pattern (type-safe dispatch at each level).
pub fn collect_protocol_stack(pkt: &Packet<'_>) -> Vec<&'static str> {
    let mut stack = Vec::new();
    let mut current = Some(pkt.clone());
    while let Some(p) = current {
        let mut visitor = ProtocolStackVisitor::new();
        p.accept(&mut visitor);
        stack.extend(visitor.stack);
        current = p.inner();
    }
    stack
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

    // -- Visitor pattern tests --

    #[test]
    fn visitor_protocol_name() {
        use wireforge_core::arp::ArpPacketBuilder;

        let bytes = ArpPacketBuilder::new()
            .sender_hw_addr(&[0xAA; 6]).unwrap()
            .sender_proto_addr(&[10, 0, 0, 1]).unwrap()
            .target_hw_addr(&[0xBB; 6]).unwrap()
            .target_proto_addr(&[10, 0, 0, 2]).unwrap()
            .build();

        let pkt = Packet::Arp(ArpPacket::new(&bytes).unwrap());

        let mut visitor = ProtocolStackVisitor::new();
        pkt.accept(&mut visitor);
        assert_eq!(visitor.stack, vec!["ARP"]);
    }

    #[test]
    fn visitor_packet_size() {
        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .ttl(64)
            .build();

        let ip = Ipv4Packet::new(&ip_bytes).unwrap();
        let pkt = Packet::Ipv4(ip.clone());

        let mut visitor = PacketSizeVisitor::new();
        pkt.accept(&mut visitor);
        assert_eq!(visitor.size, ip_bytes.len());
    }

    #[test]
    fn visitor_dispatches_all_variants() {
        // Build one of each packet type and verify accept() dispatches correctly.
        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .build();

        let ip = Ipv4Packet::new(&ip_bytes).unwrap();
        let pkt = Packet::Ipv4(ip);

        // Use accept() to get the protocol name
        let name = pkt.protocol_name();
        assert_eq!(name, "IPv4");

        let mut psv = ProtocolStackVisitor::new();
        pkt.accept(&mut psv);
        assert_eq!(psv.stack, vec!["IPv4"]);
    }

    // -- Composite pattern tests --

    #[test]
    fn composite_ethernet_to_ipv4_to_tcp() {
        use wireforge_core::tcp::TcpPacketBuilder;

        let tcp_bytes = TcpPacketBuilder::new()
            .source_port(12345)
            .destination_port(80)
            .sequence(1)
            .syn(true)
            .window(65535)
            .build(
                std::net::Ipv4Addr::new(10, 0, 0, 1),
                std::net::Ipv4Addr::new(10, 0, 0, 2),
            );

        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .payload(&tcp_bytes).unwrap()
            .build();

        let mut frame = vec![0xFFu8; 12]; // dst + src mac
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType::Ipv4
        frame.extend_from_slice(&ip_bytes);

        let (eth, _inner) = parse_ethernet_frame(&frame).unwrap();
        let ethernet_pkt = Packet::Ethernet(eth);

        // Composite: walk down the stack
        assert_eq!(ethernet_pkt.protocol_name(), "Ethernet");
        let l3 = ethernet_pkt.inner().unwrap();
        assert_eq!(l3.protocol_name(), "IPv4");
        let l4 = l3.inner().unwrap();
        assert_eq!(l4.protocol_name(), "TCP");
        // TCP is a leaf — no further nesting
        assert!(l4.inner().is_none());
    }

    #[test]
    fn collect_stack_ethernet_ipv4_tcp() {
        use wireforge_core::tcp::TcpPacketBuilder;

        let tcp_bytes = TcpPacketBuilder::new()
            .source_port(443)
            .destination_port(54321)
            .sequence(100)
            .syn(true)
            .window(8192)
            .build(
                std::net::Ipv4Addr::new(10, 0, 0, 1),
                std::net::Ipv4Addr::new(10, 0, 0, 2),
            );

        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .payload(&tcp_bytes).unwrap()
            .build();

        let mut frame = vec![0xFFu8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&ip_bytes);

        let (eth, _) = parse_ethernet_frame(&frame).unwrap();
        let pkt = Packet::Ethernet(eth);

        let stack = collect_protocol_stack(&pkt);
        assert_eq!(stack, vec!["Ethernet", "IPv4", "TCP"]);
    }

    #[test]
    fn arp_is_leaf() {
        use wireforge_core::arp::ArpPacketBuilder;

        let bytes = ArpPacketBuilder::new()
            .sender_hw_addr(&[0xAA; 6]).unwrap()
            .sender_proto_addr(&[10, 0, 0, 1]).unwrap()
            .target_hw_addr(&[0xBB; 6]).unwrap()
            .target_proto_addr(&[10, 0, 0, 2]).unwrap()
            .build();

        let pkt = Packet::Arp(ArpPacket::new(&bytes).unwrap());
        assert_eq!(pkt.protocol_name(), "ARP");
        assert!(pkt.inner().is_none()); // ARP has no inner protocol
    }
}
