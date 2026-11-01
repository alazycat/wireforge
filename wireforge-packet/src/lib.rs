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
use wireforge_core::sll::SllPacket;
use wireforge_core::sll2::Sll2Packet;
use wireforge_core::tcp::TcpPacket;
use wireforge_core::types::{EtherType, IpProtocol};
use wireforge_core::udp::UdpPacket;
use wireforge_core::usbpcap::UsbPcapPacket;
use wireforge_core::vxlan::{VxlanPacket, VXLAN_UDP_PORT};

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

/// Generate a `From` impl that wraps a concrete packet type in [`Packet`].
macro_rules! packet_from {
    ($variant:ident, $type:ty) => {
        impl<'a> From<$type> for Packet<'a> {
            fn from(p: $type) -> Self {
                Packet::$variant(p)
            }
        }
    };
}

// From impls for easy conversion
packet_from!(Ethernet, EthernetPacket<'a>);
packet_from!(Arp, ArpPacket<'a>);
packet_from!(Ipv4, Ipv4Packet<'a>);
packet_from!(Ipv6, Ipv6Packet<'a>);
packet_from!(Tcp, TcpPacket<'a>);
packet_from!(Udp, UdpPacket<'a>);
packet_from!(Icmp, IcmpPacket<'a>);
packet_from!(Icmpv6, Icmpv6Packet<'a>);

impl<'a> wireforge_core::Packet for Packet<'a> {
    fn packet(&self) -> &[u8] {
        match self {
            Packet::Ethernet(packet) => wireforge_core::Packet::packet(packet),
            Packet::Arp(packet) => wireforge_core::Packet::packet(packet),
            Packet::Ipv4(packet) => wireforge_core::Packet::packet(packet),
            Packet::Ipv6(packet) => wireforge_core::Packet::packet(packet),
            Packet::Tcp(packet) => wireforge_core::Packet::packet(packet),
            Packet::Udp(packet) => wireforge_core::Packet::packet(packet),
            Packet::Icmp(packet) => wireforge_core::Packet::packet(packet),
            Packet::Icmpv6(packet) => wireforge_core::Packet::packet(packet),
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Packet::Ethernet(packet) => wireforge_core::Packet::payload(packet),
            Packet::Arp(packet) => wireforge_core::Packet::payload(packet),
            Packet::Ipv4(packet) => wireforge_core::Packet::payload(packet),
            Packet::Ipv6(packet) => wireforge_core::Packet::payload(packet),
            Packet::Tcp(packet) => wireforge_core::Packet::payload(packet),
            Packet::Udp(packet) => wireforge_core::Packet::payload(packet),
            Packet::Icmp(packet) => wireforge_core::Packet::payload(packet),
            Packet::Icmpv6(packet) => wireforge_core::Packet::payload(packet),
        }
    }
}

/// Dispatch a payload by EtherType to the correct L3 parser.
fn dispatch_ethertype<'a>(et: EtherType, payload: &'a [u8]) -> Option<Packet<'a>> {
    match et {
        EtherType::Arp => ArpPacket::new(payload).map(Packet::Arp),
        EtherType::Ipv4 => Ipv4Packet::new(payload).map(Packet::Ipv4),
        EtherType::Ipv6 => Ipv6Packet::new(payload).map(Packet::Ipv6),
        _ => None,
    }
}

/// Parse an Ethernet frame and dispatch the encapsulated protocol.
///
/// Returns the parsed `EthernetPacket` and, if the EtherType matches a
/// known protocol, the inner `Packet` as well.
pub fn parse_ethernet_frame(buf: &[u8]) -> Option<(EthernetPacket<'_>, Option<Packet<'_>>)> {
    let eth = EthernetPacket::new(buf)?;
    let inner = dispatch_ethertype(eth.ethertype(), eth.payload());
    Some((eth, inner))
}

/// Parse a Linux cooked capture (SLL) frame and dispatch the encapsulated protocol.
///
/// SLL is the link layer emitted by libpcap for cooked sockets — most
/// notably `tcpdump -i any`. The SLL `protocol` field has the same
/// semantics as the Ethernet EtherType, so dispatch works identically.
pub fn parse_sll_frame(buf: &[u8]) -> Option<(SllPacket<'_>, Option<Packet<'_>>)> {
    let sll = SllPacket::new(buf)?;
    let inner = dispatch_ethertype(sll.protocol(), sll.payload());
    Some((sll, inner))
}

/// Parse a Linux cooked capture v2 (SLL2) frame and dispatch the encapsulated protocol.
///
/// SLL2 is the successor of SLL used by newer tcpdump releases; see
/// [`parse_sll_frame`] for the SLL variant.
pub fn parse_sll2_frame(buf: &[u8]) -> Option<(Sll2Packet<'_>, Option<Packet<'_>>)> {
    let sll2 = Sll2Packet::new(buf)?;
    let inner = dispatch_ethertype(sll2.protocol(), sll2.payload());
    Some((sll2, inner))
}

/// pcap link-layer header type (the `DLT_*` value from the pcap file header).
///
/// This maps the pcap global-header `network` field to the correct
/// link-layer parser. Values most relevant to WireForge are named;
/// everything else falls back to [`LinkType::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LinkType {
    /// `DLT_EN10MB` (1) — Ethernet II frames.
    Ethernet,
    /// `DLT_RAW` (12; 101 on OpenBSD) — raw IP packets, version detected
    /// from the IP header nibble.
    Raw,
    /// `DLT_LINUX_SLL` (113) — Linux cooked capture v1 (`tcpdump -i any`).
    LinuxSll,
    /// `DLT_LINUX_SLL2` (276) — Linux cooked capture v2 (newer tcpdump).
    LinuxSll2,
    /// `LINKTYPE_USBPCAP` (249) — USBPcap USB traffic captures (Windows).
    UsbPcap,
    /// Any other DLT value, held verbatim.
    Other(i32),
}

impl LinkType {
    /// Map a raw pcap `DLT_*` value to a [`LinkType`].
    pub fn from_dlt(v: i32) -> Self {
        match v {
            1 => LinkType::Ethernet,
            12 | 101 => LinkType::Raw,
            113 => LinkType::LinuxSll,
            276 => LinkType::LinuxSll2,
            249 => LinkType::UsbPcap,
            other => LinkType::Other(other),
        }
    }

    /// The raw pcap `DLT_*` value for this link type.
    pub fn dlt(self) -> i32 {
        match self {
            LinkType::Ethernet => 1,
            LinkType::Raw => 12,
            LinkType::LinuxSll => 113,
            LinkType::LinuxSll2 => 276,
            LinkType::UsbPcap => 249,
            LinkType::Other(v) => v,
        }
    }
}

/// A parsed link-layer packet produced by [`parse_link_layer`].
#[derive(Debug, Clone)]
pub enum LinkPacket<'a> {
    Ethernet(EthernetPacket<'a>),
    Sll(SllPacket<'a>),
    Sll2(Sll2Packet<'a>),
    /// USBPcap capture (`LINKTYPE_USBPCAP`) — the USBPcap header itself;
    /// the payload is raw USB transfer data, not a network protocol.
    UsbPcap(UsbPcapPacket<'a>),
    /// Raw IP capture (`DLT_RAW`) — the link layer carries no header of
    /// its own; the bytes are the IP packet itself.
    RawIp(&'a [u8]),
}

/// Parse a link-layer packet of the given pcap link type and dispatch the
/// encapsulated protocol.
///
/// This is the correct entry point when reading pcap files whose global
/// header `network` field is not `DLT_EN10MB` — e.g. captures created by
/// `tcpdump -i any` (`DLT_LINUX_SLL` / `DLT_LINUX_SLL2`).
///
/// Returns the parsed link-layer packet and, if the encapsulated protocol
/// matches a known protocol, the inner [`Packet`] as well.
///
/// # Examples
///
/// ```
/// use wireforge_core::ipv4::Ipv4PacketBuilder;
/// use wireforge_core::types::IpProtocol;
/// use wireforge_core::util::PacketBuilder;
/// use wireforge_packet::{LinkPacket, LinkType, parse_link_layer};
///
/// // An IPv4 packet as it would appear inside a `tcpdump -i any` capture.
/// let ip = Ipv4PacketBuilder::new()
///     .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
///     .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
///     .protocol(IpProtocol::Tcp)
///     .ttl(64)
///     .build();
///
/// // SLL header: unicast, Ethernet device, 6-byte sender address, IPv4.
/// let mut frame = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x06];
/// frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00]);
/// frame.extend_from_slice(&[0x08, 0x00]); // EtherType::Ipv4
/// frame.extend_from_slice(&ip);
///
/// let (link, inner) = parse_link_layer(LinkType::LinuxSll, &frame).unwrap();
/// assert!(matches!(link, LinkPacket::Sll(_)));
/// assert!(matches!(inner, Some(wireforge_packet::Packet::Ipv4(_))));
/// ```
pub fn parse_link_layer<'a>(link: LinkType, buf: &'a [u8]) -> Option<(LinkPacket<'a>, Option<Packet<'a>>)> {
    match link {
        LinkType::Ethernet => {
            let (eth, inner) = parse_ethernet_frame(buf)?;
            Some((LinkPacket::Ethernet(eth), inner))
        }
        LinkType::LinuxSll => {
            let (sll, inner) = parse_sll_frame(buf)?;
            Some((LinkPacket::Sll(sll), inner))
        }
        LinkType::LinuxSll2 => {
            let (sll2, inner) = parse_sll2_frame(buf)?;
            Some((LinkPacket::Sll2(sll2), inner))
        }
        LinkType::UsbPcap => {
            let usb = UsbPcapPacket::new(buf)?;
            Some((LinkPacket::UsbPcap(usb), None))
        }
        LinkType::Raw => {
            let inner = match buf.first()? >> 4 {
                4 => Ipv4Packet::new(buf).map(Packet::Ipv4),
                6 => Ipv6Packet::new(buf).map(Packet::Ipv6),
                _ => None,
            };
            Some((LinkPacket::RawIp(buf), inner))
        }
        LinkType::Other(_) => None,
    }
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

/// Parse a VXLAN datagram carried in UDP (destination port 4789, RFC 7348).
///
/// Returns the VXLAN header and, when the encapsulated payload is a valid
/// Ethernet frame, the frame together with its dispatched inner packet.
///
/// # Examples
///
/// ```
/// use wireforge_core::udp::UdpPacket;
/// use wireforge_core::util::PacketBuilder;
/// use wireforge_core::vxlan::VxlanPacketBuilder;
/// use wireforge_packet::parse_udp_vxlan;
///
/// // Build a UDP datagram with a VXLAN payload (checksum zeroed for simplicity).
/// let inner = [0xEEu8; 14]; // inner Ethernet frame
/// let vxlan = VxlanPacketBuilder::new(0x42).payload(&inner).build();
/// let mut udp = vec![0x12, 0x35, 0x12, 0xB5, 0x00, 0x1E, 0x00, 0x00];
/// udp.extend_from_slice(&vxlan);
///
/// let udp = UdpPacket::new(&udp).unwrap();
/// let (vxlan, eth, dispatched) = parse_udp_vxlan(&udp).unwrap();
/// assert_eq!(vxlan.vni(), 0x42);
/// assert!(eth.is_some());
/// assert!(dispatched.is_none()); // 0xEE... is not a valid EtherType dispatch
/// ```
pub fn parse_udp_vxlan<'a>(
    udp: &UdpPacket<'a>,
) -> Option<(VxlanPacket<'a>, Option<EthernetPacket<'a>>, Option<Packet<'a>>)> {
    if udp.destination_port() != VXLAN_UDP_PORT {
        return None;
    }
    let vxlan = VxlanPacket::new(udp.payload())?;
    let (eth, dispatched) = match parse_ethernet_frame(vxlan.payload()) {
        Some((eth, dispatched)) => (Some(eth), dispatched),
        None => (None, None),
    };
    Some((vxlan, eth, dispatched))
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
    /// ```rust,no_run
    /// use wireforge_packet::Packet;
    ///
    /// fn walk(packet: Packet<'_>) {
    ///     let mut current = Some(packet);
    ///     while let Some(p) = current {
    ///         println!("{}", p.protocol_name());
    ///         current = p.inner();
    ///     }
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
            Packet::Arp(_)
            | Packet::Tcp(_)
            | Packet::Udp(_)
            | Packet::Icmp(_)
            | Packet::Icmpv6(_) => None,
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
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }
}

impl Default for ProtocolStackVisitor {
    fn default() -> Self {
        Self::new()
    }
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
    pub fn new() -> Self {
        Self { size: 0 }
    }
}

impl Default for PacketSizeVisitor {
    fn default() -> Self {
        Self::new()
    }
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
    use wireforge_core::usbpcap::{UsbPcapPacketBuilder, USBPCAP_TRANSFER_INTERRUPT};
    use wireforge_core::{Packet as PacketTrait, PacketSize};

    #[test]
    fn packet_enum_implements_core_packet_traits() {
        fn assert_packet<T: PacketTrait + PacketSize>() {}
        assert_packet::<Packet<'static>>();

        let frame = [0u8; 60];
        let ethernet = EthernetPacket::new(&frame).expect("valid Ethernet frame");
        let packet = Packet::Ethernet(ethernet);
        assert_eq!(PacketTrait::packet(&packet).len(), 60);
        assert_eq!(PacketTrait::payload(&packet).len(), 46);
        assert_eq!(packet.packet_size(), 60);
    }

    use super::*;
    use wireforge_core::ipv4::Ipv4PacketBuilder;
    use wireforge_core::udp::UdpPacketBuilder;
    use wireforge_core::vxlan::VxlanPacketBuilder;
    use wireforge_core::util::PacketBuilder;

    #[test]
    fn parse_udp_vxlan_dispatches_inner_frame() {
        // Inner Ethernet frame carrying ARP (dst mac ff:ff, ethertype 0x0806).
        let mut inner = vec![0xFF; 6];
        inner.extend_from_slice(&[0x02; 6]);
        inner.extend_from_slice(&[0x08, 0x06]);
        inner.extend_from_slice(&[0x00; 28]); // ARP body

        let vxlan = VxlanPacketBuilder::new(0x00ABCD).payload(&inner).build();
        let udp_len = 8 + vxlan.len();
        let mut udp = vec![0x12, 0x35, 0x12, 0xB5, (udp_len >> 8) as u8, udp_len as u8, 0, 0];
        udp.extend_from_slice(&vxlan);

        let udp_pkt = UdpPacket::new(&udp).unwrap();
        let (vxlan, eth, dispatched) = parse_udp_vxlan(&udp_pkt).unwrap();
        assert_eq!(vxlan.vni(), 0x00ABCD);
        assert_eq!(eth.unwrap().ethertype(), EtherType::Arp);
        assert!(matches!(dispatched, Some(Packet::Arp(_))));
    }

    #[test]
    fn parse_udp_vxlan_rejects_wrong_port() {
        let vxlan = VxlanPacketBuilder::new(1).build();
        let mut udp = vec![0x12, 0x35, 0x1F, 0x90, 0x00, 0x10, 0, 0]; // dst port 8080
        udp.extend_from_slice(&vxlan);
        let udp_pkt = UdpPacket::new(&udp).unwrap();
        assert!(parse_udp_vxlan(&udp_pkt).is_none());
    }

    #[test]
    fn parse_udp_vxlan_rejects_short_payload() {
        // UDP length 12 = 8 header + only 4 bytes of "VXLAN" (truncated).
        let udp = vec![0x12, 0x35, 0x12, 0xB5, 0x00, 0x0C, 0, 0, 0, 0, 0, 0];
        let udp_pkt = UdpPacket::new(&udp).unwrap();
        assert!(parse_udp_vxlan(&udp_pkt).is_none());
    }

    // -- Linux cooked capture (SLL / SLL2) dispatch tests --

    fn sll_frame(ip_bytes: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x06]; // unicast, Ethernet, addr len 6
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00]);
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType::Ipv4
        frame.extend_from_slice(ip_bytes);
        frame
    }

    fn sll2_frame(ip6_bytes: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x86, 0xDD, 0x00, 0x00]; // protocol: IPv6
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // ifindex 2
        frame.extend_from_slice(&[0x00, 0x01]); // arphrd Ethernet
        frame.push(0x00); // packet type: unicast
        frame.push(0x00); // address length
        frame.extend_from_slice(&[0x00; 8]); // address
        frame.extend_from_slice(ip6_bytes);
        frame
    }

    #[test]
    fn parse_sll_frame_dispatches_ipv4() {
        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .ttl(64)
            .build();

        let frame = sll_frame(&ip_bytes);
        let (sll, inner) = parse_sll_frame(&frame).unwrap();
        assert_eq!(sll.protocol(), EtherType::Ipv4);
        assert!(matches!(inner, Some(Packet::Ipv4(_))));
    }

    #[test]
    fn parse_sll2_frame_dispatches_ipv6() {
        let mut ip6 = vec![0x60u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x40];
        ip6.extend_from_slice(&[0u8; 32]); // src + dst = ::

        let frame = sll2_frame(&ip6);
        let (sll2, inner) = parse_sll2_frame(&frame).unwrap();
        assert_eq!(sll2.protocol(), EtherType::Ipv6);
        assert_eq!(sll2.interface_index(), 2);
        assert!(matches!(inner, Some(Packet::Ipv6(_))));
    }

    #[test]
    fn link_type_dlt_mapping() {
        assert_eq!(LinkType::from_dlt(1), LinkType::Ethernet);
        assert_eq!(LinkType::from_dlt(12), LinkType::Raw);
        assert_eq!(LinkType::from_dlt(101), LinkType::Raw);
        assert_eq!(LinkType::from_dlt(113), LinkType::LinuxSll);
        assert_eq!(LinkType::from_dlt(276), LinkType::LinuxSll2);
        assert_eq!(LinkType::from_dlt(249), LinkType::UsbPcap);
        assert_eq!(LinkType::from_dlt(999), LinkType::Other(999));
        assert_eq!(LinkType::Ethernet.dlt(), 1);
        assert_eq!(LinkType::LinuxSll.dlt(), 113);
        assert_eq!(LinkType::LinuxSll2.dlt(), 276);
        assert_eq!(LinkType::UsbPcap.dlt(), 249);
    }

    #[test]
    fn parse_link_layer_sll_like_tcpdump_i_any() {
        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Udp)
            .ttl(64)
            .build();

        let frame = sll_frame(&ip_bytes);
        let (link, inner) = parse_link_layer(LinkType::LinuxSll, &frame).unwrap();
        assert!(matches!(link, LinkPacket::Sll(_)));
        assert!(matches!(inner, Some(Packet::Ipv4(_))));

        let mut ip6 = vec![0x60u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x40];
        ip6.extend_from_slice(&[0u8; 32]);
        let frame = sll2_frame(&ip6);
        let (link, inner) = parse_link_layer(LinkType::LinuxSll2, &frame).unwrap();
        assert!(matches!(link, LinkPacket::Sll2(_)));
        assert!(matches!(inner, Some(Packet::Ipv6(_))));
    }

    #[test]
    fn parse_link_layer_ethernet_and_raw() {
        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .ttl(64)
            .build();

        // Ethernet: needs at least a 14-byte header.
        assert!(parse_link_layer(LinkType::Ethernet, &[0u8; 10]).is_none());

        // Raw: the same bytes parse as an IPv4 packet directly.
        let (link, inner) = parse_link_layer(LinkType::Raw, &ip_bytes).unwrap();
        assert!(matches!(link, LinkPacket::RawIp(_)));
        assert!(matches!(inner, Some(Packet::Ipv4(_))));

        // Unknown DLT → no dispatch.
        assert!(parse_link_layer(LinkType::Other(777), &ip_bytes).is_none());
    }

    #[test]
    fn parse_link_layer_usbpcap() {
        let packet = UsbPcapPacketBuilder::new()
            .bus(1)
            .device(5)
            .transfer(USBPCAP_TRANSFER_INTERRUPT)
            .payload(&[0xAA, 0xBB])
            .build();

        let (link, inner) = parse_link_layer(LinkType::UsbPcap, &packet).unwrap();
        assert!(matches!(link, LinkPacket::UsbPcap(_)));
        assert!(inner.is_none());

        if let LinkPacket::UsbPcap(usb) = link {
            assert_eq!(usb.bus(), 1);
            assert_eq!(usb.device(), 5);
            assert_eq!(usb.transfer(), USBPCAP_TRANSFER_INTERRUPT);
            assert_eq!(usb.payload(), &[0xAA, 0xBB]);
        } else {
            unreachable!();
        }
    }

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
        arp_bytes.push(6); // hw_addr_len
        arp_bytes.push(4); // proto_addr_len
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
            .build(
                std::net::Ipv4Addr::new(10, 0, 0, 1),
                std::net::Ipv4Addr::new(10, 0, 0, 2),
            );

        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Udp)
            .ttl(64)
            .payload(&udp_bytes)
            .unwrap()
            .build();

        let ip = Ipv4Packet::new(&ip_bytes).unwrap();
        let inner = parse_ipv4_payload(&ip);
        assert!(matches!(inner, Some(Packet::Udp(_))));
    }

    #[test]
    fn dispatch_ipv4_to_icmp() {
        use wireforge_core::icmp::IcmpPacketBuilder;
        let icmp_bytes = IcmpPacketBuilder::echo_request()
            .identifier(1)
            .sequence_number(1)
            .payload(b"ping")
            .build();

        let ip_bytes = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Icmp)
            .ttl(64)
            .payload(&icmp_bytes)
            .unwrap()
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
            .sender_hw_addr(&[0xAA; 6])
            .unwrap()
            .sender_proto_addr(&[10, 0, 0, 1])
            .unwrap()
            .target_hw_addr(&[0xBB; 6])
            .unwrap()
            .target_proto_addr(&[10, 0, 0, 2])
            .unwrap()
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
            .payload(&tcp_bytes)
            .unwrap()
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
            .payload(&tcp_bytes)
            .unwrap()
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
            .sender_hw_addr(&[0xAA; 6])
            .unwrap()
            .sender_proto_addr(&[10, 0, 0, 1])
            .unwrap()
            .target_hw_addr(&[0xBB; 6])
            .unwrap()
            .target_proto_addr(&[10, 0, 0, 2])
            .unwrap()
            .build();

        let pkt = Packet::Arp(ArpPacket::new(&bytes).unwrap());
        assert_eq!(pkt.protocol_name(), "ARP");
        assert!(pkt.inner().is_none()); // ARP has no inner protocol
    }
}
