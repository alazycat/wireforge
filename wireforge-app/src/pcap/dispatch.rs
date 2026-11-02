//! Bridge between pcap capture records and the packet/app dispatch layers.
//!
//! Requires the `dispatch` feature, which pulls in [`wireforge_packet`].
//! WireForge keeps file I/O ([`super::PcapReader`]) and protocol dispatch
//! ([`wireforge_packet::parse_link_layer`]) in separate layers; this module
//! is the glue so callers don't have to hand-roll the layer walking.
//!
//! The borrow model is zero-copy: the caller owns the record buffer, and
//! [`parse_capture`] only borrows it — no self-referential structs, no
//! per-record allocation.

use wireforge_packet::{parse_link_layer, LinkPacket, LinkType, Packet};

use crate::app_packet::{parse_tcp_application, parse_udp_application, AppPacket};

/// A capture record parsed through every layer that recognized itself.
///
/// Constructed by [`parse_capture`]; all fields borrow the input buffer.
#[derive(Debug, Clone)]
pub struct ParsedCapture<'a> {
    /// Link-layer packet (Ethernet, SLL, SLL2, USBPcap, or raw IP bytes).
    pub link: LinkPacket<'a>,
    /// Network layer — IPv4 or IPv6, when the link payload dispatches to IP.
    pub network: Option<Packet<'a>>,
    /// Transport layer — TCP, UDP, ICMP, or ICMPv6.
    pub transport: Option<Packet<'a>>,
    /// Application layer, dispatched by TCP/UDP port. `None` when the
    /// transport is not TCP/UDP or the port/payload did not match a
    /// supported protocol.
    pub app: Option<AppPacket<'a>>,
}

/// Parse a raw capture record through all layers: link → network →
/// transport → application.
///
/// This walks the protocol stack top-down: [`parse_link_layer`] for the
/// link header, [`Packet::inner`] down to the transport leaf, then the
/// port-based application dispatch ([`parse_tcp_application`] /
/// [`parse_udp_application`]). Every layer that fails to parse simply
/// stays `None`; only a hopeless frame (shorter than the link header)
/// makes the whole call return `None`.
///
/// VXLAN/inner-frame recursion is intentionally not performed — a UDP
/// datagram on port 4789 is dispatched like any other UDP payload.
///
/// # Examples
///
/// ```
/// use wireforge_app::pcap::{parse_capture, LinkType};
/// use wireforge_core::ipv4::Ipv4PacketBuilder;
/// use wireforge_core::tcp::TcpPacketBuilder;
/// use wireforge_core::types::IpProtocol;
/// use wireforge_core::util::PacketBuilder;
/// use wireforge_packet::{LinkPacket, Packet};
///
/// let tcp = TcpPacketBuilder::new()
///     .source_port(443)
///     .destination_port(54321)
///     .sequence(1)
///     .syn(true)
///     .window(8192)
///     .build(std::net::Ipv4Addr::new(10, 0, 0, 1), std::net::Ipv4Addr::new(10, 0, 0, 2));
/// let ip = Ipv4PacketBuilder::new()
///     .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
///     .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
///     .protocol(IpProtocol::Tcp)
///     .ttl(64)
///     .payload(&tcp)
///     .unwrap()
///     .build();
/// let mut frame = vec![0xFFu8; 12]; // dst + src MAC
/// frame.extend_from_slice(&[0x08, 0x00]); // EtherType::Ipv4
/// frame.extend_from_slice(&ip);
///
/// let parsed = parse_capture(&frame, LinkType::Ethernet).unwrap();
/// assert!(matches!(parsed.link, LinkPacket::Ethernet(_)));
/// assert!(matches!(parsed.network, Some(Packet::Ipv4(_))));
/// assert!(matches!(parsed.transport, Some(Packet::Tcp(_))));
/// // No TLS payload in a bare SYN — app dispatch declines.
/// assert!(parsed.app.is_none());
/// ```
pub fn parse_capture(buf: &[u8], link: LinkType) -> Option<ParsedCapture<'_>> {
    let (link_pkt, inner) = parse_link_layer(link, buf)?;

    let mut network: Option<Packet<'_>> = None;
    let mut transport: Option<Packet<'_>> = None;
    // (payload, src_port, dst_port, is_tcp) — captured while the packet is
    // still owned here, so app dispatch borrows straight into `buf`.
    let mut l4: Option<(&[u8], u16, u16, bool)> = None;

    let mut current = inner;
    while let Some(p) = current {
        match &p {
            Packet::Tcp(tcp) => {
                l4 = Some((tcp.payload(), tcp.source_port(), tcp.destination_port(), true));
            }
            Packet::Udp(udp) => {
                l4 = Some((udp.payload(), udp.source_port(), udp.destination_port(), false));
            }
            _ => {}
        }

        let is_leaf = !matches!(p, Packet::Ipv4(_) | Packet::Ipv6(_));
        match p {
            Packet::Ipv4(_) | Packet::Ipv6(_) => network = Some(p.clone()),
            Packet::Tcp(_) | Packet::Udp(_) | Packet::Icmp(_) | Packet::Icmpv6(_) => {
                transport = Some(p.clone());
            }
            // ARP and other non-IP leaves carry no further layers.
            _ => {}
        }
        if is_leaf {
            break;
        }
        current = p.inner();
    }

    let app = match l4 {
        Some((payload, src, dst, true)) => parse_tcp_application(payload, src, dst),
        Some((payload, src, dst, false)) => parse_udp_application(payload, src, dst),
        None => None,
    };

    Some(ParsedCapture {
        link: link_pkt,
        network,
        transport,
        app,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::builder::DnsPacketBuilder;
    use crate::dns::types::{DnsClass, DnsType};
    use wireforge_core::ipv4::Ipv4PacketBuilder;
    use wireforge_core::tcp::TcpPacketBuilder;
    use wireforge_core::types::IpProtocol;
    use wireforge_core::udp::UdpPacketBuilder;
    use wireforge_core::util::PacketBuilder;

    /// Ethernet frame carrying an IPv4 packet with the given transport payload.
    fn eth_frame(protocol: IpProtocol, transport: &[u8]) -> Vec<u8> {
        let ip = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(protocol)
            .ttl(64)
            .payload(transport)
            .unwrap()
            .build();
        let mut frame = vec![0xFFu8; 12];
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType::Ipv4
        frame.extend_from_slice(&ip);
        frame
    }

    #[test]
    fn parses_ethernet_to_tcp_without_app() {
        let tcp = TcpPacketBuilder::new()
            .source_port(443)
            .destination_port(54321)
            .sequence(1)
            .syn(true)
            .window(8192)
            .build(std::net::Ipv4Addr::new(10, 0, 0, 1), std::net::Ipv4Addr::new(10, 0, 0, 2));
        let frame = eth_frame(IpProtocol::Tcp, &tcp);

        let parsed = parse_capture(&frame, LinkType::Ethernet).unwrap();
        assert!(matches!(parsed.link, LinkPacket::Ethernet(_)));
        assert!(matches!(parsed.network, Some(Packet::Ipv4(_))));
        assert!(matches!(parsed.transport, Some(Packet::Tcp(_))));
        // Bare SYN — no TLS payload, so app dispatch declines.
        assert!(parsed.app.is_none());
    }

    #[test]
    fn parses_ethernet_to_udp_mdns_app() {
        let q = DnsPacketBuilder::query()
            .add_question("_http._tcp.local", DnsType::PTR, DnsClass::IN)
            .build();
        let udp = UdpPacketBuilder::new()
            .source_port(5353)
            .destination_port(5353)
            .payload(&q)
            .build(
                std::net::Ipv4Addr::new(10, 0, 0, 1),
                std::net::Ipv4Addr::new(10, 0, 0, 2),
            );
        let frame = eth_frame(IpProtocol::Udp, &udp);

        let parsed = parse_capture(&frame, LinkType::Ethernet).unwrap();
        assert!(matches!(parsed.transport, Some(Packet::Udp(_))));
        assert!(matches!(parsed.app, Some(AppPacket::Mdns(_))));
    }

    #[test]
    fn parses_raw_ip_frame_dlt_12() {
        // Regression companion: DLT_RAW (12) captures are raw IP frames.
        let tcp = TcpPacketBuilder::new()
            .source_port(22)
            .destination_port(54321)
            .sequence(1)
            .syn(true)
            .window(8192)
            .build(std::net::Ipv4Addr::new(10, 0, 0, 1), std::net::Ipv4Addr::new(10, 0, 0, 2));
        let ip = Ipv4PacketBuilder::new()
            .source(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .destination(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .protocol(IpProtocol::Tcp)
            .ttl(64)
            .payload(&tcp)
            .unwrap()
            .build();

        let parsed = parse_capture(&ip, LinkType::Raw).unwrap();
        assert!(matches!(parsed.link, LinkPacket::RawIp(_)));
        assert!(matches!(parsed.network, Some(Packet::Ipv4(_))));
        assert!(matches!(parsed.transport, Some(Packet::Tcp(_))));
    }

    #[test]
    fn arp_frame_yields_only_link_layer() {
        // Ethernet frame with EtherType::Arp and a truncated ARP body —
        // enough for the link layer, no IP/transport/app layers.
        let mut frame = vec![0xFFu8; 12];
        frame.extend_from_slice(&[0x08, 0x06]);
        frame.extend_from_slice(&[0x00; 28]);

        let parsed = parse_capture(&frame, LinkType::Ethernet).unwrap();
        assert!(matches!(parsed.link, LinkPacket::Ethernet(_)));
        assert!(parsed.network.is_none());
        assert!(parsed.transport.is_none());
        assert!(parsed.app.is_none());
    }

    #[test]
    fn hopeless_frame_returns_none() {
        assert!(parse_capture(&[0u8; 5], LinkType::Ethernet).is_none());
    }
}
