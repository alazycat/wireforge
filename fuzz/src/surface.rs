//! Every parser surface exposed by wireforge-core and wireforge-app,
//! exercised over one untrusted byte buffer. Each function must return
//! normally (no panic, no overflow) for any input.

use std::fmt::Debug;
use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr};

use wireforge_app::app_packet::{parse_tcp_application, parse_udp_application};
use wireforge_app::dns::parser::DnsPacket;
use wireforge_core::arp::ArpPacket;
use wireforge_core::ether::EthernetPacket;
use wireforge_core::flowcontrol::{PfcPacket, PausePacket};
use wireforge_core::gre::GrePacket;
use wireforge_core::icmp::{IcmpPacket, Icmpv6Packet};
use wireforge_core::igmp::IgmpPacket;
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::ipv6::Ipv6Packet;
use wireforge_core::sll::SllPacket;
use wireforge_core::sll2::Sll2Packet;
use wireforge_core::tcp::TcpPacket;
use wireforge_core::udp::UdpPacket;
use wireforge_core::usbpcap::UsbPcapPacket;
use wireforge_core::vlan::parse_vlan_chain;
use wireforge_core::vxlan::VxlanPacket;

/// Fold any value's Debug representation into the sink so the optimizer
/// cannot discard the work. FNV-1a over `format!("{:?}")`.
fn mix<T: ?Sized + Debug>(sink: &mut u64, value: &T) {
    let repr = format!("{:?}", value);
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in repr.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    *sink ^= h;
}

/// Run every parse surface against `data`. Returns a checksum of
/// touched values so the optimizer cannot discard any work.
pub fn run_all(data: &[u8]) -> u64 {
    let mut sink = 0u64;
    ipv4(data, &mut sink);
    ipv6(data, &mut sink);
    tcp(data, &mut sink);
    udp(data, &mut sink);
    l2(data, &mut sink);
    tunnels(data, &mut sink);
    icmp_igmp(data, &mut sink);
    dns(data, &mut sink);
    app(data, &mut sink);
    sink
}

fn ipv4(data: &[u8], s: &mut u64) {
    let Some(pkt) = Ipv4Packet::new(data) else {
        return;
    };
    mix(s, &(
        pkt.version(),
        pkt.ihl(),
        pkt.dscp(),
        pkt.ecn(),
        pkt.total_length(),
        pkt.identification(),
        pkt.flags(),
        pkt.dont_fragment(),
        pkt.more_fragments(),
        pkt.fragment_offset(),
        pkt.ttl(),
        pkt.protocol(),
    ));
    mix(s, &(
        pkt.checksum(),
        pkt.source(),
        pkt.destination(),
        pkt.header_length(),
    ));
    mix(s, &pkt.options().len());
    mix(s, &pkt.verify_checksum());
    mix(s, &pkt.payload().len());
    black_box(pkt.as_bytes());
}

fn ipv6(data: &[u8], s: &mut u64) {
    let Some(pkt) = Ipv6Packet::new(data) else {
        return;
    };
    mix(s, &(
        pkt.version(),
        pkt.traffic_class(),
        pkt.flow_label(),
        pkt.payload_length(),
        pkt.next_header(),
        pkt.hop_limit(),
        pkt.source(),
        pkt.destination(),
        pkt.final_protocol(),
    ));
    for hdr in pkt.extension_headers() {
        mix(s, &hdr);
    }
    mix(s, &pkt.payload().len());
    black_box(pkt.as_bytes());
}

fn tcp(data: &[u8], s: &mut u64) {
    let Some(pkt) = TcpPacket::new(data) else {
        return;
    };
    for opt in pkt.options() {
        mix(s, &opt);
    }
    mix(s, &pkt.verify_checksum(
        Ipv4Addr::from([10, 0, 0, 1]),
        Ipv4Addr::from([10, 0, 0, 2]),
    ));
    mix(s, &pkt.verify_checksum_v6(
        Ipv6Addr::from([0u16; 8]),
        Ipv6Addr::from([0u16; 8]),
    ));
    mix(s, &pkt.payload().len());
    black_box(pkt.as_bytes());
}

fn udp(data: &[u8], s: &mut u64) {
    let Some(pkt) = UdpPacket::new(data) else {
        return;
    };
    mix(s, &pkt.verify_checksum(
        Ipv4Addr::from([192, 168, 1, 1]),
        Ipv4Addr::from([192, 168, 1, 2]),
    ));
    mix(s, &pkt.verify_checksum_v6(
        Ipv6Addr::from([0u16; 8]),
        Ipv6Addr::from([0u16; 8]),
    ));
    mix(s, &pkt.payload().len());
    black_box(pkt.as_bytes());
}

fn l2(data: &[u8], s: &mut u64) {
    if let Some(eth) = EthernetPacket::new(data) {
        mix(s, &(eth.dst_mac(), eth.src_mac(), eth.raw_ethertype()));
        mix(s, &eth.payload().len());
        black_box(eth.as_bytes());
    }

    if let Some((vlans, ethertype, inner)) = parse_vlan_chain(data) {
        mix(s, &(vlans.len(), ethertype, inner.len()));
        for vlan in &vlans {
            mix(s, &(vlan.pcp(), vlan.dei(), vlan.vid(), vlan.tpid()));
        }
    }

    if let Some(arp) = ArpPacket::new(data) {
        mix(s, &arp.as_bytes().len());
    }

    if let Some(sll) = SllPacket::new(data) {
        mix(s, &(sll.as_bytes().len(), sll.payload().len()));
    }

    if let Some(sll2) = Sll2Packet::new(data) {
        mix(s, &(sll2.as_bytes().len(), sll2.payload().len()));
    }

    if let Some(pause) = PausePacket::new(data) {
        mix(s, &(pause.as_bytes().len(), pause.payload().len()));
    }

    if let Some(pfc) = PfcPacket::new(data) {
        mix(s, &(pfc.as_bytes().len(), pfc.payload().len()));
    }

    if let Some(usb) = UsbPcapPacket::new(data) {
        mix(s, &(usb.header_payload().len(), usb.payload().len()));
        mix(s, &(usb.irp_id(), usb.status(), usb.function(), usb.bus()));
    }
}

fn tunnels(data: &[u8], s: &mut u64) {
    if let Some(gre) = GrePacket::new(data) {
        mix(s, &(
            gre.flags(),
            gre.checksum_present(),
            gre.routing_present(),
            gre.key_present(),
            gre.sequence_present(),
            gre.strict_source_route(),
            gre.recursion_control(),
            gre.version(),
            gre.protocol_type(),
        ));
        mix(s, &gre.checksum());
        mix(s, &gre.key());
        mix(s, &gre.sequence());
        mix(s, &gre.routing().map(|r| r.len()));
        mix(s, &gre.header_length());
        mix(s, &gre.payload().len());
        black_box(gre.as_bytes());
    }

    if let Some(vxlan) = VxlanPacket::new(data) {
        mix(s, &(
            vxlan.flags(),
            vxlan.vni_present(),
            vxlan.vni(),
            vxlan.reserved1().len(),
            vxlan.reserved2(),
            vxlan.payload().len(),
        ));
        black_box(vxlan.as_bytes());
    }
}

fn icmp_igmp(data: &[u8], s: &mut u64) {
    if let Some(icmp) = IcmpPacket::new(data) {
        mix(s, &icmp.verify_checksum());
        mix(s, &icmp.message());
        mix(s, &icmp.payload().len());
        black_box(icmp.as_bytes());
    }

    if let Some(icmpv6) = Icmpv6Packet::new(data) {
        mix(s, &icmpv6.verify_checksum(
            Ipv6Addr::from([0u16; 8]),
            Ipv6Addr::from([0u16; 8]),
        ));
        mix(s, &icmpv6.message());
        black_box(icmpv6.as_bytes());
    }

    if let Some(igmp) = IgmpPacket::new(data) {
        mix(s, &igmp.verify_checksum());
        mix(s, &igmp.message());
        mix(s, &igmp.payload().len());
        black_box(igmp.as_bytes());
    }
}

fn dns(data: &[u8], s: &mut u64) {
    let Some(pkt) = DnsPacket::new(data) else {
        return;
    };
    mix(s, &(
        pkt.transaction_id(),
        pkt.flags(),
        pkt.qr(),
        pkt.opcode(),
        pkt.aa(),
        pkt.tc(),
        pkt.rd(),
        pkt.ra(),
        pkt.rcode(),
        pkt.questions_count(),
        pkt.answers_count(),
        pkt.authorities_count(),
    ));
    mix(s, &pkt.additionals_count());

    for q in pkt.questions() {
        mix(s, &(&q.name, q.qtype, q.qclass));
    }

    for record in pkt
        .answers()
        .chain(pkt.authorities())
        .chain(pkt.additionals())
    {
        mix(s, &record);
    }
}

fn app(data: &[u8], s: &mut u64) {
    if data.len() < 4 {
        return;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let payload = &data[4..];

    if let Some(pkt) = parse_tcp_application(payload, src_port, dst_port) {
        mix(s, &pkt.protocol_name());
    }
    if let Some(pkt) = parse_udp_application(payload, src_port, dst_port) {
        mix(s, &pkt.protocol_name());
    }
}
