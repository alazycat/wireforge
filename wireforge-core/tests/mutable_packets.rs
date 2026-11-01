//! In-place mutation tests for the `Mutable*Packet` views.

use core::net::{Ipv4Addr, Ipv6Addr};

use wireforge_core::arp::{ArpPacket, ArpPacketBuilder, MutableArpPacket};
use wireforge_core::ether::{EthernetPacket, EthernetPacketBuilder, MutableEthernetPacket};
use wireforge_core::gre::{GrePacket, GrePacketBuilder, MutableGrePacket};
use wireforge_core::icmp::{
    IcmpMessage, IcmpPacket, IcmpPacketBuilder, Icmpv6Message, Icmpv6Packet, Icmpv6PacketBuilder,
    MutableIcmpPacket, MutableIcmpv6Packet,
};
use wireforge_core::igmp::{IgmpPacket, IgmpPacketBuilder, MutableIgmpPacket};
use wireforge_core::ipv4::{Ipv4Packet, Ipv4PacketBuilder, MutableIpv4Packet};
use wireforge_core::ipv6::{Ipv6Packet, Ipv6PacketBuilder, MutableIpv6Packet};
use wireforge_core::packet::{MutablePacket, Packet, PacketSize};
use wireforge_core::tcp::{MutableTcpPacket, TcpPacket, TcpPacketBuilder};
use wireforge_core::types::{ArpHardwareType, ArpOperation, EtherType, IpProtocol};
use wireforge_core::udp::{MutableUdpPacket, UdpPacket, UdpPacketBuilder};
use wireforge_core::util::internet_checksum;
use wireforge_core::vlan::{MutableVlanPacket, VlanPacket};

#[test]
fn ethernet_in_place() {
    let mut frame = EthernetPacketBuilder::new()
        .dst_mac([0x00; 6])
        .src_mac([0x11; 6])
        .ethertype(EtherType::Ipv4)
        .payload(&[0u8; 46])
        .build();

    {
        let mut packet = MutableEthernetPacket::new(&mut frame).expect("mutable Ethernet");
        packet.set_dst_mac([0xAA; 6]);
        packet.set_src_mac([0xBB; 6]);
        packet.set_ethertype(EtherType::Arp);
        packet.payload_mut()[0] = 0x42;

        assert_eq!(Packet::packet(&packet).len(), 60);
        assert_eq!(PacketSize::packet_size(&packet), 60);
        assert_eq!(MutablePacket::packet_mut(&mut packet).len(), 60);
    }

    let packet = EthernetPacket::new(&frame).expect("parsed Ethernet");
    assert_eq!(packet.dst_mac(), [0xAA; 6]);
    assert_eq!(packet.src_mac(), [0xBB; 6]);
    assert_eq!(packet.ethertype(), EtherType::Arp);
    assert_eq!(packet.payload()[0], 0x42);
}

#[test]
fn mutable_clone_from_copies_packet() {
    let source = EthernetPacketBuilder::new()
        .dst_mac([0x22; 6])
        .src_mac([0x33; 6])
        .ethertype(EtherType::Ipv6)
        .payload(&[0x11; 46])
        .build();
    let mut destination = vec![0u8; source.len()];

    {
        let mut view = MutableEthernetPacket::new(&mut destination).expect("mutable Ethernet");
        let source_packet = EthernetPacket::new(&source).expect("parsed Ethernet");
        view.clone_from(&source_packet);
    }

    assert_eq!(destination, source);
}

#[test]
fn vlan_in_place() {
    let mut bytes = vec![0x00, 0x64, 0x08, 0x00, 0x00, 0x00];

    {
        let mut packet = MutableVlanPacket::new(&mut bytes).expect("mutable VLAN");
        packet.set_pcp(5);
        packet.set_dei(true);
        packet.set_vid(123);
        packet.set_ethertype(EtherType::Ipv6);
        packet.payload_mut()[0] = 0x60;
    }

    let packet = VlanPacket::new(&bytes).expect("parsed VLAN");
    assert_eq!(packet.pcp(), 5);
    assert!(packet.dei());
    assert_eq!(packet.vid(), 123);
    assert_eq!(packet.ethertype(), EtherType::Ipv6);
    assert_eq!(packet.inner()[0], 0x60);
}

#[test]
fn arp_in_place() {
    let mut bytes = ArpPacketBuilder::new()
        .hardware_type(ArpHardwareType::Ethernet)
        .protocol_type(EtherType::Ipv4)
        .operation(ArpOperation::Request)
        .sender_hw_addr(&[0x00; 6])
        .expect("sender hw")
        .sender_proto_addr(&[10, 0, 0, 1])
        .expect("sender proto")
        .target_hw_addr(&[0x00; 6])
        .expect("target hw")
        .target_proto_addr(&[10, 0, 0, 2])
        .expect("target proto")
        .build();

    {
        let mut packet = MutableArpPacket::new(&mut bytes).expect("mutable ARP");
        packet.set_operation(ArpOperation::Reply);
        packet.set_sender_mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        packet.set_sender_ip(Ipv4Addr::new(192, 168, 1, 1));
        packet.set_target_mac([0xAA; 6]);
        packet.set_target_ip(Ipv4Addr::new(192, 168, 1, 2));
    }

    let packet = ArpPacket::new(&bytes).expect("parsed ARP");
    assert!(packet.is_reply());
    assert_eq!(
        packet.sender_hw_addr(),
        &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
    );
    assert_eq!(packet.sender_proto_addr(), &[192, 168, 1, 1]);
    assert_eq!(packet.target_hw_addr(), &[0xAA; 6]);
    assert_eq!(packet.target_proto_addr(), &[192, 168, 1, 2]);
}

#[test]
fn ipv4_in_place() {
    let mut bytes = Ipv4PacketBuilder::new()
        .source(Ipv4Addr::new(10, 0, 0, 1))
        .destination(Ipv4Addr::new(10, 0, 0, 2))
        .protocol(IpProtocol::Udp)
        .ttl(64)
        .payload(&[1, 2, 3, 4])
        .expect("payload")
        .build();

    {
        let mut packet = MutableIpv4Packet::new(&mut bytes).expect("mutable IPv4");
        packet.set_ttl(1);
        packet.set_source(Ipv4Addr::new(192, 168, 1, 1));
        packet.set_destination(Ipv4Addr::new(192, 168, 1, 2));
        packet.set_protocol(IpProtocol::Tcp);
        packet.set_dscp(10);
        packet.set_ecn(1);
        packet.set_more_fragments(true);
        packet.update_checksum();
    }

    let packet = Ipv4Packet::new(&bytes).expect("parsed IPv4");
    assert_eq!(packet.ttl(), 1);
    assert_eq!(packet.source(), Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(packet.destination(), Ipv4Addr::new(192, 168, 1, 2));
    assert_eq!(packet.protocol(), IpProtocol::Tcp);
    assert_eq!(packet.dscp(), 10);
    assert_eq!(packet.ecn(), 1);
    assert!(packet.more_fragments());
    assert!(packet.verify_checksum());
}

#[test]
fn ipv6_in_place() {
    let source: Ipv6Addr = "2001:db8::1".parse().expect("source");
    let destination: Ipv6Addr = "2001:db8::2".parse().expect("destination");
    let new_source: Ipv6Addr = "2001:db8::10".parse().expect("new source");
    let new_destination: Ipv6Addr = "2001:db8::20".parse().expect("new destination");

    let mut bytes = Ipv6PacketBuilder::new()
        .source(source)
        .destination(destination)
        .next_header(IpProtocol::Udp)
        .payload(&[1, 2, 3, 4])
        .expect("payload")
        .build();

    {
        let mut packet = MutableIpv6Packet::new(&mut bytes).expect("mutable IPv6");
        packet.set_hop_limit(1);
        packet.set_traffic_class(0xAB);
        packet.set_flow_label(0x12345);
        packet.set_source(new_source);
        packet.set_destination(new_destination);
        packet.set_next_header(IpProtocol::Tcp);
        packet.payload_mut()[0] = 0x99;
    }

    let packet = Ipv6Packet::new(&bytes).expect("parsed IPv6");
    assert_eq!(packet.hop_limit(), 1);
    assert_eq!(packet.traffic_class(), 0xAB);
    assert_eq!(packet.flow_label(), 0x12345);
    assert_eq!(packet.source(), new_source);
    assert_eq!(packet.destination(), new_destination);
    assert_eq!(packet.next_header(), IpProtocol::Tcp);
    assert_eq!(packet.payload()[0], 0x99);
}

#[test]
fn tcp_in_place() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);

    let mut bytes = TcpPacketBuilder::new()
        .source_port(1234)
        .destination_port(80)
        .sequence(1)
        .syn(true)
        .window(65535)
        .payload(b"hello")
        .build(source, destination);

    {
        let mut packet = MutableTcpPacket::new(&mut bytes).expect("mutable TCP");
        packet.set_source_port(4321);
        packet.set_destination_port(443);
        packet.set_sequence(42);
        packet.set_syn(false);
        packet.set_ack(true);
        packet.set_window(1000);
        packet.payload_mut()[0] = b'H';
        packet.update_checksum(source, destination);
    }

    let packet = TcpPacket::new(&bytes).expect("parsed TCP");
    assert_eq!(packet.source_port(), 4321);
    assert_eq!(packet.destination_port(), 443);
    assert_eq!(packet.sequence(), 42);
    assert!(!packet.syn());
    assert!(packet.ack());
    assert_eq!(packet.window(), 1000);
    assert_eq!(packet.payload(), b"Hello");
    assert!(packet.verify_checksum(source, destination));
}

#[test]
fn udp_in_place() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);

    let mut bytes = UdpPacketBuilder::new()
        .source_port(53)
        .destination_port(5353)
        .payload(b"dns")
        .build(source, destination);

    {
        let mut packet = MutableUdpPacket::new(&mut bytes).expect("mutable UDP");
        packet.set_source_port(1234);
        packet.set_destination_port(4321);
        packet.payload_mut()[0] = b'D';
        packet.update_checksum(source, destination);
    }

    let packet = UdpPacket::new(&bytes).expect("parsed UDP");
    assert_eq!(packet.source_port(), 1234);
    assert_eq!(packet.destination_port(), 4321);
    assert_eq!(packet.payload(), b"Dns");
    assert!(packet.verify_checksum(source, destination));
}

#[test]
fn icmp_in_place() {
    let mut bytes = IcmpPacketBuilder::echo_request()
        .identifier(1)
        .sequence_number(1)
        .payload(b"ping")
        .build();

    {
        let mut packet = MutableIcmpPacket::new(&mut bytes).expect("mutable ICMP");
        packet.set_identifier(7);
        packet.set_sequence_number(9);
        packet.set_payload(b"PONG").expect("payload fits");
        packet.update_checksum();
    }

    let packet = IcmpPacket::new(&bytes).expect("parsed ICMP");
    match packet.message() {
        IcmpMessage::EchoRequest {
            identifier,
            sequence_number,
            data,
        } => {
            assert_eq!(identifier, 7);
            assert_eq!(sequence_number, 9);
            assert_eq!(data, b"PONG");
        }
        _ => panic!("expected an ICMP echo request"),
    }
    assert!(packet.verify_checksum());
}

#[test]
fn icmpv6_in_place() {
    let source: Ipv6Addr = "2001:db8::1".parse().expect("source");
    let destination: Ipv6Addr = "2001:db8::2".parse().expect("destination");
    let mut bytes = Icmpv6PacketBuilder::echo_request()
        .identifier(1)
        .sequence_number(1)
        .body(b"ping")
        .build(source, destination);

    {
        let mut packet = MutableIcmpv6Packet::new(&mut bytes).expect("mutable ICMPv6");
        packet.set_identifier(7);
        packet.set_sequence_number(9);
        packet.body_mut()[0] = b'P';
        packet.update_checksum(source, destination);
    }

    let packet = Icmpv6Packet::new(&bytes).expect("parsed ICMPv6");
    match packet.message() {
        Icmpv6Message::EchoRequest {
            identifier,
            sequence_number,
            data,
        } => {
            assert_eq!(identifier, 7);
            assert_eq!(sequence_number, 9);
            assert_eq!(data, b"Ping");
        }
        _ => panic!("expected an ICMPv6 echo request"),
    }
    assert!(packet.verify_checksum(source, destination));
}

#[test]
fn igmp_in_place() {
    let group = Ipv4Addr::new(224, 0, 0, 1);
    let new_group = Ipv4Addr::new(239, 1, 1, 1);

    let mut bytes = IgmpPacketBuilder::report_v2(group).payload(b"x").build();

    {
        let mut packet = MutableIgmpPacket::new(&mut bytes).expect("mutable IGMP");
        packet.set_max_response(10);
        packet.set_group_address(new_group);
        packet.payload_mut()[0] = b'y';
        packet.update_checksum();
    }

    let packet = IgmpPacket::new(&bytes).expect("parsed IGMP");
    assert_eq!(packet.max_response(), 10);
    assert_eq!(packet.group_address(), new_group);
    assert_eq!(packet.payload(), b"y");
    assert!(packet.verify_checksum());
}

#[test]
fn gre_in_place() {
    let mut bytes = GrePacketBuilder::new(EtherType::Ipv4)
        .checksum()
        .key(0x1122_3344)
        .sequence(7)
        .payload(b"gre")
        .build();

    {
        let mut packet = MutableGrePacket::new(&mut bytes).expect("mutable GRE");
        packet.set_protocol_type(EtherType::Ipv6);
        packet.set_recursion_control(2);
        packet.set_key(0xAABB_CCDD).expect("key field present");
        packet.set_sequence(99).expect("sequence field present");
        packet.payload_mut()[0] = b'G';
        packet.update_checksum().expect("checksum field present");
    }

    let packet = GrePacket::new(&bytes).expect("parsed GRE");
    assert_eq!(packet.protocol_type(), EtherType::Ipv6);
    assert_eq!(packet.recursion_control(), 2);
    assert_eq!(packet.key(), Some(0xAABB_CCDD));
    assert_eq!(packet.sequence(), Some(99));
    assert_eq!(packet.payload(), b"Gre");
    assert_eq!(internet_checksum(&bytes), 0);
}
