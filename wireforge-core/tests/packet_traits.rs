//! Compile-time and behavioral tests for the common packet traits.

use wireforge_core::arp::ArpPacket;
use wireforge_core::ether::EthernetPacket;
use wireforge_core::gre::GrePacket;
use wireforge_core::icmp::{IcmpPacket, Icmpv6Packet};
use wireforge_core::igmp::IgmpPacket;
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::ipv6::Ipv6Packet;
use wireforge_core::packet::{Packet, PacketSize};
use wireforge_core::tcp::TcpPacket;
use wireforge_core::udp::UdpPacket;
use wireforge_core::vlan::VlanPacket;

fn assert_packet<T: Packet + PacketSize>() {}
fn assert_unsized_packet<T: Packet + PacketSize + ?Sized>() {}

#[test]
fn all_core_packets_implement_packet_and_packet_size() {
    assert_packet::<EthernetPacket<'static>>();
    assert_packet::<VlanPacket<'static>>();
    assert_packet::<ArpPacket<'static>>();
    assert_packet::<Ipv4Packet<'static>>();
    assert_packet::<Ipv6Packet<'static>>();
    assert_packet::<TcpPacket<'static>>();
    assert_packet::<UdpPacket<'static>>();
    assert_packet::<IcmpPacket<'static>>();
    assert_packet::<Icmpv6Packet<'static>>();
    assert_packet::<IgmpPacket<'static>>();
    assert_packet::<GrePacket<'static>>();

    assert_packet::<Box<EthernetPacket<'static>>>();
    assert_packet::<&EthernetPacket<'static>>();
    assert_unsized_packet::<dyn Packet>();
}

#[test]
fn ethernet_packet_exposes_buffer_payload_and_size() {
    let frame = vec![0u8; 60];
    let eth = EthernetPacket::new(&frame).expect("valid Ethernet frame");

    assert_eq!(eth.packet(), frame.as_slice());
    assert_eq!(eth.payload(), &frame[14..]);
    assert_eq!(eth.packet_size(), 60);
    assert_eq!(payload_len(&eth), 46);
}

#[test]
fn arp_payload_is_everything_after_the_fixed_header() {
    let bytes = [0u8; 28];
    let arp = ArpPacket::new(&bytes).expect("valid ARP packet");

    assert_eq!(arp.packet(), &bytes[..]);
    assert!(arp.payload().is_empty());
    assert_eq!(arp.packet_size(), 28);
}

#[test]
fn vlan_payload_is_the_inner_frame() {
    let bytes = [0u8; 18];
    let vlan = VlanPacket::new(&bytes).expect("valid VLAN packet");

    assert_eq!(vlan.packet(), &bytes[..]);
    assert_eq!(vlan.payload(), &bytes[4..]);
}

#[test]
fn boxed_and_referenced_packets_forward_to_the_inner_packet() {
    let frame = vec![0u8; 60];
    let eth = EthernetPacket::new(&frame).expect("valid Ethernet frame");

    let boxed = Box::new(eth.clone());
    assert_eq!(boxed.packet(), frame.as_slice());
    assert_eq!(boxed.packet_size(), 60);
    assert_eq!(boxed.payload().len(), 46);

    let referenced = &eth;
    assert_eq!(referenced.packet(), frame.as_slice());
    assert_eq!(referenced.packet_size(), 60);
}

fn payload_len<T: Packet>(packet: &T) -> usize {
    packet.payload().len()
}
