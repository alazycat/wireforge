//! TCP/UDP checksum tests for IPv4 and IPv6 pseudo-headers.

use core::net::{Ipv4Addr, Ipv6Addr};

use wireforge_core::tcp::{MutableTcpPacket, TcpPacket, TcpPacketBuilder};
use wireforge_core::udp::{MutableUdpPacket, UdpPacket, UdpPacketBuilder};

fn v6_addresses() -> (Ipv6Addr, Ipv6Addr) {
    (
        "2001:db8::1".parse().expect("source"),
        "2001:db8::2".parse().expect("destination"),
    )
}

#[test]
fn tcp_ipv6_known_vector_and_round_trip() {
    let (src, dst) = v6_addresses();
    let bytes = TcpPacketBuilder::new()
        .source_port(1234)
        .destination_port(80)
        .sequence(1)
        .syn(true)
        .window(65535)
        .payload(b"hello")
        .build_v6(src, dst);

    let packet = TcpPacket::new(&bytes).expect("parsed TCP");
    assert_eq!(packet.checksum(), 0x0B74);
    assert!(packet.verify_checksum_v6(src, dst));

    let mut corrupted = bytes.clone();
    corrupted[16] ^= 0xFF;
    assert!(!TcpPacket::new(&corrupted)
        .expect("parsed TCP")
        .verify_checksum_v6(src, dst));
}

#[test]
fn udp_ipv6_known_vector_and_zero_checksum_is_invalid() {
    let (src, dst) = v6_addresses();
    let bytes = UdpPacketBuilder::new()
        .source_port(53)
        .destination_port(5353)
        .payload(b"dns!!")
        .build_v6(src, dst);

    let packet = UdpPacket::new(&bytes).expect("parsed UDP");
    assert_eq!(packet.checksum(), 0x96B1);
    assert!(packet.verify_checksum_v6(src, dst));

    let mut zero = bytes.clone();
    zero[6] = 0;
    zero[7] = 0;
    assert!(!UdpPacket::new(&zero)
        .expect("parsed UDP")
        .verify_checksum_v6(src, dst));
}

#[test]
fn ipv4_checksums_are_unchanged() {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);

    let tcp = TcpPacketBuilder::new()
        .source_port(1234)
        .destination_port(80)
        .sequence(1)
        .syn(true)
        .window(65535)
        .payload(b"hello")
        .build(src, dst);
    let tcp_packet = TcpPacket::new(&tcp).expect("parsed TCP");
    assert_eq!(tcp_packet.checksum(), 0x52E6);
    assert!(tcp_packet.verify_checksum(src, dst));

    let udp = UdpPacketBuilder::new()
        .source_port(53)
        .destination_port(5353)
        .payload(b"dns!!")
        .build(src, dst);
    let udp_packet = UdpPacket::new(&udp).expect("parsed UDP");
    assert_eq!(udp_packet.checksum(), 0xDE23);
    assert!(udp_packet.verify_checksum(src, dst));
}

#[test]
fn mutable_ipv6_checksums_are_recomputed() {
    let (src, dst) = v6_addresses();

    let mut tcp = TcpPacketBuilder::new()
        .source_port(1234)
        .destination_port(80)
        .sequence(1)
        .syn(true)
        .window(65535)
        .payload(b"hello")
        .build_v6(src, dst);
    {
        let mut packet = MutableTcpPacket::new(&mut tcp).expect("mutable TCP");
        packet.set_destination_port(443);
        packet.payload_mut()[0] = b'H';
        packet.update_checksum_v6(src, dst);
    }
    assert!(TcpPacket::new(&tcp)
        .expect("parsed TCP")
        .verify_checksum_v6(src, dst));

    let mut udp = UdpPacketBuilder::new()
        .source_port(53)
        .destination_port(5353)
        .payload(b"dns!!")
        .build_v6(src, dst);
    {
        let mut packet = MutableUdpPacket::new(&mut udp).expect("mutable UDP");
        packet.set_destination_port(4321);
        packet.payload_mut()[0] = b'D';
        packet.update_checksum_v6(src, dst);
    }
    assert!(UdpPacket::new(&udp)
        .expect("parsed UDP")
        .verify_checksum_v6(src, dst));
}
