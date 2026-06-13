//! Example: build an Ethernet + IPv4 + TCP SYN packet.
//!
//! Usage: `cargo run --example packet_build`

use std::net::Ipv4Addr;
use wireforge_core::ether::EthernetPacketBuilder;
use wireforge_core::ipv4::Ipv4PacketBuilder;
use wireforge_core::tcp::TcpPacketBuilder;
use wireforge_core::types::{EtherType, IpProtocol};

fn main() {
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(93, 184, 216, 34); // example.com

    let tcp = TcpPacketBuilder::new()
        .source_port(54321)
        .destination_port(80)
        .sequence(0)
        .syn(true)
        .window(65535)
        .mss(1460)
        .build(src_ip, dst_ip);

    let ipv4 = Ipv4PacketBuilder::new()
        .source(src_ip)
        .destination(dst_ip)
        .protocol(IpProtocol::Tcp)
        .ttl(64)
        .payload(&tcp)
        .unwrap()
        .build();

    let frame = EthernetPacketBuilder::new()
        .dst_mac([0xFF; 6])
        .src_mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        .ethertype(EtherType::Ipv4)
        .payload(&ipv4)
        .build();

    println!("Built Ethernet frame: {} bytes", frame.len());
    println!("  Ethernet header: 14 bytes");
    println!("  IPv4 header:     20 bytes");
    println!("  TCP header:      {} bytes", tcp.len());
}
