//! Cross-platform packet sender — constructs and sends an Ethernet frame.
//!
//! # Platform Support
//! - Linux: AF_PACKET (requires root)
//! - macOS: BPF (requires root)
//! - Windows: L2 send not supported (UnsupportedPlatform)
//!
//! # Usage
//! ```sh
//! sudo cargo run --example cross_platform_send -- eth0
//! ```

use std::net::Ipv4Addr;
use wireforge_core::ether::EthernetPacketBuilder;
use wireforge_core::icmp::IcmpPacketBuilder;
use wireforge_core::ipv4::Ipv4PacketBuilder;
use wireforge_core::types::{EtherType, IpProtocol};
use wireforge_io::{DefaultL2Writer, traits::L2Writer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ifname = std::env::args().nth(1).unwrap_or_else(|| "eth0".into());
    println!("Sending on {} ...", ifname);

    // Build ICMP Echo Request
    let icmp = IcmpPacketBuilder::echo_request()
        .identifier(0x0001)
        .sequence_number(1)
        .payload(b"wireforge!")
        .build();

    // Build IPv4 packet
    let ipv4 = Ipv4PacketBuilder::new()
        .source(Ipv4Addr::new(192, 168, 1, 100))
        .destination(Ipv4Addr::new(192, 168, 1, 1))
        .protocol(IpProtocol::Icmp)
        .ttl(64)
        .payload(&icmp)
        .unwrap()
        .build();

    // Build Ethernet frame (broadcast)
    let frame = EthernetPacketBuilder::new()
        .dst_mac([0xFF; 6])
        .src_mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        .ethertype(EtherType::Ipv4)
        .payload(&ipv4)
        .build();

    let tx = DefaultL2Writer::new(&ifname)?;
    let n = tx.send(&frame)?;
    println!("Sent {} bytes", n);
    Ok(())
}
