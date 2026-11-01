//! Send an ICMPv6 Echo Request over a raw IPv6 socket and wait for a packet.
//!
//! Requires root (Linux) or Administrator (Windows). The source address is
//! fixed to `::1`, so this example is intended for loopback testing.
//!
//! ```sh
//! sudo cargo run --example ipv6_l3 -- ::1
//! ```

use std::net::{Ipv6Addr, SocketAddrV6};
use std::time::Duration;

use wireforge_core::icmp::Icmpv6PacketBuilder;
use wireforge_core::ipv6::Ipv6PacketBuilder;
use wireforge_core::types::IpProtocol;
use wireforge_io::{DefaultL3ReaderV6, DefaultL3WriterV6, IoError};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dst: Ipv6Addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "::1".into())
        .parse()?;
    let src = Ipv6Addr::LOCALHOST;

    let icmp = Icmpv6PacketBuilder::echo_request()
        .identifier(std::process::id() as u16)
        .sequence_number(1)
        .body(b"wireforge-v6")
        .build(src, dst);
    let packet = Ipv6PacketBuilder::new()
        .source(src)
        .destination(dst)
        .next_header(IpProtocol::Icmpv6)
        .hop_limit(64)
        .payload(&icmp)
        .expect("payload should fit")
        .build();

    // Open the capture socket first: AF_PACKET only sees packets that arrive
    // after the socket is created.
    let mut rx = DefaultL3ReaderV6::new(IpProtocol::Icmpv6)?;
    rx.set_timeout(Some(Duration::from_millis(500)))?;

    let tx = DefaultL3WriterV6::new()?;
    let sent = tx.send_to(&packet, SocketAddrV6::new(dst, 0, 0, 0))?;
    println!("sent {sent} bytes to {dst}");

    for _ in 0..4 {
        match rx.recv() {
            Ok(reply) => {
                println!(
                    "received IPv6 packet: {} -> {}",
                    reply.source(),
                    reply.destination()
                );
                return Ok(());
            }
            Err(IoError::Timeout) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    println!("no IPv6 packet received");
    Ok(())
}
