//! ICMP echo (ping) over a transport channel.
//!
//! Demonstrates the `pnet_transport`-style API: `transport_channel`, sender
//! TTL, and `next_with_timeout`.
//!
//! # Usage
//!
//! Requires root on Linux/macOS or Administrator on Windows:
//!
//! ```text
//! cargo run -p wireforge-io --example transport_echo [-- <destination-ip>]
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use wireforge_core::icmp::IcmpPacketBuilder;
use wireforge_core::types::IpProtocol;
use wireforge_io::transport::{transport_channel, TransportChannelType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dst: IpAddr = std::env::args()
        .nth(1)
        .map(|arg| arg.parse())
        .transpose()?
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let IpAddr::V4(dst) = dst else {
        eprintln!("transport channels are IPv4-only");
        std::process::exit(2);
    };

    let (tx, mut rx) =
        transport_channel(4096, TransportChannelType::Layer4(IpProtocol::Icmp))?;
    tx.set_ttl(64)?;

    const IDENTIFIER: u16 = 0x5746;
    let request = IcmpPacketBuilder::echo_request()
        .identifier(IDENTIFIER)
        .sequence_number(1)
        .payload(b"wireforge-echo")
        .build();
    let sent = tx.send_to(&request, IpAddr::V4(dst))?;
    println!("sent {sent}-byte echo request to {dst}");

    // The raw ICMP socket also sees other hosts' ICMP traffic; wait for our
    // echo reply specifically (identifier + type 0).
    for _ in 0..8 {
        let Some(reply) = rx.next_with_timeout(Duration::from_secs(1))? else {
            println!("no reply within 1s (last attempt)");
            continue;
        };
        let Some(icmp) = reply.icmp() else {
            continue;
        };
        if icmp.type_() != 0 {
            continue; // not an echo reply
        }
        let rest = icmp.rest_of_header();
        if (rest >> 16) as u16 != IDENTIFIER {
            continue; // not our request
        }
        println!(
            "echo reply from {}: seq {} ({} bytes)",
            reply.source(),
            rest as u16,
            reply.as_ip_bytes().len()
        );
        return Ok(());
    }
    Err("no matching echo reply received".into())
}
