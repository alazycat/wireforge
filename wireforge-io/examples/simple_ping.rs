//! Example: send an ICMP Echo Request and wait for Echo Reply.
//!
//! Linux only. Usage: `sudo cargo run --example simple_ping -- <target_ip>`
//!
//! ```sh
//! sudo cargo run --example simple_ping -- 8.8.8.8
//! ```

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};
    use wireforge_core::icmp::{IcmpPacket, IcmpPacketBuilder};
    use wireforge_core::ipv4::{Ipv4Packet, Ipv4PacketBuilder};
    use wireforge_core::types::IpProtocol;
    use wireforge_io::{L3Receiver, L3Sender};

    let target: Ipv4Addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "8.8.8.8".into())
        .parse()?;
    let src = Ipv4Addr::new(0, 0, 0, 0); // kernel fills source

    let mut rx = L3Receiver::new(IpProtocol::Icmp)?;
    rx.set_timeout(Some(Duration::from_secs(2)))?;

    let tx = L3Sender::new()?;

    let icmp = IcmpPacketBuilder::echo_request()
        .identifier(0x0001)
        .sequence_number(1)
        .payload(b"wireforge-ping!")
        .build();

    let ip = Ipv4PacketBuilder::new()
        .source(src)
        .destination(target)
        .protocol(IpProtocol::Icmp)
        .ttl(64)
        .payload(&icmp)
        .unwrap()
        .build();

    let start = Instant::now();
    tx.send_to(&ip, std::net::SocketAddrV4::new(target, 0))?;
    println!("PING {} ...", target);

    loop {
        let reply = rx.recv()?;
        if reply.protocol() == IpProtocol::Icmp && reply.destination() == src {
            if let Some(icmp_reply) = IcmpPacket::new(reply.payload()) {
                if icmp_reply.type_() == 0 {
                    // Echo Reply
                    let rtt = start.elapsed();
                    println!(
                        "Reply from {}: seq={} ttl={} rtt={:.2}ms",
                        reply.source(),
                        1,
                        reply.ttl(),
                        rtt.as_secs_f64() * 1000.0,
                    );
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("simple_ping requires Linux (raw sockets).");
}
