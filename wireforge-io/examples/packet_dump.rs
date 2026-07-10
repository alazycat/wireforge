//! Example: capture and dump packets from a network interface.
//!
//! Linux only. Usage: `cargo run --example packet_dump -- <interface>`
//!
//! ```sh
//! sudo cargo run --example packet_dump -- eth0
//! ```

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use wireforge_io::{L2Receiver, IoError};

    let ifname = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let mut rx = L2Receiver::new(&ifname)?;
    println!("Listening on {}...", ifname);

    loop {
        match rx.recv() {
            Ok(eth) => {
                println!(
                    "{} -> {}  EtherType={:?}  payload={} bytes",
                    hex_mac(&eth.src_mac()),
                    hex_mac(&eth.dst_mac()),
                    eth.ethertype(),
                    eth.payload().len(),
                );
            }
            Err(IoError::Timeout) => continue,
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn hex_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("packet_dump requires Linux (AF_PACKET sockets).");
}
