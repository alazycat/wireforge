//! Cross-platform packet dumper — captures and prints Ethernet frames.
//!
//! # Platform Support
//! - Linux: AF_PACKET (requires root)
//! - macOS: BPF (requires root)
//! - Windows: NPcap (requires NPcap installed + Administrator)
//!
//! # Usage
//! ```sh
//! sudo cargo run --example cross_platform_dump -- eth0
//! cargo run --example cross_platform_dump          # auto-detect first non-loopback
//! ```

use std::time::Duration;
use wireforge_io::{list_interfaces, DefaultL2Reader, traits::L2Reader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ifname = std::env::args().nth(1).unwrap_or_else(|| {
        list_interfaces()
            .ok()
            .and_then(|ifaces| ifaces.into_iter().find(|i| !i.is_loopback && i.is_up).map(|i| i.name))
            .unwrap_or_else(|| "lo".into())
    });

    println!("Opening {} ...", ifname);
    let mut rx = DefaultL2Reader::new(&ifname)?;
    rx.set_timeout(Some(Duration::from_secs(1)))?;

    println!("Listening on {} (Ctrl+C to stop)...\n", ifname);
    for i in 0..10 {
        match rx.recv() {
            Ok(eth) => {
                println!("#{}: {} → {}  EtherType={:?}  len={}",
                    i + 1,
                    mac_hex(&eth.src_mac()),
                    mac_hex(&eth.dst_mac()),
                    eth.ethertype(),
                    eth.payload().len() + 14,
                );
            }
            Err(wireforge_io::IoError::Timeout) => continue,
            Err(e) => { eprintln!("Error: {e}"); break; }
        }
    }
    Ok(())
}

fn mac_hex(mac: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
