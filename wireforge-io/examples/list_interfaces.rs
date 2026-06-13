//! List all network interfaces on the current system.
//!
//! Works without elevated privileges on all platforms.
//! Usage: `cargo run --example list_interfaces`

use wireforge_io::list_interfaces;

fn main() {
    let ifaces = list_interfaces().expect("failed to list interfaces");
    println!("Found {} interface(s):\n", ifaces.len());
    println!("{:<20} {:<8} {:<20} {:<8} {:?}", "Name", "Up", "MAC", "Loop", "IPs");
    println!("{}", "-".repeat(80));
    for iface in &ifaces {
        let mac = iface.mac_address
            .map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]))
            .unwrap_or_else(|| "-".into());
        let ips: Vec<_> = iface.ips.iter().map(|ip| ip.to_string()).collect();
        println!("{:<20} {:<8} {:<20} {:<8} {}",
            iface.name,
            if iface.is_up { "UP" } else { "DOWN" },
            mac,
            if iface.is_loopback { "LOOP" } else { "" },
            ips.join(", "),
        );
    }
}
