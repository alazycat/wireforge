//! List all network interfaces on the current system.
//!
//! Works without elevated privileges on all platforms.
//! Usage: `cargo run --example list_interfaces`

use wireforge_io::list_interfaces;

fn main() {
    let ifaces = list_interfaces().expect("failed to list interfaces");
    println!("Found {} interface(s):\n", ifaces.len());
    println!(
        "{:<4} {:<38} {:<6} {:<18} {:<24} {:<4} IPs",
        "Idx", "Name", "Up", "MAC", "Flags", "Loop"
    );
    println!("{}", "-".repeat(120));
    for iface in &ifaces {
        let mac = iface
            .mac_address
            .map(|m| {
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                )
            })
            .unwrap_or_else(|| "-".into());
        let mut flags = Vec::new();
        if iface.is_broadcast {
            flags.push("bcast");
        }
        if iface.is_point_to_point {
            flags.push("p2p");
        }
        if iface.is_multicast {
            flags.push("mcast");
        }
        if iface.is_running {
            flags.push("running");
        }
        let ips: Vec<_> = iface
            .ip_networks
            .iter()
            .map(|network| network.to_string())
            .collect();
        println!(
            "{:<4} {:<38} {:<6} {:<18} {:<24} {:<4} {}",
            iface.index,
            iface.name,
            if iface.is_up { "UP" } else { "DOWN" },
            mac,
            flags.join(","),
            if iface.is_loopback { "LOOP" } else { "" },
            ips.join(", "),
        );
        if let Some(desc) = iface
            .description
            .as_deref()
            .or(iface.friendly_name.as_deref())
        {
            println!("     {desc}");
        }
    }
}
