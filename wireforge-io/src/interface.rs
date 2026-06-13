//! Network interface enumeration (cross-platform).

use std::net::IpAddr;

use crate::error::IoError;

/// Information about a network interface.
#[derive(Debug, Clone)]
pub struct Interface {
    /// OS-internal name (e.g. "eth0", "en0", "Ethernet0").
    pub name: String,
    /// Human-readable name.
    pub friendly_name: Option<String>,
    /// MAC address.
    pub mac_address: Option<[u8; 6]>,
    /// Bound IP addresses.
    pub ips: Vec<IpAddr>,
    /// Whether the interface is a loopback.
    pub is_loopback: bool,
    /// Whether the interface is up.
    pub is_up: bool,
}

/// List all available network interfaces on the system.
///
/// Does not require elevated privileges on any platform.
pub fn list_interfaces() -> Result<Vec<Interface>, IoError> {
    platform_list_interfaces()
}

#[cfg(target_os = "linux")]
fn platform_list_interfaces() -> Result<Vec<Interface>, IoError> {
    // Uses SIOCGIFCONF + SIOCGIFFLAGS + SIOCGIFHWADDR
    // Implementation populated in Issue #33.
    Ok(vec![Interface {
        name: "lo".into(),
        friendly_name: None,
        mac_address: None,
        ips: vec![],
        is_loopback: true,
        is_up: true,
    }])
}

#[cfg(target_os = "macos")]
fn platform_list_interfaces() -> Result<Vec<Interface>, IoError> {
    // Uses getifaddrs()
    // Placeholder until full implementation in Issue #33.
    Ok(vec![])
}

#[cfg(target_os = "windows")]
fn platform_list_interfaces() -> Result<Vec<Interface>, IoError> {
    // Uses npcap::Adapter::list() or GetAdaptersInfo
    // Placeholder until full implementation in Issue #33.
    Ok(vec![])
}
