//! Network interface enumeration (cross-platform).
//!
//! Does not require elevated privileges on any platform.

use std::net::IpAddr;

use crate::error::IoError;

/// An IP address together with its network prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IpNetwork {
    /// Address assigned to the interface.
    pub addr: IpAddr,
    /// Prefix length in bits (0..=32 for IPv4, 0..=128 for IPv6).
    pub prefix_length: u8,
}

impl IpNetwork {
    /// Create a new address/prefix pair.
    pub fn new(addr: IpAddr, prefix_length: u8) -> Self {
        Self {
            addr,
            prefix_length,
        }
    }

    /// The assigned address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length in bits.
    pub fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    /// The netmask represented as an IP address.
    pub fn netmask(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(_) => {
                let prefix = self.prefix_length.min(32);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                IpAddr::V4(std::net::Ipv4Addr::from(mask))
            }
            IpAddr::V6(_) => {
                let prefix = self.prefix_length.min(128);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                IpAddr::V6(std::net::Ipv6Addr::from(mask))
            }
        }
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_length)
    }
}

/// Information about a network interface.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Interface {
    /// OS-internal name (e.g. "eth0", "en0", `{GUID}` on Windows).
    pub name: String,
    /// OS-provided description, where available.
    ///
    /// Linux and macOS do not expose one through `getifaddrs`, so this is
    /// `None` there.
    pub description: Option<String>,
    /// Human-readable name (Windows `FriendlyName`; `None` on Unix).
    pub friendly_name: Option<String>,
    /// OS interface index.
    pub index: u32,
    /// MAC address.
    pub mac_address: Option<[u8; 6]>,
    /// Bound IP addresses. Kept for compatibility; mirrors
    /// [`ip_networks`](Self::ip_networks).
    pub ips: Vec<IpAddr>,
    /// Bound IP addresses with their prefix lengths.
    pub ip_networks: Vec<IpNetwork>,
    /// Whether the interface is a loopback.
    pub is_loopback: bool,
    /// Whether the interface is up.
    pub is_up: bool,
    /// Whether the interface supports broadcast.
    pub is_broadcast: bool,
    /// Whether the interface is point-to-point.
    pub is_point_to_point: bool,
    /// Whether the interface supports multicast.
    pub is_multicast: bool,
    /// Whether the interface is running.
    pub is_running: bool,
}

/// List all available network interfaces on the system.
pub fn list_interfaces() -> Result<Vec<Interface>, IoError> {
    platform_list_interfaces()
}

// ---------------------------------------------------------------------------
// Linux: getifaddrs()
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn platform_list_interfaces() -> Result<Vec<Interface>, IoError> {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(IoError::Socket(std::io::Error::last_os_error()));
    }

    struct IfInfo {
        name: String,
        index: u32,
        mac: Option<[u8; 6]>,
        ip_networks: Vec<IpNetwork>,
        is_loopback: bool,
        is_up: bool,
        is_broadcast: bool,
        is_point_to_point: bool,
        is_multicast: bool,
        is_running: bool,
    }

    let mut map: HashMap<String, IfInfo> = HashMap::new();
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        let name = cstr_to_string(ifa.ifa_name);
        let flags = ifa.ifa_flags;
        let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };

        let entry = map.entry(name.clone()).or_insert_with(|| IfInfo {
            name,
            index,
            mac: None,
            ip_networks: Vec::new(),
            is_loopback: flags & libc::IFF_LOOPBACK as u32 != 0,
            is_up: flags & libc::IFF_UP as u32 != 0,
            is_broadcast: flags & libc::IFF_BROADCAST as u32 != 0,
            is_point_to_point: flags & libc::IFF_POINTOPOINT as u32 != 0,
            is_multicast: flags & libc::IFF_MULTICAST as u32 != 0,
            is_running: flags & libc::IFF_RUNNING as u32 != 0,
        });

        if !ifa.ifa_addr.is_null() {
            let family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
            match family {
                libc::AF_INET => {
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    let addr = IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                    let prefix = if ifa.ifa_netmask.is_null() {
                        32
                    } else {
                        let mask = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
                        u32::from_be(mask.sin_addr.s_addr).leading_ones() as u8
                    };
                    let network = IpNetwork::new(addr, prefix);
                    if !entry.ip_networks.contains(&network) {
                        entry.ip_networks.push(network);
                    }
                }
                libc::AF_INET6 => {
                    let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    let addr = IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
                    let prefix = if ifa.ifa_netmask.is_null() {
                        128
                    } else {
                        let mask = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
                        u128::from_be_bytes(mask.sin6_addr.s6_addr).leading_ones() as u8
                    };
                    let network = IpNetwork::new(addr, prefix);
                    if !entry.ip_networks.contains(&network) {
                        entry.ip_networks.push(network);
                    }
                }
                libc::AF_PACKET => {
                    let sll = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
                    if sll.sll_halen == 6 && entry.mac.is_none() {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&sll.sll_addr[..6]);
                        entry.mac = Some(mac);
                    }
                }
                _ => {}
            }
        }

        cur = ifa.ifa_next;
    }

    unsafe {
        libc::freeifaddrs(ifap);
    }

    let mut interfaces: Vec<Interface> = map
        .into_values()
        .map(|info| {
            let ips: Vec<IpAddr> = info
                .ip_networks
                .iter()
                .map(|network| network.addr)
                .collect();
            Interface {
                name: info.name,
                description: None,
                friendly_name: None,
                index: info.index,
                mac_address: info.mac,
                ips,
                ip_networks: info.ip_networks,
                is_loopback: info.is_loopback,
                is_up: info.is_up,
                is_broadcast: info.is_broadcast,
                is_point_to_point: info.is_point_to_point,
                is_multicast: info.is_multicast,
                is_running: info.is_running,
            }
        })
        .collect();
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn cstr_to_string(ptr: *const libc::c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// macOS/BSD: getifaddrs()
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn platform_list_interfaces() -> Result<Vec<Interface>, IoError> {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(IoError::Socket(std::io::Error::last_os_error()));
    }

    struct IfInfo {
        name: String,
        index: u32,
        mac: Option<[u8; 6]>,
        ip_networks: Vec<IpNetwork>,
        is_loopback: bool,
        is_up: bool,
        is_broadcast: bool,
        is_point_to_point: bool,
        is_multicast: bool,
        is_running: bool,
    }
    let mut map: HashMap<String, IfInfo> = HashMap::new();

    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        let name = cstr_to_string_osx(ifa.ifa_name);
        let flags = ifa.ifa_flags;
        let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };

        let entry = map.entry(name.clone()).or_insert_with(|| IfInfo {
            name,
            index,
            mac: None,
            ip_networks: Vec::new(),
            is_loopback: flags & libc::IFF_LOOPBACK as u32 != 0,
            is_up: flags & libc::IFF_UP as u32 != 0,
            is_broadcast: flags & libc::IFF_BROADCAST as u32 != 0,
            is_point_to_point: flags & libc::IFF_POINTOPOINT as u32 != 0,
            is_multicast: flags & libc::IFF_MULTICAST as u32 != 0,
            is_running: flags & libc::IFF_RUNNING as u32 != 0,
        });

        if !ifa.ifa_addr.is_null() {
            let sa = unsafe { &*ifa.ifa_addr };
            match sa.sa_family as i32 {
                libc::AF_LINK => {
                    let sdl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
                    if sdl.sdl_alen == 6 {
                        let mac_addr = unsafe {
                            *(sdl.sdl_data.as_ptr().offset(sdl.sdl_nlen as isize) as *const [u8; 6])
                        };
                        entry.mac = Some(mac_addr);
                    }
                }
                libc::AF_INET => {
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    let addr = IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                    let prefix = if ifa.ifa_netmask.is_null() {
                        32
                    } else {
                        let mask = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
                        u32::from_be(mask.sin_addr.s_addr).leading_ones() as u8
                    };
                    let network = IpNetwork::new(addr, prefix);
                    if !entry.ip_networks.contains(&network) {
                        entry.ip_networks.push(network);
                    }
                }
                libc::AF_INET6 => {
                    let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    let addr = IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
                    let prefix = if ifa.ifa_netmask.is_null() {
                        128
                    } else {
                        let mask = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
                        u128::from_be_bytes(mask.sin6_addr.s6_addr).leading_ones() as u8
                    };
                    let network = IpNetwork::new(addr, prefix);
                    if !entry.ip_networks.contains(&network) {
                        entry.ip_networks.push(network);
                    }
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe {
        libc::freeifaddrs(ifap);
    }

    let mut interfaces: Vec<Interface> = map
        .into_values()
        .map(|info| {
            let ips: Vec<IpAddr> = info
                .ip_networks
                .iter()
                .map(|network| network.addr)
                .collect();
            Interface {
                name: info.name,
                description: None,
                friendly_name: None,
                index: info.index,
                mac_address: info.mac,
                ips,
                ip_networks: info.ip_networks,
                is_loopback: info.is_loopback,
                is_up: info.is_up,
                is_broadcast: info.is_broadcast,
                is_point_to_point: info.is_point_to_point,
                is_multicast: info.is_multicast,
                is_running: info.is_running,
            }
        })
        .collect();
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(interfaces)
}

#[cfg(target_os = "macos")]
fn cstr_to_string_osx(ptr: *const libc::c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(ptr).to_bytes() };
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Windows: IP Helper API (GetAdaptersAddresses)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn platform_list_interfaces() -> Result<Vec<Interface>, IoError> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    const AF_UNSPEC: u32 = 0;
    const GAA_FLAG_INCLUDE_PREFIX: u32 = 0x0010;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_OPER_STATUS_UP: u32 = 1;
    const IP_ADAPTER_NO_MULTICAST: u32 = 0x0010;

    #[repr(C)]
    #[allow(dead_code)]
    struct SocketAddress {
        sockaddr_ptr: *const u8, // LPSOCKADDR
        sockaddr_len: i32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct IpAdapterUnicastAddress {
        length: u32,
        flags: u32,
        next: *mut IpAdapterUnicastAddress,
        address: SocketAddress,
        prefix_origin: u32,
        suffix_origin: u32,
        dad_state: u32,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        lease_lifetime: u32,
        on_link_prefix_length: u8,
    }

    #[repr(C)]
    struct IpAdapterAddresses {
        length: u32,
        if_index: u32,
        next: *mut IpAdapterAddresses,
        /// ANSI adapter name (usually the adapter GUID, e.g. `{A7D0...}`).
        adapter_name: *const std::ffi::c_char,
        first_unicast_address: *mut IpAdapterUnicastAddress,
        first_anycast_address: *mut std::ffi::c_void,
        first_multicast_address: *mut std::ffi::c_void,
        first_dns_server_address: *mut std::ffi::c_void,
        dns_suffix: *const u16,
        description: *const u16,
        friendly_name: *const u16,
        physical_address: [u8; 8],
        physical_address_length: u32,
        flags: u32,
        mtu: u32,
        if_type: u32,
        oper_status: u32,
    }

    extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *const std::ffi::c_void,
            addresses: *mut IpAdapterAddresses,
            size: *mut u32,
        ) -> u32;
    }

    // First call: get required size
    let mut size: u32 = 0;
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if ret != 111 {
        return Ok(vec![]);
    } // ERROR_BUFFER_OVERFLOW

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null(),
            buf.as_mut_ptr() as *mut IpAdapterAddresses,
            &mut size,
        )
    };
    if ret != 0 {
        return Ok(vec![]);
    }

    let mut interfaces = Vec::new();
    let mut cur = buf.as_ptr() as *const IpAdapterAddresses;

    while !cur.is_null() {
        let a = unsafe { &*cur };

        let name = if a.adapter_name.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(a.adapter_name) }
                .to_string_lossy()
                .into_owned()
        };
        let description = wide_ptr_to_string(a.description);
        let friendly_name = wide_ptr_to_string(a.friendly_name);

        let mac = if a.physical_address_length == 6 {
            Some([
                a.physical_address[0],
                a.physical_address[1],
                a.physical_address[2],
                a.physical_address[3],
                a.physical_address[4],
                a.physical_address[5],
            ])
        } else {
            None
        };

        let mut ip_networks = Vec::new();
        let mut ua = a.first_unicast_address;
        while !ua.is_null() {
            let u = unsafe { &*ua };
            if !u.address.sockaddr_ptr.is_null() {
                let family = unsafe { *(u.address.sockaddr_ptr as *const u16) };
                let network = match family {
                    2 => {
                        // AF_INET
                        let b = unsafe {
                            std::slice::from_raw_parts(u.address.sockaddr_ptr.offset(4), 4)
                        };
                        let addr = IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
                        Some(IpNetwork::new(addr, u.on_link_prefix_length.min(32)))
                    }
                    23 => {
                        // AF_INET6
                        let b = unsafe {
                            std::slice::from_raw_parts(u.address.sockaddr_ptr.offset(8), 16)
                        };
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(b);
                        let addr = IpAddr::V6(Ipv6Addr::from(arr));
                        Some(IpNetwork::new(addr, u.on_link_prefix_length.min(128)))
                    }
                    _ => None,
                };

                if let Some(network) = network {
                    if !ip_networks.contains(&network) {
                        ip_networks.push(network);
                    }
                }
            }
            ua = u.next;
        }

        let ips: Vec<IpAddr> = ip_networks.iter().map(|network| network.addr).collect();

        interfaces.push(Interface {
            name,
            description,
            friendly_name,
            index: a.if_index,
            mac_address: mac,
            ips,
            ip_networks,
            is_loopback: a.if_type == IF_TYPE_SOFTWARE_LOOPBACK,
            is_up: a.oper_status == IF_OPER_STATUS_UP,
            is_broadcast: false,
            is_point_to_point: false,
            is_multicast: a.flags & IP_ADAPTER_NO_MULTICAST == 0,
            is_running: a.oper_status == IF_OPER_STATUS_UP,
        });

        cur = a.next;
    }

    Ok(interfaces)
}

/// Decode a NUL-terminated UTF-16 string from the Windows IP Helper API.
#[cfg(target_os = "windows")]
fn wide_ptr_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    if len == 0 {
        return None;
    }
    let wide = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf16_lossy(wide))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_interfaces_returns_something() {
        let ifaces = list_interfaces().expect("list_interfaces should succeed");
        assert!(!ifaces.is_empty(), "should return at least one interface");
    }

    #[test]
    fn list_interfaces_has_loopback() {
        let ifaces = list_interfaces().expect("list_interfaces should succeed");
        assert!(
            ifaces.iter().any(|i| i.is_loopback),
            "should contain loopback"
        );
    }

    #[test]
    fn interfaces_have_consistent_ip_networks() {
        let ifaces = list_interfaces().expect("list_interfaces should succeed");
        for iface in &ifaces {
            assert_eq!(
                iface.ips.len(),
                iface.ip_networks.len(),
                "ips and ip_networks should mirror each other on {:?}",
                iface.name
            );
            for network in &iface.ip_networks {
                let max_prefix = match network.addr {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                assert!(
                    network.prefix_length <= max_prefix,
                    "invalid prefix length in {network} on {:?}",
                    iface.name
                );
                assert!(
                    iface.ips.contains(&network.addr),
                    "{network} missing from ips on {:?}",
                    iface.name
                );
            }
        }
    }

    #[test]
    fn loopback_has_index_and_addresses() {
        let ifaces = list_interfaces().expect("list_interfaces should succeed");
        let loopback = ifaces
            .iter()
            .find(|iface| iface.is_loopback)
            .expect("should contain loopback");

        assert!(loopback.index > 0, "loopback index should be nonzero");
        assert!(
            !loopback.ip_networks.is_empty(),
            "loopback should have at least one address"
        );
        assert!(loopback.is_up, "loopback should be up");
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn loopback_has_ipv4_and_ipv6_addresses() {
        let ifaces = list_interfaces().expect("list_interfaces should succeed");
        let loopback = ifaces
            .iter()
            .find(|iface| iface.is_loopback)
            .expect("should contain loopback");

        assert!(
            loopback
                .ip_networks
                .iter()
                .any(|network| matches!(network.addr, IpAddr::V4(ip) if ip.is_loopback())),
            "loopback should have an IPv4 address"
        );
        assert!(
            loopback
                .ip_networks
                .iter()
                .any(|network| matches!(network.addr, IpAddr::V6(ip) if ip.is_loopback())),
            "loopback should have an IPv6 address"
        );
    }

    #[test]
    fn ip_network_netmask_and_display() {
        let v4 = IpNetwork::new("192.168.1.10".parse().expect("IPv4"), 24);
        assert_eq!(
            v4.netmask(),
            "255.255.255.0".parse::<IpAddr>().expect("netmask")
        );
        assert_eq!(v4.to_string(), "192.168.1.10/24");
        assert_eq!(v4.addr(), "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(v4.prefix_length(), 24);

        let v6 = IpNetwork::new("2001:db8::1".parse().expect("IPv6"), 64);
        assert_eq!(
            v6.netmask(),
            "ffff:ffff:ffff:ffff::".parse::<IpAddr>().expect("netmask")
        );
        assert_eq!(v6.to_string(), "2001:db8::1/64");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_interface_names_are_ascii() {
        let ifaces = list_interfaces().expect("list_interfaces should succeed");
        for iface in &ifaces {
            assert!(
                iface.name.is_ascii(),
                "interface name should be decoded from ANSI, got {:?}",
                iface.name
            );
            assert!(
                iface.name.starts_with('{') && iface.name.ends_with('}'),
                "interface name should be an adapter GUID, got {:?}",
                iface.name
            );
        }
    }
}
