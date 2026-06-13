//! Network interface enumeration (cross-platform).
//!
//! Does not require elevated privileges on any platform.

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
pub fn list_interfaces() -> Result<Vec<Interface>, IoError> {
    platform_list_interfaces()
}

// ---------------------------------------------------------------------------
// Linux: SIOCGIFCONF + per-interface ioctls
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn platform_list_interfaces() -> Result<Vec<Interface>, IoError> {
    use std::os::fd::AsRawFd;
    use socket2::{Domain, Socket, Type};

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    let fd = sock.as_raw_fd();

    // SIOCGIFCONF: get all interface configs
    let mut ifc: libc::ifconf = unsafe { std::mem::zeroed() };
    let buf_size = 4096usize;
    let mut buf = vec![0u8; buf_size];
    ifc.ifc_len = buf_size as i32;
    ifc.ifc_ifcu.ifcu_buf = buf.as_mut_ptr() as *mut libc::c_char;

    if unsafe { libc::ioctl(fd, libc::SIOCGIFCONF, &mut ifc) } < 0 {
        return Err(IoError::Socket(std::io::Error::last_os_error()));
    }

    let mut interfaces = Vec::new();
    let mut pos = 0usize;
    while pos < ifc.ifc_len as usize {
        let ifr: &libc::ifreq = unsafe { &*(ifc.ifc_ifcu.ifcu_buf.add(pos) as *const libc::ifreq) };
        pos += std::mem::size_of::<libc::ifreq>();
        let name = cstr_to_string(&ifr.ifr_name);

        let mut ifr_flags = unsafe { std::mem::zeroed::<libc::ifreq>() };
        copy_ifname(&mut ifr_flags, &name);
        let is_up = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr_flags) } >= 0
            && unsafe { ifr_flags.ifr_ifru.ifru_flags & libc::IFF_UP as i16 } != 0;
        let is_loopback = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr_flags) } >= 0
            && unsafe { ifr_flags.ifr_ifru.ifru_flags & libc::IFF_LOOPBACK as i16 } != 0;

        // MAC address
        let mut ifr_hw = unsafe { std::mem::zeroed::<libc::ifreq>() };
        copy_ifname(&mut ifr_hw, &name);
        let mac = if unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifr_hw) } >= 0 {
            let sa = unsafe { &ifr_hw.ifr_ifru.ifru_hwaddr };
            Some([sa.sa_data[0] as u8, sa.sa_data[1] as u8, sa.sa_data[2] as u8,
                  sa.sa_data[3] as u8, sa.sa_data[4] as u8, sa.sa_data[5] as u8])
        } else { None };

        // IP address
        let mut ifr_addr = unsafe { std::mem::zeroed::<libc::ifreq>() };
        copy_ifname(&mut ifr_addr, &name);
        let ips = if unsafe { libc::ioctl(fd, libc::SIOCGIFADDR, &mut ifr_addr) } >= 0 {
            let sa = unsafe { &ifr_addr.ifr_ifru.ifru_addr };
            if sa.sa_family as i32 == libc::AF_INET {
                let addr_bytes = unsafe { (*(sa as *const libc::sockaddr as *const libc::sockaddr_in)).sin_addr.s_addr };
                let ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(addr_bytes)));
                vec![ip]
            } else { vec![] }
        } else { vec![] };

        interfaces.push(Interface { name, friendly_name: None, mac_address: mac, ips, is_loopback, is_up });
    }
    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn cstr_to_string(cstr: &[i8]) -> String {
    let bytes: Vec<u8> = cstr.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(target_os = "linux")]
fn copy_ifname(ifr: &mut libc::ifreq, name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(ifr.ifr_name.len() - 1);
    ifr.ifr_name[..len].copy_from_slice(unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const i8, len) });
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
        mac: Option<[u8; 6]>,
        is_loopback: bool,
        is_up: bool,
        ips: Vec<IpAddr>,
    }
    let mut map: HashMap<String, IfInfo> = HashMap::new();

    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        let name = cstr_to_string_osx(ifa.ifa_name);
        let entry = map.entry(name.clone()).or_insert_with(|| IfInfo {
            name,
            mac: None,
            is_loopback: (ifa.ifa_flags & libc::IFF_LOOPBACK as u32) != 0,
            is_up: (ifa.ifa_flags & libc::IFF_UP as u32) != 0,
            ips: vec![],
        });

        if !ifa.ifa_addr.is_null() {
            let sa = unsafe { &*ifa.ifa_addr };
            match sa.sa_family as i32 {
                libc::AF_LINK => {
                    let sdl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
                    if sdl.sdl_alen == 6 {
                        let mac_addr = unsafe { *(sdl.sdl_data.as_ptr().offset(sdl.sdl_nlen as isize) as *const [u8; 6]) };
                        entry.mac = Some(mac_addr);
                    }
                }
                libc::AF_INET => {
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    entry.ips.push(IpAddr::V4(addr));
                }
                libc::AF_INET6 => {
                    let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    entry.ips.push(IpAddr::V6(addr));
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap); }

    Ok(map.into_values().map(|info| Interface {
        name: info.name,
        friendly_name: None,
        mac_address: info.mac,
        ips: info.ips,
        is_loopback: info.is_loopback,
        is_up: info.is_up,
    }).collect())
}

#[cfg(target_os = "macos")]
fn cstr_to_string_osx(ptr: *const libc::c_char) -> String {
    if ptr.is_null() { return String::new(); }
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

    #[repr(C)]
    struct IpAdapterUnicastAddress {
        length: u32,
        _flags: u32,
        next: *mut IpAdapterUnicastAddress,
        sockaddr_ptr: *const u8,   // LPSOCKADDR
        sockaddr_len: i32,
    }

    #[repr(C)]
    struct IpAdapterAddresses {
        length: u32,
        if_index: u32,
        next: *mut IpAdapterAddresses,
        adapter_name: *const u8,
        first_unicast_address: *mut IpAdapterUnicastAddress,
        // skip: first_anycast(8), first_multicast(8), first_dns(8), dns_suffix(8), description(8), friendly_name(8)
        _pad1: [u8; 48],
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
    let ret = unsafe { GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, std::ptr::null(), std::ptr::null_mut(), &mut size) };
    if ret != 111 { return Ok(vec![]); } // ERROR_BUFFER_OVERFLOW

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe { GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, std::ptr::null(), buf.as_mut_ptr() as *mut IpAdapterAddresses, &mut size) };
    if ret != 0 { return Ok(vec![]); }

    let mut interfaces = Vec::new();
    let mut cur = buf.as_ptr() as *const IpAdapterAddresses;

    while !cur.is_null() {
        let a = unsafe { &*cur };

        let name = wide_to_string(a.adapter_name);
        let friendly_name = None; // field not directly accessible without offset; skip for now

        let mac = if a.physical_address_length == 6 {
            Some([a.physical_address[0], a.physical_address[1], a.physical_address[2],
                  a.physical_address[3], a.physical_address[4], a.physical_address[5]])
        } else { None };

        let mut ips = Vec::new();
        let mut ua = a.first_unicast_address;
        while !ua.is_null() {
            let u = unsafe { &*ua };
            if !u.sockaddr_ptr.is_null() {
                let family = unsafe { *(u.sockaddr_ptr as *const u16) };
                match family {
                    2 => { // AF_INET
                        let b = unsafe { std::slice::from_raw_parts(u.sockaddr_ptr.offset(4), 4) };
                        ips.push(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])));
                    }
                    23 => { // AF_INET6
                        let b = unsafe { std::slice::from_raw_parts(u.sockaddr_ptr.offset(8), 16) };
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(b);
                        ips.push(IpAddr::V6(Ipv6Addr::from(arr)));
                    }
                    _ => {}
                }
            }
            ua = u.next;
        }

        interfaces.push(Interface {
            name,
            friendly_name,
            mac_address: mac,
            ips,
            is_loopback: a.if_type == IF_TYPE_SOFTWARE_LOOPBACK,
            is_up: a.oper_status == IF_OPER_STATUS_UP,
        });

        cur = a.next;
    }

    Ok(interfaces)
}

#[cfg(target_os = "windows")]
fn wide_to_string(ptr: *const u8) -> String {
    if ptr.is_null() { return String::new(); }
    let len = unsafe {
        let mut end = ptr;
        loop {
            let w = u16::from_le_bytes([*end, *(end.offset(1))]);
            if w == 0 { break; }
            end = end.offset(2);
        }
        (end as usize - ptr as usize) / 2
    };
    let wide: Vec<u16> = (0..len).map(|i| unsafe {
        u16::from_le_bytes([*ptr.add(i*2), *ptr.add(i*2+1)])
    }).collect();
    String::from_utf16_lossy(&wide)
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
        assert!(ifaces.iter().any(|i| i.is_loopback), "should contain loopback");
    }
}
