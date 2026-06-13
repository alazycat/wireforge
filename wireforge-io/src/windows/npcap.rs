//! Windows NPcap L2 capture via dynamic FFI to wpcap.dll.
//! Implements `L2Reader` trait. L2 send is unsupported on this platform.

use std::ffi::{c_char, c_int, c_uchar, c_uint, CStr, CString};
use std::sync::OnceLock;
use std::time::Duration;

use wireforge_core::ether::EthernetPacket;

use crate::error::IoError;
use crate::traits::{L2Reader, L2Writer};

// ---------------------------------------------------------------------------
// C types
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types)]
type bpf_u_int32 = c_uint;
#[allow(non_camel_case_types)]
type time_t = i64;

#[repr(C)]
struct TimeVal {
    tv_sec: time_t,
    tv_usec: i64,
}

#[repr(C)]
struct PcapPktHdr {
    ts: TimeVal,
    caplen: bpf_u_int32,
    len: bpf_u_int32,
}

type PcapT = *mut std::ffi::c_void;

type PcapOpenLiveFn = unsafe extern "system" fn(
    device: *const c_char, snaplen: c_int, promisc: c_int, to_ms: c_int, errbuf: *mut c_char,
) -> PcapT;

type PcapNextExFn = unsafe extern "system" fn(
    p: PcapT, pkt_header: *mut *mut PcapPktHdr, pkt_data: *mut *const c_uchar,
) -> c_int;

type PcapCloseFn = unsafe extern "system" fn(p: PcapT);

type PcapFindAllDevsFn = unsafe extern "system" fn(
    alldevsp: *mut *mut PcapIfT, errbuf: *mut c_char,
) -> c_int;

type PcapFreeAllDevsFn = unsafe extern "system" fn(alldevs: *mut PcapIfT);

type PcapSetTimeoutFn = unsafe extern "system" fn(p: PcapT, timeout_ms: c_int) -> c_int;

#[repr(C)]
struct PcapIfT {
    next: *mut PcapIfT,
    name: *const c_char,
    description: *const c_char,
    addresses: *mut std::ffi::c_void,
    flags: bpf_u_int32,
}

// ---------------------------------------------------------------------------
// DLL loading helpers — raw Win32 FFI
// ---------------------------------------------------------------------------

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lpFileName: *const u8) -> *mut std::ffi::c_void;
    fn FreeLibrary(hModule: *mut std::ffi::c_void) -> c_int;
    fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> Option<unsafe extern "system" fn()>;
}

fn load_dll(name: &str) -> Result<*mut std::ffi::c_void, IoError> {
    let cname = CString::new(name).map_err(|_| IoError::Parse("invalid DLL name"))?;
    let ptr = cname.as_ptr() as *const u8;
    let handle = unsafe { LoadLibraryA(ptr) };
    if handle.is_null() {
        return Err(IoError::Npcap(format!("{name} not found. Install Npcap from https://npcap.com")));
    }
    Ok(handle)
}

fn get_proc<T>(dll: *mut std::ffi::c_void, name: &str) -> Option<T> {
    let cname = CString::new(name).ok()?;
    let ptr = cname.as_ptr() as *const u8;
    unsafe {
        let f = GetProcAddress(dll, ptr)?;
        Some(std::mem::transmute_copy(&f))
    }
}

// ---------------------------------------------------------------------------
// Function pointer cache
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct NpcapFns {
    dll: *mut std::ffi::c_void,
    open_live: PcapOpenLiveFn,
    next_ex: PcapNextExFn,
    close: PcapCloseFn,
    find_all_devs: PcapFindAllDevsFn,
    free_all_devs: PcapFreeAllDevsFn,
    set_timeout: PcapSetTimeoutFn,
}

// SAFETY: Function pointers are read-only after initialization. DLL handle is never freed.
unsafe impl Send for NpcapFns {}
unsafe impl Sync for NpcapFns {}

static NPCAP_FNS: OnceLock<Option<NpcapFns>> = OnceLock::new();

fn get_npcap() -> Result<&'static NpcapFns, IoError> {
    NPCAP_FNS.get_or_init(|| {
        let dll = match load_dll("wpcap.dll") {
            Ok(h) => h,
            Err(_) => return None,
        };
        let open_live: PcapOpenLiveFn = get_proc(dll, "pcap_open_live")?;
        let next_ex: PcapNextExFn = get_proc(dll, "pcap_next_ex")?;
        let close: PcapCloseFn = get_proc(dll, "pcap_close")?;
        let find_all_devs: PcapFindAllDevsFn = get_proc(dll, "pcap_findalldevs")?;
        let free_all_devs: PcapFreeAllDevsFn = get_proc(dll, "pcap_freealldevs")?;
        let set_timeout: PcapSetTimeoutFn = get_proc(dll, "pcap_set_timeout")?;
        Some(NpcapFns { dll, open_live, next_ex, close, find_all_devs, free_all_devs, set_timeout })
    })
    .as_ref()
    .ok_or_else(|| IoError::Npcap("wpcap.dll not found. Install Npcap from https://npcap.com".into()))
}

// ---------------------------------------------------------------------------
// NpcapReader
// ---------------------------------------------------------------------------

pub struct NpcapReader {
    handle: PcapT,
}

impl NpcapReader {
    pub fn new(ifname: &str) -> Result<Self, IoError> {
        let npcap = get_npcap()?;
        let device = CString::new(ifname).map_err(|_| IoError::Parse("invalid interface name"))?;
        let mut errbuf = vec![0u8; 256];
        let handle = unsafe {
            (npcap.open_live)(device.as_ptr(), 65535, 0, 1000, errbuf.as_mut_ptr() as *mut c_char)
        };
        if handle.is_null() {
            let msg = CStr::from_bytes_until_nul(&errbuf)
                .ok()
                .and_then(|s| s.to_str().ok())
                .unwrap_or("unknown error");
            return Err(IoError::Npcap(format!("pcap_open_live failed: {msg}")));
        }
        Ok(Self { handle })
    }

    pub fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> {
        let npcap = get_npcap()?;
        let mut header: *mut PcapPktHdr = std::ptr::null_mut();
        let mut data: *const c_uchar = std::ptr::null();
        let ret = unsafe { (npcap.next_ex)(self.handle, &mut header, &mut data) };
        match ret {
            1 => {
                let hdr = unsafe { &*header };
                let len = hdr.caplen as usize;
                let packet_data = unsafe { std::slice::from_raw_parts(data, len) };
                EthernetPacket::new(packet_data).ok_or(IoError::Parse("invalid Ethernet frame"))
            }
            0 => Err(IoError::Timeout),
            _ => Err(IoError::Npcap("pcap_next_ex error".into())),
        }
    }
}

impl L2Reader for NpcapReader {
    fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> { self.recv() }

    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        let npcap = get_npcap()?;
        let ms = dur.map(|d| d.as_millis() as c_int).unwrap_or(0);
        unsafe { (npcap.set_timeout)(self.handle, ms) };
        Ok(())
    }

    fn set_promiscuous(&mut self, _on: bool) -> Result<(), IoError> {
        Err(IoError::Npcap("set_promiscuous: re-create reader with desired promisc mode".into()))
    }
}

impl Drop for NpcapReader {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if let Ok(npcap) = get_npcap() {
                unsafe { (npcap.close)(self.handle); }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NpcapWriter — unsupported on Windows
// ---------------------------------------------------------------------------

pub struct NpcapWriter;

impl NpcapWriter {
    pub fn new(_ifname: &str) -> Result<Self, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

impl L2Writer for NpcapWriter {
    fn send(&self, _packet: &[u8]) -> Result<usize, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npcap_available() {
        assert!(get_npcap().is_ok(), "NPcap should be available on this system");
    }

    #[test]
    fn list_devices() {
        let npcap = get_npcap().expect("NPcap should be available");
        let mut alldevs: *mut PcapIfT = std::ptr::null_mut();
        let mut errbuf = vec![0u8; 256];
        let ret = unsafe { (npcap.find_all_devs)(&mut alldevs, errbuf.as_mut_ptr() as *mut c_char) };
        assert_eq!(ret, 0, "pcap_findalldevs should succeed");
        let mut count = 0;
        let mut cur = alldevs;
        while !cur.is_null() {
            let dev = unsafe { &*cur };
            let name = unsafe { CStr::from_ptr(dev.name) }.to_str().unwrap_or("");
            if !name.is_empty() { count += 1; }
            cur = dev.next;
        }
        unsafe { (npcap.free_all_devs)(alldevs); }
        assert!(count > 0, "should find at least one device");
    }

    #[test]
    fn test_loopback_capture() {
        let npcap = get_npcap().expect("NPcap should be available");
        let mut alldevs: *mut PcapIfT = std::ptr::null_mut();
        let mut errbuf = vec![0u8; 256];
        unsafe { (npcap.find_all_devs)(&mut alldevs, errbuf.as_mut_ptr() as *mut c_char); }

        let mut loopback_name = None;
        let mut cur = alldevs;
        while !cur.is_null() {
            let dev = unsafe { &*cur };
            let name = unsafe { CStr::from_ptr(dev.name) }.to_str().unwrap_or("");
            let desc = if dev.description.is_null() { "" } else {
                unsafe { CStr::from_ptr(dev.description) }.to_str().unwrap_or("")
            };
            if name.contains("Loopback") || desc.contains("Loopback") {
                loopback_name = Some(name.to_string());
                break;
            }
            cur = dev.next;
        }
        unsafe { (npcap.free_all_devs)(alldevs); }

        let ifname = match loopback_name {
            Some(name) => name,
            None => {
                eprintln!("No NPcap loopback adapter found; skipping capture test");
                return;
            }
        };

        let mut reader = NpcapReader::new(&ifname).expect("should open loopback adapter");
        reader.set_timeout(Some(Duration::from_secs(1))).ok();

        match reader.recv() {
            Ok(_pkt) => { /* captured a packet */ }
            Err(IoError::Timeout) => { /* expected on idle loopback */ }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
