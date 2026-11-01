//! Windows NPcap L2 capture and injection via dynamic FFI to wpcap.dll.
//! Implements `L2Reader` and `L2Writer`.

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
    device: *const c_char,
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    errbuf: *mut c_char,
) -> PcapT;

type PcapNextExFn = unsafe extern "system" fn(
    p: PcapT,
    pkt_header: *mut *mut PcapPktHdr,
    pkt_data: *mut *const c_uchar,
) -> c_int;

type PcapCloseFn = unsafe extern "system" fn(p: PcapT);

type PcapFindAllDevsFn =
    unsafe extern "system" fn(alldevsp: *mut *mut PcapIfT, errbuf: *mut c_char) -> c_int;

type PcapFreeAllDevsFn = unsafe extern "system" fn(alldevs: *mut PcapIfT);

type PcapSendPacketFn =
    unsafe extern "system" fn(p: PcapT, buf: *const c_uchar, size: c_int) -> c_int;

type PcapGetErrFn = unsafe extern "system" fn(p: PcapT) -> *const c_char;

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
    #[allow(dead_code)]
    fn FreeLibrary(hModule: *mut std::ffi::c_void) -> c_int;
    fn GetProcAddress(
        hModule: *mut std::ffi::c_void,
        lpProcName: *const u8,
    ) -> Option<unsafe extern "system" fn()>;
}

fn load_dll(name: &str) -> Result<*mut std::ffi::c_void, IoError> {
    let cname = CString::new(name).map_err(|_| IoError::Parse("invalid DLL name"))?;
    let ptr = cname.as_ptr() as *const u8;
    let handle = unsafe { LoadLibraryA(ptr) };
    if handle.is_null() {
        return Err(IoError::Npcap(format!(
            "{name} not found. Install Npcap from https://npcap.com"
        )));
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

struct NpcapFns {
    #[allow(dead_code)]
    dll: *mut std::ffi::c_void,
    open_live: PcapOpenLiveFn,
    next_ex: PcapNextExFn,
    close: PcapCloseFn,
    // Used by tests today; also needed by Windows interface enumeration (#8).
    #[allow(dead_code)]
    find_all_devs: PcapFindAllDevsFn,
    #[allow(dead_code)]
    free_all_devs: PcapFreeAllDevsFn,
    send_packet: PcapSendPacketFn,
    get_err: PcapGetErrFn,
}

// SAFETY: Function pointers are read-only after initialization. DLL handle is never freed.
unsafe impl Send for NpcapFns {}
unsafe impl Sync for NpcapFns {}

static NPCAP_FNS: OnceLock<Option<NpcapFns>> = OnceLock::new();

fn get_npcap() -> Result<&'static NpcapFns, IoError> {
    NPCAP_FNS
        .get_or_init(|| {
            let dll = match load_dll("wpcap.dll") {
                Ok(h) => h,
                Err(_) => return None,
            };
            let open_live: PcapOpenLiveFn = get_proc(dll, "pcap_open_live")?;
            let next_ex: PcapNextExFn = get_proc(dll, "pcap_next_ex")?;
            let close: PcapCloseFn = get_proc(dll, "pcap_close")?;
            let find_all_devs: PcapFindAllDevsFn = get_proc(dll, "pcap_findalldevs")?;
            let free_all_devs: PcapFreeAllDevsFn = get_proc(dll, "pcap_freealldevs")?;
            let send_packet: PcapSendPacketFn = get_proc(dll, "pcap_sendpacket")?;
            let get_err: PcapGetErrFn = get_proc(dll, "pcap_geterr")?;
            Some(NpcapFns {
                dll,
                open_live,
                next_ex,
                close,
                find_all_devs,
                free_all_devs,
                send_packet,
                get_err,
            })
        })
        .as_ref()
        .ok_or_else(|| {
            IoError::Npcap("wpcap.dll not found. Install Npcap from https://npcap.com".into())
        })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Snap length used for capture and injection handles.
const SNAPLEN: c_int = 65535;

/// Default read timeout, matching the previous hard-coded `pcap_open_live` value.
const DEFAULT_TIMEOUT_MS: c_int = 1000;

fn timeout_to_ms(dur: Option<Duration>) -> c_int {
    match dur {
        None => 0,
        Some(d) => d.as_millis().min(c_int::MAX as u128) as c_int,
    }
}

/// Translate a Windows adapter name into an Npcap device name.
///
/// `list_interfaces()` returns the IP Helper API `AdapterName`, which is the
/// adapter GUID in braces (`{...}`). Npcap expects `\Device\NPF_{GUID}`.
/// Names that already look like Npcap device names are left untouched.
fn npcap_device_name(name: &str) -> String {
    if name.starts_with("\\Device\\NPF") {
        name.to_string()
    } else if name.starts_with('{') {
        format!("\\Device\\NPF_{name}")
    } else {
        name.to_string()
    }
}

fn open_live(
    npcap: &NpcapFns,
    device: &CStr,
    promisc: bool,
    timeout_ms: c_int,
) -> Result<PcapT, IoError> {
    let mut errbuf = vec![0u8; 256];
    let handle = unsafe {
        (npcap.open_live)(
            device.as_ptr(),
            SNAPLEN,
            if promisc { 1 } else { 0 },
            timeout_ms,
            errbuf.as_mut_ptr() as *mut c_char,
        )
    };
    if handle.is_null() {
        let msg = CStr::from_bytes_until_nul(&errbuf)
            .ok()
            .and_then(|s| s.to_str().ok())
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown error");
        return Err(IoError::Npcap(format!("pcap_open_live failed: {msg}")));
    }
    Ok(handle)
}

/// Best-effort error message from a live pcap handle.
unsafe fn pcap_error(npcap: &NpcapFns, handle: PcapT) -> String {
    let ptr = (npcap.get_err)(handle);
    if ptr.is_null() {
        "unknown pcap error".into()
    } else {
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// ---------------------------------------------------------------------------
// NpcapReader
// ---------------------------------------------------------------------------

pub struct NpcapReader {
    handle: PcapT,
    ifname: CString,
    promisc: bool,
    timeout_ms: c_int,
}

impl NpcapReader {
    /// Open a capture handle with default settings: promiscuous mode off and a
    /// 1-second read timeout.
    pub fn new(ifname: &str) -> Result<Self, IoError> {
        Self::with_options(
            ifname,
            false,
            Some(Duration::from_millis(DEFAULT_TIMEOUT_MS as u64)),
        )
    }

    /// Open a capture handle with explicit promiscuous and timeout settings.
    ///
    /// `timeout`: `None` blocks indefinitely; `Some(d)` sets the read timeout.
    pub fn with_options(
        ifname: &str,
        promisc: bool,
        timeout: Option<Duration>,
    ) -> Result<Self, IoError> {
        let npcap = get_npcap()?;
        let device = CString::new(npcap_device_name(ifname))
            .map_err(|_| IoError::Parse("invalid interface name"))?;
        let timeout_ms = timeout_to_ms(timeout);
        let handle = open_live(npcap, &device, promisc, timeout_ms)?;
        Ok(Self {
            handle,
            ifname: device,
            promisc,
            timeout_ms,
        })
    }

    pub fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> {
        if self.handle.is_null() {
            return Err(IoError::Npcap("capture handle is closed".into()));
        }
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
            _ => {
                let msg = unsafe { pcap_error(npcap, self.handle) };
                Err(IoError::Npcap(format!("pcap_next_ex error: {msg}")))
            }
        }
    }

    /// Re-open the capture handle with new settings.
    ///
    /// The new handle is opened before the old one is closed, so a failed
    /// re-open leaves the current reader usable.
    fn reopen_with(&mut self, promisc: bool, timeout_ms: c_int) -> Result<(), IoError> {
        let npcap = get_npcap()?;
        let new_handle = open_live(npcap, &self.ifname, promisc, timeout_ms)?;
        let old_handle = std::mem::replace(&mut self.handle, new_handle);
        self.promisc = promisc;
        self.timeout_ms = timeout_ms;
        if !old_handle.is_null() {
            unsafe {
                (npcap.close)(old_handle);
            }
        }
        Ok(())
    }
}

impl L2Reader for NpcapReader {
    fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> {
        self.recv()
    }

    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        self.reopen_with(self.promisc, timeout_to_ms(dur))
    }

    fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError> {
        self.reopen_with(on, self.timeout_ms)
    }
}

impl Drop for NpcapReader {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if let Ok(npcap) = get_npcap() {
                unsafe {
                    (npcap.close)(self.handle);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NpcapWriter
// ---------------------------------------------------------------------------

pub struct NpcapWriter {
    handle: PcapT,
}

impl NpcapWriter {
    /// Open an injection handle for the given Npcap device.
    pub fn new(ifname: &str) -> Result<Self, IoError> {
        let npcap = get_npcap()?;
        let device = CString::new(npcap_device_name(ifname))
            .map_err(|_| IoError::Parse("invalid interface name"))?;
        let handle = open_live(npcap, &device, false, DEFAULT_TIMEOUT_MS)?;
        Ok(Self { handle })
    }

    /// Send raw bytes as an Ethernet frame. Returns the number of bytes sent.
    pub fn send(&self, packet: &[u8]) -> Result<usize, IoError> {
        if self.handle.is_null() {
            return Err(IoError::Npcap("injection handle is closed".into()));
        }
        let npcap = get_npcap()?;
        let size = c_int::try_from(packet.len())
            .map_err(|_| IoError::Npcap("packet is too large to inject".into()))?;
        let ret =
            unsafe { (npcap.send_packet)(self.handle, packet.as_ptr() as *const c_uchar, size) };
        if ret != 0 {
            let msg = unsafe { pcap_error(npcap, self.handle) };
            return Err(IoError::Npcap(format!("pcap_sendpacket failed: {msg}")));
        }
        Ok(packet.len())
    }
}

impl Drop for NpcapWriter {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if let Ok(npcap) = get_npcap() {
                unsafe {
                    (npcap.close)(self.handle);
                }
            }
        }
    }
}

impl L2Writer for NpcapWriter {
    fn send(&self, packet: &[u8]) -> Result<usize, IoError> {
        self.send(packet)
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
        assert!(
            get_npcap().is_ok(),
            "NPcap should be available on this system"
        );
    }

    #[test]
    fn list_devices() {
        let npcap = get_npcap().expect("NPcap should be available");
        let mut alldevs: *mut PcapIfT = std::ptr::null_mut();
        let mut errbuf = vec![0u8; 256];
        let ret =
            unsafe { (npcap.find_all_devs)(&mut alldevs, errbuf.as_mut_ptr() as *mut c_char) };
        assert_eq!(ret, 0, "pcap_findalldevs should succeed");
        let mut count = 0;
        let mut cur = alldevs;
        while !cur.is_null() {
            let dev = unsafe { &*cur };
            let name = unsafe { CStr::from_ptr(dev.name) }.to_str().unwrap_or("");
            if !name.is_empty() {
                count += 1;
            }
            cur = dev.next;
        }
        unsafe {
            (npcap.free_all_devs)(alldevs);
        }
        assert!(count > 0, "should find at least one device");
    }

    #[test]
    fn test_loopback_capture() {
        let ifname = match find_npcap_device("Loopback") {
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

    /// Find an Npcap device whose name or description contains `needle`.
    fn find_npcap_device(needle: &str) -> Option<String> {
        let npcap = get_npcap().ok()?;
        let mut alldevs: *mut PcapIfT = std::ptr::null_mut();
        let mut errbuf = vec![0u8; 256];
        let ret =
            unsafe { (npcap.find_all_devs)(&mut alldevs, errbuf.as_mut_ptr() as *mut c_char) };
        if ret != 0 {
            return None;
        }

        let mut found = None;
        let mut cur = alldevs;
        while !cur.is_null() {
            let dev = unsafe { &*cur };
            let name = unsafe { CStr::from_ptr(dev.name) }.to_str().unwrap_or("");
            let desc = if dev.description.is_null() {
                ""
            } else {
                unsafe { CStr::from_ptr(dev.description) }
                    .to_str()
                    .unwrap_or("")
            };
            if name.contains(needle) || desc.contains(needle) {
                found = Some(name.to_string());
                break;
            }
            cur = dev.next;
        }
        unsafe {
            (npcap.free_all_devs)(alldevs);
        }
        found
    }

    #[test]
    fn npcap_device_name_normalizes_guid() {
        const GUID: &str = "{A7D0AF84-9652-4724-A194-86DC99F75C1B}";
        assert_eq!(
            npcap_device_name(GUID),
            "\\Device\\NPF_{A7D0AF84-9652-4724-A194-86DC99F75C1B}"
        );
        assert_eq!(
            npcap_device_name("\\Device\\NPF_{A7D0AF84-9652-4724-A194-86DC99F75C1B}"),
            "\\Device\\NPF_{A7D0AF84-9652-4724-A194-86DC99F75C1B}"
        );
        assert_eq!(
            npcap_device_name("\\Device\\NPF_Loopback"),
            "\\Device\\NPF_Loopback"
        );
    }

    #[test]
    #[ignore = "requires Npcap and an adapter that permits capture"]
    fn npcap_opens_adapter_by_guid() {
        let ifaces = crate::list_interfaces().expect("list_interfaces should succeed");
        let mut attempted = 0;
        for iface in ifaces.iter().filter(|i| i.name.starts_with('{')) {
            attempted += 1;
            if NpcapReader::with_options(&iface.name, false, Some(Duration::from_millis(200)))
                .is_ok()
            {
                return;
            }
        }
        if attempted == 0 {
            return;
        }
        panic!("no adapter could be opened using an Interface name from list_interfaces()");
    }

    #[test]
    #[ignore = "requires Npcap and the Npcap loopback adapter"]
    fn npcap_writer_opens_loopback() {
        let ifname = match find_npcap_device("Loopback") {
            Some(name) => name,
            None => return,
        };
        let _writer = NpcapWriter::new(&ifname).expect("writer should open loopback adapter");
    }

    #[test]
    #[ignore = "requires Npcap and the Npcap loopback adapter"]
    fn npcap_writer_sends_frame() {
        let ifname = match find_npcap_device("Loopback") {
            Some(name) => name,
            None => return,
        };
        let writer = NpcapWriter::new(&ifname).expect("writer should open loopback adapter");

        // 60-byte Ethernet frame with a locally assigned experimental EtherType.
        let mut frame = vec![0u8; 60];
        frame[0..6].copy_from_slice(&[0xFF; 6]); // broadcast
        frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame[12..14].copy_from_slice(&[0x88, 0xB5]); // IEEE 802 local experimental

        let sent = writer.send(&frame).expect("send should succeed");
        assert_eq!(sent, frame.len());
    }

    #[test]
    #[ignore = "requires Npcap and the Npcap loopback adapter"]
    fn npcap_reader_set_promiscuous_reopens() {
        let ifname = match find_npcap_device("Loopback") {
            Some(name) => name,
            None => return,
        };
        let mut reader = NpcapReader::new(&ifname).expect("reader should open");

        reader
            .set_promiscuous(true)
            .expect("enabling promiscuous mode should succeed");
        reader
            .set_promiscuous(false)
            .expect("disabling promiscuous mode should succeed");

        // The reopened handle must still be usable.
        reader
            .set_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        match reader.recv() {
            Ok(_) | Err(IoError::Timeout) => {}
            Err(e) => panic!("unexpected error after reopen: {e}"),
        }
    }

    #[test]
    #[ignore = "requires Npcap and the Npcap loopback adapter"]
    fn npcap_reader_set_timeout_takes_effect() {
        use std::time::Instant;

        let ifname = match find_npcap_device("Loopback") {
            Some(name) => name,
            None => return,
        };
        let mut reader = NpcapReader::new(&ifname).expect("reader should open");

        reader
            .set_timeout(Some(Duration::from_millis(100)))
            .expect("set_timeout should succeed");

        // Drain whatever is already queued, then measure a fresh timeout.
        let drain_deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < drain_deadline {
            match reader.recv() {
                Ok(_) => continue,
                Err(IoError::Timeout) => break,
                Err(e) => panic!("unexpected error while draining: {e}"),
            }
        }

        let start = Instant::now();
        match reader.recv() {
            Err(IoError::Timeout) => {}
            Ok(_) => return, // unrelated traffic arrived; timing cannot be measured
            Err(e) => panic!("unexpected error: {e}"),
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(700),
            "recv should honor the 100 ms timeout, took {elapsed:?}"
        );
    }
}
