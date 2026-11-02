//! macOS BPF (Berkeley Packet Filter) L2 capture and injection.
//! Implements `L2Reader` and `L2Writer` traits via /dev/bpf devices.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

use wireforge_core::ether::EthernetPacket;

use crate::common;
use crate::config::Config;
use crate::error::IoError;
use crate::traits::{L2Reader, L2Writer};

// ---------------------------------------------------------------------------
// ioctl request codes from <net/bpf.h> and <net/if.h> (macOS/BSD values).
// Defined locally instead of taken from the libc crate because BPF constants
// are not exported for every BSD target. Values follow the `_IOC` encoding:
// `_IOWR('B', n, t)` etc., with `sizeof(struct ifreq) == 32`.
// ---------------------------------------------------------------------------
const BIOCGBLEN: libc::c_ulong = 0x4004_4266; // _IOR('B', 102, u32)
const BIOCSBLEN: libc::c_ulong = 0xC044_4266; // _IOWR('B', 102, u32)
const BIOCSETIF: libc::c_ulong = 0x8020_426C; // _IOW('B', 108, struct ifreq)
const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270; // _IOW('B', 112, u32)
const BIOCPROMISC: libc::c_ulong = 0x2000_4269; // _IO('B', 105)
const SIOCGIFFLAGS: libc::c_ulong = 0xC020_6911; // _IOWR('i', 17, struct ifreq)
const SIOCSIFFLAGS: libc::c_ulong = 0x8020_6910; // _IOW('i', 16, struct ifreq)
const IFF_PROMISC: libc::c_short = 0x0100;
/// `POLLIN` from <poll.h> — not exported by the libc crate for BSD targets.
const POLLIN: libc::c_short = 0x001;

/// `BPF_ALIGNMENT` from <net/bpf.h>: records in the read buffer are padded to
/// this boundary.
const BPF_ALIGNMENT: usize = 4;
/// Minimum `bpf_hdr` size: timeval(16) + caplen(4) + datalen(4) + hdrlen(2).
const BPF_HDRLEN_MIN: usize = 26;

/// Round `x` up to the BPF record boundary (`BPF_WORDALIGN`).
fn bpf_wordalign(x: usize) -> usize {
    (x + (BPF_ALIGNMENT - 1)) & !(BPF_ALIGNMENT - 1)
}

/// Open the first available `/dev/bpfN` device (then the legacy `/dev/bpf`
/// symlink). Requires root; `EACCES` maps to [`IoError::PermissionDenied`].
fn open_bpf_device(attempts: usize, writable: bool) -> Result<File, IoError> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(writable);
    let mut last: Option<io::Error> = None;
    for i in 0..attempts.max(1) {
        match opts.open(format!("/dev/bpf{i}")) {
            Ok(dev) => return Ok(dev),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Err(IoError::PermissionDenied)
            }
            Err(e) => last = Some(e),
        }
    }
    if let Ok(dev) = opts.open("/dev/bpf") {
        return Ok(dev);
    }
    match last {
        Some(e) => Err(IoError::Socket(e)),
        None => Err(IoError::Bpf("no /dev/bpf device available")),
    }
}

fn ioctl_void(fd: libc::c_int, req: libc::c_ulong) -> Result<(), IoError> {
    if unsafe { libc::ioctl(fd, req) } < 0 {
        return Err(IoError::Socket(io::Error::last_os_error()));
    }
    Ok(())
}

fn ioctl_ptr<T>(fd: libc::c_int, req: libc::c_ulong, arg: *mut T) -> Result<(), IoError> {
    if unsafe { libc::ioctl(fd, req, arg as *mut libc::c_void) } < 0 {
        return Err(IoError::Socket(io::Error::last_os_error()));
    }
    Ok(())
}

/// Copy interface name into an ifreq's ifr_name field.
fn copy_ifname(ifr: &mut libc::ifreq, name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(ifr.ifr_name.len() - 1);
    // SAFETY: ifr_name is [c_char]; the interface name is ASCII.
    let name_i8 = unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const libc::c_char, len) };
    ifr.ifr_name[..len].copy_from_slice(name_i8);
}

/// Attach a BPF device to an interface (`BIOCSETIF`).
fn bind_bpf_to_interface(fd: libc::c_int, ifname: &str) -> Result<(), IoError> {
    let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut ifreq, ifname);
    if let Err(IoError::Socket(err)) = ioctl_ptr(fd, BIOCSETIF, &mut ifreq) {
        return Err(match err.raw_os_error() {
            Some(libc::ENXIO) | Some(libc::ENOENT) | Some(libc::ENODEV) => {
                IoError::InterfaceNotFound(ifname.to_string())
            }
            _ => IoError::Socket(err),
        });
    }
    Ok(())
}

/// BPF-based L2 frame reader.
pub struct BpfReader {
    dev: File,
    ifname: String,
    /// Read buffer holding one BPF "read return" batch of records.
    buf: Vec<u8>,
    /// Parse cursor into `buf`; `buf[offset..len]` are unprocessed bytes.
    offset: usize,
    len: usize,
    timeout: Option<Duration>,
}

impl BpfReader {
    /// Open a BPF device and bind to the given interface.
    pub fn new(ifname: &str) -> Result<Self, IoError> {
        Self::with_config(ifname, Config::default())
    }

    /// Open a BPF device with the given configuration.
    pub fn with_config(ifname: &str, config: Config) -> Result<Self, IoError> {
        let dev = open_bpf_device(config.bpf_fd_attempts, true)?;
        let fd = dev.as_raw_fd();

        if ifname.len() >= 16 {
            return Err(IoError::InterfaceNotFound(ifname.to_string()));
        }
        // BIOCSBLEN must be set before BIOCSETIF (bpf(4)).
        if config.read_buffer_size > 0 {
            let mut blen = config.read_buffer_size as u32;
            ioctl_ptr(fd, BIOCSBLEN, &mut blen)?;
        }
        bind_bpf_to_interface(fd, ifname)?;
        // Deliver each packet as soon as it arrives instead of waiting for the
        // buffer to fill — matches the AF_PACKET backend's per-read semantics.
        let mut one: u32 = 1;
        ioctl_ptr(fd, BIOCIMMEDIATE, &mut one)?;
        let mut blen: u32 = 0;
        ioctl_ptr(fd, BIOCGBLEN, &mut blen)?;
        let buf = vec![0u8; (blen as usize).max(BPF_HDRLEN_MIN * 2)];

        let mut reader = Self {
            dev,
            ifname: ifname.to_string(),
            buf,
            offset: 0,
            len: 0,
            timeout: None,
        };
        reader.timeout = config.read_timeout;
        if config.promiscuous {
            reader.set_promiscuous(true)?;
        }
        Ok(reader)
    }

    /// Block until the device is readable or the configured timeout expires.
    /// BPF devices are character devices, so `SO_RCVTIMEO` does not apply;
    /// `poll(2)` is the portable timeout mechanism.
    fn wait_readable(&self) -> Result<(), IoError> {
        let Some(d) = self.timeout else {
            return Ok(()); // plain blocking read
        };
        let mut pfd = libc::pollfd {
            fd: self.dev.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        let mut ms = d.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        if ms == 0 && !d.is_zero() {
            ms = 1; // avoid turning a sub-millisecond timeout into a non-blocking poll
        }
        let n = unsafe { libc::poll(&mut pfd, 1, ms) };
        if n < 0 {
            return Err(IoError::Socket(io::Error::last_os_error()));
        }
        if n == 0 {
            return Err(IoError::Timeout);
        }
        Ok(())
    }

    /// Locate the next BPF record in the read buffer and return its frame
    /// byte range. Returns `None` when the buffered batch is exhausted.
    ///
    /// Takes `&self` only and returns indices instead of a slice: `recv`
    /// must be able to advance the cursor (`&mut`) before returning a
    /// reference into `self.buf`, which one combined `&mut self` method
    /// would not type-check.
    fn locate_frame(&self) -> Option<Result<(usize, usize), IoError>> {
        if self.len - self.offset < BPF_HDRLEN_MIN {
            return None;
        }
        let b = &self.buf[self.offset..self.len];
        // bpf_hdr: timeval(16) | caplen u32 | datalen u32 | hdrlen u16,
        // all native-endian. hdrlen is authoritative and may exceed the
        // minimum if the header is ever extended.
        let caplen = u32::from_ne_bytes([b[16], b[17], b[18], b[19]]) as usize;
        let _datalen = u32::from_ne_bytes([b[20], b[21], b[22], b[23]]) as usize;
        let hdrlen = u16::from_ne_bytes([b[24], b[25]]) as usize;
        let frame_start = self.offset + hdrlen;
        let frame_end = frame_start + caplen;
        if hdrlen < BPF_HDRLEN_MIN || frame_end > self.len {
            return Some(Err(IoError::Parse("corrupt BPF record header")));
        }
        Some(Ok((frame_start, frame_end)))
    }

    /// Receive a single Ethernet frame and parse it.
    pub fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> {
        loop {
            if let Some(res) = self.locate_frame() {
                let (start, end) = res?;
                self.offset = bpf_wordalign(end).min(self.len);
                return EthernetPacket::new(&self.buf[start..end])
                    .ok_or(IoError::Parse("invalid Ethernet frame"));
            }
            // Buffer exhausted — fetch a new batch of records.
            self.wait_readable()?;
            let buf_len = self.buf.len();
            let n = loop {
                let n = unsafe {
                    libc::read(
                        self.dev.as_raw_fd(),
                        self.buf.as_mut_ptr() as *mut libc::c_void,
                        buf_len,
                    )
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(common::recv_error(err));
                }
                break n as usize;
            };
            if n == 0 {
                return Err(IoError::Socket(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "BPF device returned EOF",
                )));
            }
            self.offset = 0;
            self.len = n;
        }
    }

    /// Set the receive timeout. `None` means blocking (no timeout).
    pub fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        self.timeout = dur;
        Ok(())
    }

    /// Enable or disable promiscuous mode.
    pub fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError> {
        let fd = self.dev.as_raw_fd();
        if on {
            return ioctl_void(fd, BIOCPROMISC);
        }
        // BPF has no "leave promiscuous mode" ioctl; clear the interface flag
        // through SIOCSIFFLAGS instead.
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        copy_ifname(&mut ifreq, &self.ifname);
        ioctl_ptr(fd, SIOCGIFFLAGS, &mut ifreq)?;
        // SAFETY: reading the ifru_flags union member set by SIOCGIFFLAGS.
        let mut flags = unsafe { ifreq.ifr_ifru.ifru_flags };
        flags &= !IFF_PROMISC;
        // Writing a Copy union field is safe; reading it is what needs unsafe.
        ifreq.ifr_ifru.ifru_flags = flags;
        ioctl_ptr(fd, SIOCSIFFLAGS, &mut ifreq)
    }
}

/// BPF-based L2 frame writer.
pub struct BpfWriter {
    dev: File,
}

impl BpfWriter {
    /// Open a BPF device for injection on the given interface.
    pub fn new(ifname: &str) -> Result<Self, IoError> {
        Self::with_config(ifname, Config::default())
    }

    /// Open a BPF device with the given configuration.
    ///
    /// `write_buffer_size` and `write_timeout` are ignored: BPF devices are
    /// character devices and expose no `SO_SNDBUF`/`SO_SNDTIMEO` equivalent.
    pub fn with_config(ifname: &str, config: Config) -> Result<Self, IoError> {
        let dev = open_bpf_device(config.bpf_fd_attempts, true)?;
        if ifname.len() >= 16 {
            return Err(IoError::InterfaceNotFound(ifname.to_string()));
        }
        bind_bpf_to_interface(dev.as_raw_fd(), ifname)?;
        Ok(Self { dev })
    }

    /// Send raw bytes as an Ethernet frame on the bound interface.
    pub fn send(&self, packet: &[u8]) -> Result<usize, IoError> {
        let n = unsafe {
            libc::write(
                self.dev.as_raw_fd(),
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
            )
        };
        if n < 0 {
            return Err(IoError::Socket(io::Error::last_os_error()));
        }
        Ok(n as usize)
    }
}

// Trait implementations
impl L2Reader for BpfReader {
    fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> {
        self.recv()
    }

    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        self.set_timeout(dur)
    }

    fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError> {
        self.set_promiscuous(on)
    }
}

impl L2Writer for BpfWriter {
    fn send(&self, packet: &[u8]) -> Result<usize, IoError> {
        self.send(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_wordalign_rounds_up_to_record_boundary() {
        assert_eq!(bpf_wordalign(0), 0);
        assert_eq!(bpf_wordalign(1), 4);
        assert_eq!(bpf_wordalign(4), 4);
        assert_eq!(bpf_wordalign(5), 8);
        // A minimal record (26-byte header + 1-byte payload) advances by 28.
        assert_eq!(bpf_wordalign(BPF_HDRLEN_MIN + 1), BPF_HDRLEN_MIN + 2);
    }
}
