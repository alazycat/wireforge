//! L2 (AF_PACKET) socket I/O — Ethernet frame capture and injection.

use std::os::fd::AsRawFd;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use wireforge_core::ether::EthernetPacket;

use crate::error::IoError;
use crate::traits::{L2Reader, L2Writer};

/// Receiver for raw L2 Ethernet frames via AF_PACKET socket.
pub struct L2Receiver {
    sock: Socket,
    buf: Vec<u8>,
    ifname: String,
}

impl L2Receiver {
    /// Open an AF_PACKET socket and bind to the given interface.
    pub fn new(ifname: &str) -> Result<Self, IoError> {
        let sock = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(libc::ETH_P_ALL)),
        )?;

        // Bind to interface using SO_BINDTODEVICE
        sock.bind_device(Some(ifname.as_bytes()))?;

        Ok(Self {
            sock,
            buf: vec![0u8; 65536],
            ifname: ifname.to_string(),
        })
    }

    /// Receive a single Ethernet frame and parse it.
    pub fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> {
        let n = unsafe {
            libc::recv(
                self.sock.as_raw_fd(),
                self.buf.as_mut_ptr() as *mut libc::c_void,
                self.buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(IoError::Socket(std::io::Error::last_os_error()));
        }
        let n = n as usize;
        EthernetPacket::new(&self.buf[..n]).ok_or(IoError::Parse("invalid Ethernet frame"))
    }

    /// Enable or disable promiscuous mode.
    pub fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError> {
        let fd = self.sock.as_raw_fd();
        unsafe {
            let mut ifreq: libc::ifreq = std::mem::zeroed();
            copy_ifname(&mut ifreq, &self.ifname);
            // Read current flags
            libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifreq);
            let mut flags = ifreq.ifr_ifru.ifru_flags;
            if on {
                flags |= libc::IFF_PROMISC as i16;
            } else {
                flags &= !(libc::IFF_PROMISC as i16);
            }
            ifreq.ifr_ifru.ifru_flags = flags;
            if libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifreq) < 0 {
                return Err(IoError::Socket(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    /// Set receive timeout.
    pub fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        let tv = dur.map(|d| libc::timeval {
            tv_sec: d.as_secs() as libc::time_t,
            tv_usec: d.subsec_micros() as libc::suseconds_t,
        });
        let tv_ref = tv.as_ref();
        let tv_ptr: *const libc::timeval = match tv_ref {
            Some(t) => t,
            None => std::ptr::null(),
        };
        let fd = self.sock.as_raw_fd();
        unsafe {
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                tv_ptr as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            ) < 0
            {
                return Err(IoError::Socket(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}

/// Sender for raw L2 Ethernet frames via AF_PACKET socket.
pub struct L2Sender {
    sock: Socket,
    sockaddr: libc::sockaddr_ll,
}

impl L2Sender {
    /// Open an AF_PACKET socket for sending on the given interface.
    pub fn new(ifname: &str) -> Result<Self, IoError> {
        let sock = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(libc::ETH_P_ALL)),
        )?;

        let fd = sock.as_raw_fd();
        let ifindex = unsafe {
            let mut ifreq: libc::ifreq = std::mem::zeroed();
            let name_bytes = ifname.as_bytes();
            let copy_len = name_bytes.len().min(ifreq.ifr_name.len() - 1);
            // SAFETY: ifr_name is [i8]; we copy raw bytes from the interface name
            let name_i8 = std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, copy_len);
            ifreq.ifr_name[..copy_len].copy_from_slice(name_i8);
            libc::ioctl(fd, libc::SIOCGIFINDEX, &mut ifreq);
            ifreq.ifr_ifru.ifru_ifindex
        };

        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0u8; 8],
        };

        Ok(Self { sock, sockaddr })
    }

    /// Send raw L2 bytes on the interface.
    pub fn send(&self, packet: &[u8]) -> Result<usize, IoError> {
        let n = unsafe {
            // SAFETY: transmute sockaddr_ll to sockaddr — same size, packed correctly
            let addr: &libc::sockaddr = &*(&self.sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr);
            libc::sendto(
                self.sock.as_raw_fd(),
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                addr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(IoError::Socket(std::io::Error::last_os_error()));
        }
        Ok(n as usize)
    }
}

// Trait implementations
impl L2Reader for L2Receiver {
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

impl L2Writer for L2Sender {
    fn send(&self, packet: &[u8]) -> Result<usize, IoError> {
        self.send(packet)
    }
}

/// Copy interface name into an ifreq's ifr_name field.
#[cfg(target_os = "linux")]
fn copy_ifname(ifr: &mut libc::ifreq, name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(ifr.ifr_name.len() - 1);
    // SAFETY: ifr_name is [i8]; the interface name is ASCII, so reinterpret as i8 is safe.
    let name_i8 = unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const i8, len) };
    ifr.ifr_name[..len].copy_from_slice(name_i8);
}
