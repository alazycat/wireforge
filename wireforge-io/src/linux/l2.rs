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
}

impl L2Receiver {
    /// Open an AF_PACKET socket and bind to the given interface.
    pub fn new(ifname: &str) -> Result<Self, IoError> {
        let sock = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::ETH_P_ALL))?;

        // Bind to interface using SO_BINDTODEVICE
        let ifname_bytes = ifname.as_bytes();
        sock.set_socket_option(
            &socket2::SockRef::from(&sock),
            socket2::maybe_os_specific!(libc::SO_BINDTODEVICE),
            ifname_bytes,
        )?;

        Ok(Self { sock })
    }

    /// Receive a single Ethernet frame and parse it.
    pub fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> {
        let mut buf = [0u8; 65536];
        let n = self.sock.recv(&mut buf)?;
        EthernetPacket::new(&buf[..n]).ok_or(IoError::Parse("invalid Ethernet frame"))
    }

    /// Enable or disable promiscuous mode.
    pub fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError> {
        let fd = self.sock.as_raw_fd();
        unsafe {
            let mut ifreq: libc::ifreq = std::mem::zeroed();
            // Set IFF_PROMISC via ioctl
            let mut flags = {
                let mut ifr_flags: libc::ifreq = std::mem::zeroed();
                libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr_flags);
                ifr_flags.ifr_ifru.ifru_flags
            };
            if on {
                flags |= (libc::IFF_PROMISC as i16) as i32;
            } else {
                flags &= !((libc::IFF_PROMISC as i16) as i32);
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
        let sock = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::ETH_P_ALL))?;

        let fd = sock.as_raw_fd();
        let ifindex = unsafe {
            let mut ifreq: libc::ifreq = std::mem::zeroed();
            let name_bytes = ifname.as_bytes();
            let copy_len = name_bytes.len().min(ifreq.ifr_name.len() - 1);
            ifreq.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
            libc::ioctl(fd, libc::SIOCGIFINDEX, &mut ifreq);
            ifreq.ifr_ifru.ifru_ivalue
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
        let addr = unsafe {
            let ptr: *const libc::sockaddr_ll = &self.sockaddr;
            std::mem::transmute::<&libc::sockaddr_ll, &libc::sockaddr>(&self.sockaddr)
        };
        let n = self.sock.send_to(packet, addr)?;
        Ok(n)
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
