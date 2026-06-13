//! L3 (raw socket) I/O — IPv4 packet receive and send.

use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::types::IpProtocol;

use crate::error::IoError;

/// Receiver for raw IPv4 packets via SOCK_RAW socket.
pub struct L3Receiver {
    sock: Socket,
}

impl L3Receiver {
    /// Open a SOCK_RAW socket for the given IP protocol.
    pub fn new(protocol: IpProtocol) -> Result<Self, IoError> {
        let proto = Protocol::from(u8::from(protocol) as i32);
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(proto))?;
        Ok(Self { sock })
    }

    /// Receive a single IPv4 packet and parse it.
    pub fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> {
        let mut buf = [0u8; 65536];
        let n = self.sock.recv(&mut buf)?;
        Ipv4Packet::new(&buf[..n]).ok_or(IoError::Parse("invalid IPv4 packet"))
    }

    /// Enable or disable IP_HDRINCL (header included in send).
    pub fn set_header_included(&mut self, on: bool) -> Result<(), IoError> {
        let fd = self.sock.as_raw_fd();
        let val: libc::c_int = if on { 1 } else { 0 };
        unsafe {
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) < 0
            {
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

/// Sender for raw IPv4 packets via SOCK_RAW socket.
pub struct L3Sender {
    sock: Socket,
}

impl L3Sender {
    /// Open a SOCK_RAW socket for sending IPv4 packets.
    pub fn new() -> Result<Self, IoError> {
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(libc::IPPROTO_RAW as i32)))?;
        Ok(Self { sock })
    }

    /// Send an IPv4 packet to the given destination.
    pub fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError> {
        let addr = socket2::SockAddr::from(std::net::SocketAddr::V4(dst));
        let n = self.sock.send_to(packet, &addr)?;
        Ok(n)
    }
}
