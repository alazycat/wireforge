//! L3 I/O — IPv4 raw socket and IPv6 AF_PACKET receive / raw send.

use std::net::{SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::ipv6::Ipv6Packet;
use wireforge_core::types::IpProtocol;

use crate::common;
use crate::error::IoError;
use crate::traits::{L3Reader, L3ReaderV6, L3Writer, L3WriterV6};

/// Receiver for raw IPv4 packets via SOCK_RAW socket.
pub struct L3Receiver {
    sock: Socket,
    buf: Vec<u8>,
}

impl L3Receiver {
    /// Open a SOCK_RAW socket for the given IP protocol.
    pub fn new(protocol: IpProtocol) -> Result<Self, IoError> {
        let proto = Protocol::from(u8::from(protocol) as i32);
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(proto))?;
        Ok(Self {
            sock,
            buf: vec![0u8; 65536],
        })
    }

    /// Receive a single IPv4 packet and parse it.
    pub fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> {
        let n = unsafe {
            libc::recv(
                self.sock.as_raw_fd(),
                self.buf.as_mut_ptr() as *mut libc::c_void,
                self.buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(common::recv_error(std::io::Error::last_os_error()));
        }
        let n = n as usize;
        Ipv4Packet::new(&self.buf[..n]).ok_or(IoError::Parse("invalid IPv4 packet"))
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
        common::set_socket_timeout(self.sock.as_raw_fd(), dur)
    }
}

/// Sender for raw IPv4 packets via SOCK_RAW socket.
pub struct L3Sender {
    sock: Socket,
}

impl L3Sender {
    /// Open a SOCK_RAW socket for sending IPv4 packets.
    pub fn new() -> Result<Self, IoError> {
        let sock = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(libc::IPPROTO_RAW)),
        )?;
        Ok(Self { sock })
    }

    /// Send an IPv4 packet to the given destination.
    pub fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError> {
        let addr = socket2::SockAddr::from(std::net::SocketAddr::V4(dst));
        let n = self.sock.send_to(packet, &addr)?;
        Ok(n)
    }
}

// Trait implementations
impl L3Reader for L3Receiver {
    fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> {
        self.recv()
    }

    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        self.set_timeout(dur)
    }

    fn set_header_included(&mut self, on: bool) -> Result<(), IoError> {
        self.set_header_included(on)
    }
}

impl L3Writer for L3Sender {
    fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError> {
        self.send_to(packet, dst)
    }
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/// Receiver for IPv6 packets via an AF_PACKET "cooked" (`SOCK_DGRAM`) socket.
///
/// Cooked AF_PACKET sockets deliver the network-layer packet including the
/// IPv6 header. Packets whose final upper-layer protocol does not match the
/// protocol passed to [`new`](Self::new) are skipped.
pub struct L3ReceiverV6 {
    sock: Socket,
    buf: Vec<u8>,
    protocol: IpProtocol,
}

impl L3ReceiverV6 {
    /// Open an AF_PACKET cooked socket and filter for the given IP protocol.
    pub fn new(protocol: IpProtocol) -> Result<Self, IoError> {
        let sock = Socket::new(
            Domain::PACKET,
            Type::DGRAM,
            Some(Protocol::from(eth_p_ipv6_protocol())),
        )?;
        Ok(Self {
            sock,
            buf: vec![0u8; 65536],
            protocol,
        })
    }

    /// Receive the next IPv6 packet whose final protocol matches.
    pub fn recv(&mut self) -> Result<Ipv6Packet<'_>, IoError> {
        let n = self.read_matching()?;
        Ipv6Packet::new(&self.buf[..n]).ok_or(IoError::Parse("invalid IPv6 packet"))
    }

    /// Fill `self.buf` with the next matching packet and return its length.
    ///
    /// Keeping the parsed packet local to each loop iteration lets the borrow
    /// end before `recv` is called again.
    fn read_matching(&mut self) -> Result<usize, IoError> {
        loop {
            let n = unsafe {
                libc::recv(
                    self.sock.as_raw_fd(),
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(common::recv_error(std::io::Error::last_os_error()));
            }
            let n = n as usize;
            let Some(packet) = Ipv6Packet::new(&self.buf[..n]) else {
                return Err(IoError::Parse("invalid IPv6 packet"));
            };
            if packet.final_protocol() == self.protocol {
                return Ok(n);
            }
        }
    }

    /// No-op: cooked AF_PACKET sockets always deliver the IPv6 header.
    pub fn set_header_included(&mut self, _on: bool) -> Result<(), IoError> {
        Ok(())
    }

    /// Set receive timeout.
    pub fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        common::set_socket_timeout(self.sock.as_raw_fd(), dur)
    }
}

/// AF_PACKET protocol value for IPv6 in network byte order.
fn eth_p_ipv6_protocol() -> i32 {
    (libc::ETH_P_IPV6 as u16).to_be() as i32
}

/// Sender for raw IPv6 packets via SOCK_RAW socket.
pub struct L3SenderV6 {
    sock: Socket,
}

impl L3SenderV6 {
    /// Open an IPv6 SOCK_RAW socket for sending IPv6 packets.
    pub fn new() -> Result<Self, IoError> {
        let sock = Socket::new(
            Domain::IPV6,
            Type::RAW,
            Some(Protocol::from(libc::IPPROTO_RAW)),
        )?;
        Ok(Self { sock })
    }

    /// Send an IPv6 packet to the given destination.
    pub fn send_to(&self, packet: &[u8], dst: SocketAddrV6) -> Result<usize, IoError> {
        let addr = socket2::SockAddr::from(std::net::SocketAddr::V6(dst));
        let n = self.sock.send_to(packet, &addr)?;
        Ok(n)
    }
}

impl L3ReaderV6 for L3ReceiverV6 {
    fn recv(&mut self) -> Result<Ipv6Packet<'_>, IoError> {
        self.recv()
    }

    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        self.set_timeout(dur)
    }

    fn set_header_included(&mut self, on: bool) -> Result<(), IoError> {
        self.set_header_included(on)
    }
}

impl L3WriterV6 for L3SenderV6 {
    fn send_to(&self, packet: &[u8], dst: SocketAddrV6) -> Result<usize, IoError> {
        self.send_to(packet, dst)
    }
}
