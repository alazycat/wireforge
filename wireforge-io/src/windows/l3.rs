//! Windows raw socket L3 I/O (IPv4).

use std::net::SocketAddrV4;
use std::os::raw::c_int;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::types::IpProtocol;

use crate::error::IoError;
use crate::traits::{L3Reader, L3Writer};

// Windows socket constants
const SOL_SOCKET: i32 = 0xFFFF;
const SO_RCVTIMEO: i32 = 0x1006;
const IPPROTO_IP: i32 = 0;
const IP_HDRINCL: i32 = 2;

extern "system" {
    fn setsockopt(
        s: usize,
        level: i32,
        optname: i32,
        optval: *const u8,
        optlen: i32,
    ) -> i32;
}

/// Windows raw socket L3 receiver.
pub struct WinL3Receiver {
    sock: Socket,
}

impl WinL3Receiver {
    pub fn new(protocol: IpProtocol) -> Result<Self, IoError> {
        let proto = i32::from(u8::from(protocol));
        let sock = Socket::new(Domain::IPV4, Type::from(3i32), Some(Protocol::from(proto)))?; // SOCK_RAW = 3
        Ok(Self { sock })
    }

    /// Receive a single IPv4 packet and parse it.
    pub fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> {
        let mut buf = [MaybeUninit::uninit(); 65536];
        let n = self.sock.recv(&mut buf)?;
        // SAFETY: the first n bytes are initialized by recv
        let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        Ipv4Packet::new(data).ok_or(IoError::Parse("invalid IPv4 packet"))
    }

    /// Enable or disable IP_HDRINCL (header included in send).
    pub fn set_header_included(&mut self, on: bool) -> Result<(), IoError> {
        use std::os::windows::io::AsRawSocket;
        let fd = self.sock.as_raw_socket() as usize;
        let val: c_int = if on { 1 } else { 0 };
        unsafe {
            let ret = setsockopt(
                fd,
                IPPROTO_IP,
                IP_HDRINCL,
                &val as *const _ as *const u8,
                std::mem::size_of::<c_int>() as i32,
            );
            if ret != 0 {
                return Err(IoError::Socket(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    /// Set receive timeout (DWORD milliseconds on Windows).
    pub fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        use std::os::windows::io::AsRawSocket;
        let fd = self.sock.as_raw_socket() as usize;
        let timeout_ms: u32 = dur.map(|d| d.as_millis() as u32).unwrap_or(0);
        unsafe {
            let ret = setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &timeout_ms as *const _ as *const u8,
                std::mem::size_of::<u32>() as i32,
            );
            if ret != 0 {
                return Err(IoError::Socket(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}

// Trait impl delegates to inherent methods
impl L3Reader for WinL3Receiver {
    fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> { self.recv() }
    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> { self.set_timeout(dur) }
    fn set_header_included(&mut self, on: bool) -> Result<(), IoError> { self.set_header_included(on) }
}

/// Windows raw socket L3 sender.
pub struct WinL3Sender {
    sock: Socket,
}

impl WinL3Sender {
    pub fn new() -> Result<Self, IoError> {
        let sock = Socket::new(Domain::IPV4, Type::from(3i32), Some(Protocol::from(255)))?; // SOCK_RAW = 3
        Ok(Self { sock })
    }

    /// Send an IPv4 packet to the given destination.
    pub fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError> {
        let addr = socket2::SockAddr::from(std::net::SocketAddr::V4(dst));
        let n = self.sock.send_to(packet, &addr)?;
        Ok(n)
    }
}

impl L3Writer for WinL3Sender {
    fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError> { self.send_to(packet, dst) }
}
