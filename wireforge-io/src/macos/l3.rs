//! macOS/BSD raw socket L3 I/O. Stubs — full implementation in Issue #30.

use crate::error::IoError;
use crate::traits::{L3Reader, L3ReaderV6, L3Writer, L3WriterV6};
use std::net::{SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::ipv6::Ipv6Packet;
use wireforge_core::types::IpProtocol;

pub struct BsdL3Receiver;
pub struct BsdL3Sender;

impl BsdL3Receiver {
    pub fn new(_protocol: IpProtocol) -> Result<Self, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

impl L3Reader for BsdL3Receiver {
    fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
    fn set_timeout(&mut self, _dur: Option<Duration>) -> Result<(), IoError> {
        Err(IoError::UnsupportedPlatform)
    }
    fn set_header_included(&mut self, _on: bool) -> Result<(), IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

impl BsdL3Sender {
    pub fn new() -> Result<Self, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

impl L3Writer for BsdL3Sender {
    fn send_to(&self, _packet: &[u8], _dst: SocketAddrV4) -> Result<usize, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

// ---------------------------------------------------------------------------
// IPv6 stubs
// ---------------------------------------------------------------------------

pub struct BsdL3ReceiverV6;
pub struct BsdL3SenderV6;

impl BsdL3ReceiverV6 {
    pub fn new(_protocol: IpProtocol) -> Result<Self, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
    pub fn recv(&mut self) -> Result<Ipv6Packet<'_>, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
    pub fn set_timeout(&mut self, _dur: Option<Duration>) -> Result<(), IoError> {
        Err(IoError::UnsupportedPlatform)
    }
    pub fn set_header_included(&mut self, _on: bool) -> Result<(), IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

impl L3ReaderV6 for BsdL3ReceiverV6 {
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

impl BsdL3SenderV6 {
    pub fn new() -> Result<Self, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
    pub fn send_to(&self, _packet: &[u8], _dst: SocketAddrV6) -> Result<usize, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

impl L3WriterV6 for BsdL3SenderV6 {
    fn send_to(&self, packet: &[u8], dst: SocketAddrV6) -> Result<usize, IoError> {
        self.send_to(packet, dst)
    }
}
