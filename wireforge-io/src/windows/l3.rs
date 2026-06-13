//! Windows raw socket L3 I/O. Stub — full implementation in Issue #32.

use std::net::SocketAddrV4;
use std::time::Duration;
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::types::IpProtocol;
use crate::error::IoError;
use crate::traits::{L3Reader, L3Writer};

pub struct WinL3Receiver;
pub struct WinL3Sender;

impl WinL3Receiver {
    pub fn new(_protocol: IpProtocol) -> Result<Self, IoError> { Err(IoError::UnsupportedPlatform) }
}

impl L3Reader for WinL3Receiver {
    fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> { Err(IoError::UnsupportedPlatform) }
    fn set_timeout(&mut self, _dur: Option<Duration>) -> Result<(), IoError> { Err(IoError::UnsupportedPlatform) }
    fn set_header_included(&mut self, _on: bool) -> Result<(), IoError> { Err(IoError::UnsupportedPlatform) }
}

impl WinL3Sender {
    pub fn new() -> Result<Self, IoError> { Err(IoError::UnsupportedPlatform) }
}

impl L3Writer for WinL3Sender {
    fn send_to(&self, _packet: &[u8], _dst: SocketAddrV4) -> Result<usize, IoError> { Err(IoError::UnsupportedPlatform) }
}
