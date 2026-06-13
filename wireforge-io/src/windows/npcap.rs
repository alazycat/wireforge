//! Windows NPcap L2 capture and injection. Stub — full implementation in Issue #31.
//! Requires feature flag `npcap`.

use std::time::Duration;
use wireforge_core::ether::EthernetPacket;
use crate::error::IoError;
use crate::traits::{L2Reader, L2Writer};

pub struct NpcapReader;
pub struct NpcapWriter;

impl NpcapReader {
    pub fn new(_ifname: &str) -> Result<Self, IoError> { Err(IoError::UnsupportedPlatform) }
}

impl L2Reader for NpcapReader {
    fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> { Err(IoError::UnsupportedPlatform) }
    fn set_timeout(&mut self, _dur: Option<Duration>) -> Result<(), IoError> { Err(IoError::UnsupportedPlatform) }
    fn set_promiscuous(&mut self, _on: bool) -> Result<(), IoError> { Err(IoError::UnsupportedPlatform) }
}

impl NpcapWriter {
    pub fn new(_ifname: &str) -> Result<Self, IoError> { Err(IoError::UnsupportedPlatform) }
}

impl L2Writer for NpcapWriter {
    fn send(&self, _packet: &[u8]) -> Result<usize, IoError> { Err(IoError::UnsupportedPlatform) }
}
