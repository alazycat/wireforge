//! macOS BPF (Berkeley Packet Filter) L2 capture and injection.
//! Implements `L2Reader` and `L2Writer` traits via /dev/bpf devices.

use std::time::Duration;
use wireforge_core::ether::EthernetPacket;
use crate::error::IoError;
use crate::traits::{L2Reader, L2Writer};

/// BPF-based L2 frame reader.
pub struct BpfReader {
    // populated in Issue #29
    _private: (),
}

impl BpfReader {
    pub fn new(_ifname: &str) -> Result<Self, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

impl L2Reader for BpfReader {
    fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> { Err(IoError::UnsupportedPlatform) }
    fn set_timeout(&mut self, _dur: Option<Duration>) -> Result<(), IoError> { Err(IoError::UnsupportedPlatform) }
    fn set_promiscuous(&mut self, _on: bool) -> Result<(), IoError> { Err(IoError::UnsupportedPlatform) }
}

/// BPF-based L2 frame writer.
pub struct BpfWriter;

impl BpfWriter {
    pub fn new(_ifname: &str) -> Result<Self, IoError> {
        Err(IoError::UnsupportedPlatform)
    }
}

impl L2Writer for BpfWriter {
    fn send(&self, _packet: &[u8]) -> Result<usize, IoError> { Err(IoError::UnsupportedPlatform) }
}
