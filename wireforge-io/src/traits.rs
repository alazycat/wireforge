//! Platform-independent I/O traits for L2/L3 packet capture and injection.
//!
//! Each platform provides its own implementation of these traits:
//! - Linux: `L2Receiver`/`L2Sender` (AF_PACKET), `L3Receiver`/`L3Sender` (raw socket)
//! - macOS: `BpfReader`/`BpfWriter` (BPF), `BsdL3Receiver`/`BsdL3Sender` (raw socket)
//! - Windows: `NpcapReader`/`NpcapWriter` (NPcap), `WinL3Receiver`/`WinL3Sender` (raw socket)

use std::net::SocketAddrV4;
use std::time::Duration;

use wireforge_core::ether::EthernetPacket;
use wireforge_core::ipv4::Ipv4Packet;

use crate::error::IoError;

/// Receiver for raw L2 Ethernet frames.
///
/// Implementations internally manage a receive buffer (typically 64 KB)
/// and return zero-copy parsed `EthernetPacket` references.
pub trait L2Reader {
    /// Receive a single Ethernet frame and parse it.
    fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError>;

    /// Set the receive timeout. `None` means blocking (no timeout).
    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError>;

    /// Enable or disable promiscuous mode.
    fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError>;
}

/// Sender for raw L2 Ethernet frames.
pub trait L2Writer {
    /// Send raw bytes as an Ethernet frame. Returns the number of bytes sent.
    fn send(&self, packet: &[u8]) -> Result<usize, IoError>;
}

/// Receiver for raw L3 IPv4 packets.
pub trait L3Reader {
    /// Receive a single IPv4 packet and parse it.
    fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError>;

    /// Set the receive timeout. `None` means blocking (no timeout).
    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError>;

    /// Enable or disable IP_HDRINCL (header included in send).
    fn set_header_included(&mut self, on: bool) -> Result<(), IoError>;
}

/// Sender for raw L3 IPv4 packets.
pub trait L3Writer {
    /// Send an IPv4 packet to the given destination.
    fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError>;
}
