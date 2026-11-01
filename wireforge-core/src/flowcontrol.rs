//! Ethernet flow control frame parser and builder (IEEE 802.3x PAUSE,
//! IEEE 802.1Qbb PFC).
//!
//! MAC control frames are Ethernet frames using EtherType `0x8808`
//! ([`FLOWCONTROL_ETHERTYPE`]). The bytes parsed here start immediately
//! after the Ethernet header, i.e. at the MAC control opcode.
//!
//! Two frame kinds are covered:
//!
//! - **PAUSE (802.3x)** — asks the link partner to stop transmitting for
//!   `pause_time` 512-bit-time quanta. Opcode `0x0001`.
//! - **PFC (802.1Qbb, priority-based flow control)** — per-priority pause
//!   with a priority enable vector and eight per-class pause times.
//!   Opcode `0x0101`.
//!
//! # Examples
//!
//! ```
//! use wireforge_core::flowcontrol::{PausePacket, PausePacketBuilder, PAUSE_OPCODE};
//! use wireforge_core::types::EtherType;
//! use wireforge_core::util::PacketBuilder;
//!
//! let ctrl = PausePacketBuilder::new().pause_time(0x0100).build();
//!
//! let pause = PausePacket::new(&ctrl).unwrap();
//! assert_eq!(pause.opcode(), PAUSE_OPCODE);
//! assert_eq!(pause.pause_time(), 0x0100);
//! assert_eq!(u16::from(EtherType::MacControl), 0x8808);
//! ```

use alloc::vec::Vec;

use crate::util::{read_u16be, write_u16be, PacketBuilder};

/// EtherType used by Ethernet MAC control frames (802.3x flow control).
pub const FLOWCONTROL_ETHERTYPE: u16 = 0x8808;

/// MAC control opcode for a PAUSE request (IEEE 802.3x).
pub const PAUSE_OPCODE: u16 = 0x0001;

/// MAC control opcode for priority-based flow control (IEEE 802.1Qbb).
pub const PFC_OPCODE: u16 = 0x0101;

/// Length of the PAUSE control header (opcode + pause time).
pub const PAUSE_HEADER_LEN: usize = 4;

/// Length of the PFC control header (opcode + enable vector + 8 pause times).
pub const PFC_HEADER_LEN: usize = 19;

/// Number of priority classes covered by a PFC frame.
pub const PFC_PRIORITY_CLASSES: usize = 8;

/// Zero-copy PAUSE frame (IEEE 802.3x) parser.
///
/// Holds a reference to the bytes starting at the MAC control opcode —
/// the payload of an Ethernet frame with EtherType `0x8808`.
#[derive(Debug, Clone)]
pub struct PausePacket<'a> {
    buf: &'a [u8],
}

impl<'a> PausePacket<'a> {
    crate::parser_new!(PAUSE_HEADER_LEN);

    /// Header bytes (opcode + pause time), without payload.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        &self.buf[..PAUSE_HEADER_LEN]
    }

    /// The MAC control opcode (e.g. [`PAUSE_OPCODE`]).
    #[inline]
    pub fn opcode(&self) -> u16 {
        read_u16be(&self.buf[0..2])
    }

    /// The pause time in 512-bit-time quanta.
    #[inline]
    pub fn pause_time(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }

    /// Padding / trailing bytes after the control header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[PAUSE_HEADER_LEN..]
    }
}

/// Builder for PAUSE (IEEE 802.3x) control frames.
#[derive(Debug, Clone)]
pub struct PausePacketBuilder {
    buf: [u8; PAUSE_HEADER_LEN],
    payload: Option<Vec<u8>>,
}

impl PausePacketBuilder {
    /// Create a builder with the PAUSE opcode set.
    pub fn new() -> Self {
        let mut buf = [0u8; PAUSE_HEADER_LEN];
        write_u16be(&mut buf[0..2], PAUSE_OPCODE);
        Self { buf, payload: None }
    }

    /// Override the MAC control opcode.
    pub fn opcode(mut self, opcode: u16) -> Self {
        write_u16be(&mut self.buf[0..2], opcode);
        self
    }

    /// Set the pause time in 512-bit-time quanta.
    pub fn pause_time(mut self, quanta: u16) -> Self {
        write_u16be(&mut self.buf[2..4], quanta);
        self
    }

    /// Set padding / trailing bytes.
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }
}

impl Default for PausePacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuilder for PausePacketBuilder {
    type Output = Vec<u8>;

    fn build(self) -> Vec<u8> {
        let mut packet =
            Vec::with_capacity(PAUSE_HEADER_LEN + self.payload.as_ref().map_or(0, |p| p.len()));
        packet.extend_from_slice(&self.buf);
        if let Some(p) = self.payload {
            packet.extend_from_slice(&p);
        }
        packet
    }
}

/// Zero-copy PFC frame (IEEE 802.1Qbb) parser.
///
/// Holds a reference to the bytes starting at the MAC control opcode.
#[derive(Debug, Clone)]
pub struct PfcPacket<'a> {
    buf: &'a [u8],
}

impl<'a> PfcPacket<'a> {
    crate::parser_new!(PFC_HEADER_LEN);

    /// Header bytes (opcode + enable vector + pause times), without payload.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        &self.buf[..PFC_HEADER_LEN]
    }

    /// The MAC control opcode (e.g. [`PFC_OPCODE`]).
    #[inline]
    pub fn opcode(&self) -> u16 {
        read_u16be(&self.buf[0..2])
    }

    /// The priority enable vector — bit `n` set means priority class `n`
    /// may be paused.
    #[inline]
    pub fn priority_enable_vector(&self) -> u8 {
        self.buf[2]
    }

    /// The pause time of the given priority class (0-7), in quanta.
    /// Returns `None` for priorities outside 0-7.
    #[inline]
    pub fn pause_time(&self, priority: usize) -> Option<u16> {
        if priority >= PFC_PRIORITY_CLASSES {
            return None;
        }
        let off = 3 + priority * 2;
        Some(read_u16be(&self.buf[off..off + 2]))
    }

    /// All eight per-priority pause times, indexed by priority class.
    #[inline]
    pub fn pause_times(&self) -> [u16; PFC_PRIORITY_CLASSES] {
        let mut times = [0u16; PFC_PRIORITY_CLASSES];
        for (i, t) in times.iter_mut().enumerate() {
            *t = self.pause_time(i).unwrap_or(0);
        }
        times
    }

    /// Padding / trailing bytes after the control header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[PFC_HEADER_LEN..]
    }
}

/// Builder for PFC (IEEE 802.1Qbb) control frames.
#[derive(Debug, Clone)]
pub struct PfcPacketBuilder {
    buf: [u8; PFC_HEADER_LEN],
    payload: Option<Vec<u8>>,
}

impl PfcPacketBuilder {
    /// Create a builder with the PFC opcode set and all pause times zero.
    pub fn new() -> Self {
        let mut buf = [0u8; PFC_HEADER_LEN];
        write_u16be(&mut buf[0..2], PFC_OPCODE);
        Self { buf, payload: None }
    }

    /// Override the MAC control opcode.
    pub fn opcode(mut self, opcode: u16) -> Self {
        write_u16be(&mut self.buf[0..2], opcode);
        self
    }

    /// Set the priority enable vector.
    pub fn priority_enable_vector(mut self, vector: u8) -> Self {
        self.buf[2] = vector;
        self
    }

    /// Set the pause time for one priority class (0-7).
    pub fn pause_time(mut self, priority: usize, quanta: u16) -> Result<Self, crate::BuildError> {
        if priority >= PFC_PRIORITY_CLASSES {
            return Err(crate::BuildError::InvalidField {
                field: "priority",
                reason: "PFC has 8 priority classes (0-7)",
            });
        }
        let off = 3 + priority * 2;
        write_u16be(&mut self.buf[off..off + 2], quanta);
        Ok(self)
    }

    /// Set padding / trailing bytes.
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }
}

impl Default for PfcPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuilder for PfcPacketBuilder {
    type Output = Vec<u8>;

    fn build(self) -> Vec<u8> {
        let mut packet =
            Vec::with_capacity(PFC_HEADER_LEN + self.payload.as_ref().map_or(0, |p| p.len()));
        packet.extend_from_slice(&self.buf);
        if let Some(p) = self.payload {
            packet.extend_from_slice(&p);
        }
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known PAUSE sample: opcode 0x0001, pause time 0x0100 (256 quanta).
    #[test]
    fn parse_pause_known_sample() {
        let data = [0x00, 0x01, 0x01, 0x00, 0x00, 0x00];
        let pause = PausePacket::new(&data).unwrap();
        assert_eq!(pause.opcode(), PAUSE_OPCODE);
        assert_eq!(pause.pause_time(), 0x0100);
        assert_eq!(pause.payload(), &[0x00, 0x00]);
        assert_eq!(pause.as_bytes(), &data[..PAUSE_HEADER_LEN]);
    }

    #[test]
    fn pause_too_short() {
        assert!(PausePacket::new(&[]).is_none());
        assert!(PausePacket::new(&[0u8; 3]).is_none());
    }

    #[test]
    fn pause_builder_roundtrip() {
        let frame = PausePacketBuilder::new().pause_time(0xFFFF).payload(&[0xAA; 4]).build();
        assert_eq!(frame.len(), PAUSE_HEADER_LEN + 4);
        let pause = PausePacket::new(&frame).unwrap();
        assert_eq!(pause.opcode(), PAUSE_OPCODE);
        assert_eq!(pause.pause_time(), 0xFFFF);
        assert_eq!(pause.payload(), &[0xAA; 4]);
    }

    #[test]
    fn pause_builder_custom_opcode() {
        let frame = PausePacketBuilder::new().opcode(0x0002).build();
        assert_eq!(PausePacket::new(&frame).unwrap().opcode(), 0x0002);
    }

    /// Known PFC sample: opcode 0x0101, classes 0 and 5 enabled,
    /// pause time 0x0101 for class 5.
    #[test]
    fn parse_pfc_known_sample() {
        let mut data = [0u8; PFC_HEADER_LEN];
        data[0] = 0x01;
        data[1] = 0x01;
        data[2] = 0b0010_0001; // classes 0 and 5 enabled
        data[3 + 10] = 0x01;
        data[4 + 10] = 0x01; // class 5 pause time = 0x0101

        let pfc = PfcPacket::new(&data).unwrap();
        assert_eq!(pfc.opcode(), PFC_OPCODE);
        assert_eq!(pfc.priority_enable_vector(), 0b0010_0001);
        assert_eq!(pfc.pause_time(0), Some(0));
        assert_eq!(pfc.pause_time(5), Some(0x0101));
        assert_eq!(pfc.pause_time(7), Some(0));
        assert!(pfc.pause_time(8).is_none());
        assert!(pfc.payload().is_empty());
    }

    #[test]
    fn pfc_too_short() {
        assert!(PfcPacket::new(&[]).is_none());
        assert!(PfcPacket::new(&[0u8; PFC_HEADER_LEN - 1]).is_none());
    }

    #[test]
    fn pfc_builder_roundtrip() {
        let frame = PfcPacketBuilder::new()
            .priority_enable_vector(0xFF)
            .pause_time(0, 0x1111)
            .unwrap()
            .pause_time(7, 0x7777)
            .unwrap()
            .payload(&[0x42])
            .build();

        assert_eq!(frame.len(), PFC_HEADER_LEN + 1);
        let pfc = PfcPacket::new(&frame).unwrap();
        assert_eq!(pfc.opcode(), PFC_OPCODE);
        assert_eq!(pfc.priority_enable_vector(), 0xFF);
        assert_eq!(pfc.pause_times(), [0x1111, 0, 0, 0, 0, 0, 0, 0x7777]);
        assert_eq!(pfc.payload(), &[0x42]);
    }

    #[test]
    fn pfc_builder_rejects_invalid_priority() {
        assert!(PfcPacketBuilder::new().pause_time(8, 1).is_err());
        assert!(PfcPacketBuilder::new().pause_time(usize::MAX, 1).is_err());
    }

    #[test]
    fn debug_format() {
        let frame = PausePacketBuilder::new().build();
        let pause = PausePacket::new(&frame).unwrap();
        assert!(alloc::format!("{:?}", pause).contains("PausePacket"));

        let frame = PfcPacketBuilder::new().build();
        let pfc = PfcPacket::new(&frame).unwrap();
        assert!(alloc::format!("{:?}", pfc).contains("PfcPacket"));
    }
}
