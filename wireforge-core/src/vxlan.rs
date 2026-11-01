//! VXLAN (RFC 7348) overlay tunnel header parser and builder.
//!
//! VXLAN encapsulates Ethernet frames inside UDP datagrams (typically on
//! port 4789). The 8-byte VXLAN header carries the 24-bit VXLAN Network
//! Identifier (VNI) used to separate overlay segments.
//!
//! # Header layout (RFC 7348 §4)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |R|R|R|R|I|R|R|R|            Reserved                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  VXLAN Network Identifier (VNI)               |  Reserved |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Examples
//!
//! ```
//! use wireforge_core::util::PacketBuilder;
//! use wireforge_core::vxlan::{VxlanPacket, VxlanPacketBuilder};
//!
//! // An inner Ethernet frame (abbreviated).
//! let inner = [0x01u8; 14];
//! let packet = VxlanPacketBuilder::new(0x1234).payload(&inner).build();
//!
//! let vxlan = VxlanPacket::new(&packet).unwrap();
//! assert!(vxlan.vni_present());
//! assert_eq!(vxlan.vni(), 0x1234);
//! assert_eq!(vxlan.payload(), &inner);
//! ```

use alloc::vec::Vec;

use crate::util::PacketBuilder;

/// Length of the VXLAN header in bytes.
pub const VXLAN_HEADER_LEN: usize = 8;

/// The IANA-assigned UDP destination port for VXLAN (RFC 7348).
pub const VXLAN_UDP_PORT: u16 = 4789;

/// Flags byte bit indicating that the VNI is valid (`I` bit).
pub const VXLAN_FLAG_VNI_PRESENT: u8 = 0x08;

/// Zero-copy VXLAN header parser.
///
/// Holds a reference to the underlying byte slice starting at the VXLAN
/// header. The payload is the encapsulated inner Ethernet frame.
#[derive(Debug, Clone)]
pub struct VxlanPacket<'a> {
    buf: &'a [u8],
}

impl<'a> VxlanPacket<'a> {
    crate::parser_new!(VXLAN_HEADER_LEN);

    /// Raw bytes backing this VXLAN header (header only, without payload).
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        &self.buf[..VXLAN_HEADER_LEN]
    }

    /// The flags byte.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.buf[0]
    }

    /// Whether the `I` flag is set, i.e. the VNI is valid.
    #[inline]
    pub fn vni_present(&self) -> bool {
        self.buf[0] & VXLAN_FLAG_VNI_PRESENT != 0
    }

    /// The 24-bit VXLAN Network Identifier.
    #[inline]
    pub fn vni(&self) -> u32 {
        (self.buf[4] as u32) << 16 | (self.buf[5] as u32) << 8 | self.buf[6] as u32
    }

    /// Reserved bytes 1-3 following the flags byte.
    #[inline]
    pub fn reserved1(&self) -> &'a [u8] {
        &self.buf[1..4]
    }

    /// The reserved trailing byte after the VNI.
    #[inline]
    pub fn reserved2(&self) -> u8 {
        self.buf[7]
    }

    /// The encapsulated inner Ethernet frame.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[VXLAN_HEADER_LEN..]
    }
}

/// Builder for VXLAN headers (RFC 7348).
///
/// Produces an 8-byte VXLAN header followed by the inner frame payload.
/// VNI values are truncated to 24 bits.
#[derive(Debug, Clone)]
pub struct VxlanPacketBuilder {
    buf: [u8; VXLAN_HEADER_LEN],
    payload: Option<Vec<u8>>,
}

impl VxlanPacketBuilder {
    /// Create a builder with the `I` flag set and the given VNI.
    pub fn new(vni: u32) -> Self {
        Self {
            buf: [VXLAN_FLAG_VNI_PRESENT, 0, 0, 0, 0, 0, 0, 0],
            payload: None,
        }
        .vni(vni)
    }

    /// Override the raw flags byte.
    pub fn flags(mut self, flags: u8) -> Self {
        self.buf[0] = flags;
        self
    }

    /// Set the 24-bit VXLAN Network Identifier (values are truncated to 24 bits).
    pub fn vni(mut self, vni: u32) -> Self {
        let vni = vni & 0x00FF_FFFF;
        self.buf[4] = (vni >> 16) as u8;
        self.buf[5] = (vni >> 8) as u8;
        self.buf[6] = vni as u8;
        self
    }

    /// Set the encapsulated inner Ethernet frame.
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }
}

impl PacketBuilder for VxlanPacketBuilder {
    type Output = Vec<u8>;

    fn build(self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(VXLAN_HEADER_LEN + self.payload.as_ref().map_or(0, |p| p.len()));
        packet.extend_from_slice(&self.buf);
        if let Some(p) = self.payload {
            packet.extend_from_slice(&p);
        }
        packet
    }
}

crate::impl_mutable_packet!(MutableVxlanPacket, VXLAN_HEADER_LEN);

impl<'a> MutableVxlanPacket<'a> {
    fn view(&self) -> VxlanPacket<'_> {
        VxlanPacket::new(&*self.buf).expect("validated in MutableVxlanPacket::new")
    }

    fn payload_offset(&self) -> usize {
        VXLAN_HEADER_LEN
    }

    /// The flags byte.
    pub fn flags(&self) -> u8 {
        self.buf[0]
    }

    /// Set the flags byte.
    pub fn set_flags(&mut self, flags: u8) {
        self.buf[0] = flags;
    }

    /// Whether the `I` flag is set.
    pub fn vni_present(&self) -> bool {
        self.view().vni_present()
    }

    /// The 24-bit VXLAN Network Identifier.
    pub fn vni(&self) -> u32 {
        self.view().vni()
    }

    /// Set the 24-bit VXLAN Network Identifier (values are truncated to 24 bits).
    pub fn set_vni(&mut self, vni: u32) {
        let vni = vni & 0x00FF_FFFF;
        self.buf[4] = (vni >> 16) as u8;
        self.buf[5] = (vni >> 8) as u8;
        self.buf[6] = vni as u8;
    }

    /// The reserved trailing byte after the VNI.
    pub fn reserved2(&self) -> u8 {
        self.buf[7]
    }

    /// Set the reserved trailing byte after the VNI.
    pub fn set_reserved2(&mut self, value: u8) {
        self.buf[7] = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known VXLAN sample: I flag set, VNI = 0x123456, inner frame follows.
    #[test]
    fn parse_known_sample() {
        let data = [
            0x08, 0x00, 0x00, 0x00, // flags=I, reserved
            0x12, 0x34, 0x56, // VNI = 0x123456
            0x00, // reserved
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // inner frame starts (dst mac)
        ];
        let vxlan = VxlanPacket::new(&data).unwrap();
        assert!(vxlan.vni_present());
        assert_eq!(vxlan.flags(), 0x08);
        assert_eq!(vxlan.vni(), 0x123456);
        assert_eq!(vxlan.reserved1(), &[0, 0, 0]);
        assert_eq!(vxlan.reserved2(), 0);
        assert_eq!(vxlan.payload(), &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(vxlan.as_bytes(), &data[..VXLAN_HEADER_LEN]);
    }

    #[test]
    fn vni_flag_not_set() {
        let data = [
            0x00, 0x00, 0x00, 0x00, // flags: no I bit
            0xAB, 0xCD, 0xEF, 0x00,
        ];
        let vxlan = VxlanPacket::new(&data).unwrap();
        assert!(!vxlan.vni_present());
        // VNI bytes are still readable even when the I flag is clear.
        assert_eq!(vxlan.vni(), 0xABCDEF);
    }

    #[test]
    fn too_short() {
        assert!(VxlanPacket::new(&[]).is_none());
        assert!(VxlanPacket::new(&[0u8; 7]).is_none());
    }

    #[test]
    fn empty_payload() {
        let data = [0x08, 0, 0, 0, 0, 0, 1, 0];
        let vxlan = VxlanPacket::new(&data).unwrap();
        assert_eq!(vxlan.vni(), 1);
        assert!(vxlan.payload().is_empty());
    }

    #[test]
    fn builder_roundtrip() {
        let inner = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33];
        let packet = VxlanPacketBuilder::new(0xABCDEF).payload(&inner).build();

        assert_eq!(packet.len(), VXLAN_HEADER_LEN + inner.len());
        let vxlan = VxlanPacket::new(&packet).unwrap();
        assert!(vxlan.vni_present());
        assert_eq!(vxlan.vni(), 0xABCDEF);
        assert_eq!(vxlan.reserved1(), &[0, 0, 0]);
        assert_eq!(vxlan.reserved2(), 0);
        assert_eq!(vxlan.payload(), &inner);
    }

    #[test]
    fn builder_no_payload() {
        let packet = VxlanPacketBuilder::new(0).build();
        assert_eq!(packet.len(), VXLAN_HEADER_LEN);
        let vxlan = VxlanPacket::new(&packet).unwrap();
        assert_eq!(vxlan.vni(), 0);
    }

    #[test]
    fn builder_truncates_vni_to_24_bits() {
        let packet = VxlanPacketBuilder::new(0x1_234_567).build();
        let vxlan = VxlanPacket::new(&packet).unwrap();
        assert_eq!(vxlan.vni(), 0x234567);
    }

    #[test]
    fn builder_custom_flags() {
        // Clear the I flag explicitly.
        let packet = VxlanPacketBuilder::new(7).flags(0x00).build();
        let vxlan = VxlanPacket::new(&packet).unwrap();
        assert!(!vxlan.vni_present());
        assert_eq!(vxlan.flags(), 0x00);
    }

    #[test]
    fn mutable_vxlan_accessors() {
        let mut packet = VxlanPacketBuilder::new(0x010203).build();
        let mut mutable = MutableVxlanPacket::new(&mut packet).unwrap();

        assert_eq!(mutable.vni(), 0x010203);
        assert!(mutable.vni_present());

        mutable.set_vni(0x456789);
        mutable.set_flags(0x00);
        mutable.set_reserved2(0x77);
        assert_eq!(mutable.vni(), 0x456789);
        assert!(!mutable.vni_present());
        assert_eq!(mutable.reserved2(), 0x77);
        drop(mutable);

        let reparsed = VxlanPacket::new(&packet).unwrap();
        assert_eq!(reparsed.vni(), 0x456789);
        assert_eq!(reparsed.reserved2(), 0x77);
    }

    #[test]
    fn debug_format() {
        let packet = VxlanPacketBuilder::new(1).build();
        let vxlan = VxlanPacket::new(&packet).unwrap();
        assert!(alloc::format!("{:?}", vxlan).contains("VxlanPacket"));
    }
}
