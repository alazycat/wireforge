//! Linux cooked capture v2 (SLL2) link-layer parser and builder.
//!
//! SLL2 (`LINKTYPE_LINUX_SLL2`, pcap DLT 276) is the successor of the
//! original SLL link type, emitted by newer tcpdump releases for cooked
//! captures such as `tcpdump -i any`. It reorders the SLL fields — the
//! protocol comes first — and adds the interface index, which SLL could
//! not represent.
//!
//! # Header layout (20 bytes)
//!
//! ```text
//!  0         2        4                  8         10  11      12          20
//! +---------+--------+------------------+---------+---+-------+-----------+
//! | protocol| unused | interface index  | arphrd  | pt| addrl | address   |
//! |  (2B)   |  (2B)  |      (4B)        |  (2B)   |(1)|  (1)  |  (8B)     |
//! +---------+--------+------------------+---------+---+-------+-----------+
//! ```
//!
//! # Difference from SLL
//!
//! - 20-byte header (SLL: 16 bytes), fields reordered with protocol first.
//! - Adds a 4-byte interface index field.
//! - Packet type and address length shrink from 16-bit to 8-bit fields.
//! - Everything else (packet type semantics, ARPHRD types, up to 8-byte
//!   truncated sender address, EtherType protocol) is shared with SLL.
//!
//! # Examples
//!
//! ```
//! use wireforge_core::sll2::{Sll2Packet, Sll2PacketBuilder};
//! use wireforge_core::types::EtherType;
//! use wireforge_core::util::PacketBuilder;
//!
//! let frame = Sll2PacketBuilder::new()
//!     .protocol(EtherType::Ipv4)
//!     .interface_index(2)
//!     .packet_type(0)
//!     .address(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
//!     .unwrap()
//!     .payload(&[0x45, 0x00])
//!     .build();
//!
//! let sll2 = Sll2Packet::new(&frame).unwrap();
//! assert_eq!(sll2.protocol(), EtherType::Ipv4);
//! assert_eq!(sll2.interface_index(), 2);
//! assert_eq!(sll2.address_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
//! assert_eq!(sll2.payload(), &[0x45, 0x00]);
//! ```

use alloc::vec::Vec;

use crate::types::EtherType;
use crate::util::{read_u16be, read_u32be, write_u16be, write_u32be, BuildError, PacketBuilder};

/// SLL2 header length (20 bytes).
pub const SLL2_HEADER_LEN: usize = 20;

/// Maximum length of the sender address field (8 bytes).
pub const SLL2_MAX_ADDRESS_LEN: usize = 8;

// Packet type constants are shared with SLL.
pub use crate::sll::{
    ARPHRD_ARCNET, ARPHRD_ATALK, ARPHRD_AX25, ARPHRD_CISCO, ARPHRD_CHAOS, ARPHRD_DLCI, ARPHRD_ETHER,
    ARPHRD_EETHER, ARPHRD_FDDI, ARPHRD_IEEE802, ARPHRD_IEEE80211, ARPHRD_IEEE80211_RADIOTAP,
    ARPHRD_IEEE802154, ARPHRD_INFINIBAND, ARPHRD_LOOPBACK, ARPHRD_NETLINK, ARPHRD_NETROM, ARPHRD_NONE,
    ARPHRD_PPP, ARPHRD_PRONET, ARPHRD_SIT, ARPHRD_SLIP, ARPHRD_TUNNEL, ARPHRD_TUNNEL6, ARPHRD_VOID,
    SLL_MAX_ADDRESS_LEN, SLL_PKTTYPE_BROADCAST, SLL_PKTTYPE_MULTICAST, SLL_PKTTYPE_OTHERHOST,
    SLL_PKTTYPE_OUTGOING, SLL_PKTTYPE_UNICAST,
};

/// Zero-copy Linux cooked capture v2 (SLL2) parser.
///
/// Holds a reference to the underlying byte slice. All field accessors
/// are inline offset reads — no allocation.
#[derive(Debug, Clone)]
pub struct Sll2Packet<'a> {
    buf: &'a [u8],
}

impl<'a> Sll2Packet<'a> {
    crate::parser_new!(SLL2_HEADER_LEN);

    /// Raw bytes backing this packet.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// Protocol (EtherType) of the payload.
    #[inline]
    pub fn protocol(&self) -> EtherType {
        EtherType::from(read_u16be(&self.buf[0..2]))
    }

    /// Raw protocol value.
    #[inline]
    pub fn raw_protocol(&self) -> u16 {
        read_u16be(&self.buf[0..2])
    }

    /// Reserved / unused field.
    #[inline]
    pub fn reserved(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }

    /// Index of the interface the packet was captured on.
    #[inline]
    pub fn interface_index(&self) -> u32 {
        read_u32be(&self.buf[4..8])
    }

    /// ARPHRD device type of the captured interface.
    #[inline]
    pub fn arphrd_type(&self) -> u16 {
        read_u16be(&self.buf[8..10])
    }

    /// Packet type (Linux `PACKET_*` value).
    #[inline]
    pub fn packet_type(&self) -> u8 {
        self.buf[10]
    }

    /// Number of meaningful bytes in the address field.
    #[inline]
    pub fn address_length(&self) -> u8 {
        self.buf[11]
    }

    /// Full 8-byte address field (may contain trailing padding).
    #[inline]
    pub fn address(&self) -> &'a [u8] {
        &self.buf[12..20]
    }

    /// The meaningful part of the address field, truncated to
    /// `address_length()` bytes (clamped to 8).
    #[inline]
    pub fn address_bytes(&self) -> &'a [u8] {
        let len = (self.address_length() as usize).min(SLL2_MAX_ADDRESS_LEN);
        &self.buf[12..12 + len]
    }

    /// Payload following the SLL2 header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[SLL2_HEADER_LEN..]
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing Linux cooked capture v2 (SLL2) frames.
#[derive(Debug, Clone)]
pub struct Sll2PacketBuilder {
    buf: [u8; SLL2_HEADER_LEN],
    payload: Option<Vec<u8>>,
}

impl Default for Sll2PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Sll2PacketBuilder {
    pub fn new() -> Self {
        Self {
            buf: [0u8; SLL2_HEADER_LEN],
            payload: None,
        }
    }

    /// Set the payload protocol (EtherType).
    pub fn protocol(mut self, et: EtherType) -> Self {
        write_u16be(&mut self.buf[0..2], et.into());
        self
    }

    /// Set the raw protocol value.
    pub fn raw_protocol(mut self, v: u16) -> Self {
        write_u16be(&mut self.buf[0..2], v);
        self
    }

    /// Set the reserved / unused field.
    pub fn reserved(mut self, v: u16) -> Self {
        write_u16be(&mut self.buf[2..4], v);
        self
    }

    /// Set the interface index.
    pub fn interface_index(mut self, idx: u32) -> Self {
        write_u32be(&mut self.buf[4..8], idx);
        self
    }

    /// Set the ARPHRD device type.
    pub fn arphrd_type(mut self, t: u16) -> Self {
        write_u16be(&mut self.buf[8..10], t);
        self
    }

    /// Set the packet type (Linux `PACKET_*` value).
    pub fn packet_type(mut self, t: u8) -> Self {
        self.buf[10] = t;
        self
    }

    /// Set the address length field directly.
    pub fn address_length(mut self, len: u8) -> Self {
        self.buf[11] = len;
        self
    }

    /// Set the sender hardware address (at most 8 bytes).
    ///
    /// Shorter addresses are zero-padded to the full 8-byte field and the
    /// address length field is updated automatically.
    pub fn address(mut self, addr: &[u8]) -> Result<Self, BuildError> {
        if addr.len() > SLL2_MAX_ADDRESS_LEN {
            return Err(BuildError::InvalidField {
                field: "address",
                reason: "SLL2 address field is at most 8 bytes",
            });
        }
        self.buf[12..20].fill(0);
        self.buf[12..12 + addr.len()].copy_from_slice(addr);
        self.buf[11] = addr.len() as u8;
        Ok(self)
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }

    /// Assemble the complete SLL2 frame.
    pub fn build(self) -> Vec<u8> {
        <Self as PacketBuilder>::build(self)
    }
}

impl PacketBuilder for Sll2PacketBuilder {
    type Output = Vec<u8>;

    fn build(self) -> Vec<u8> {
        let mut packet =
            Vec::with_capacity(SLL2_HEADER_LEN + self.payload.as_ref().map_or(0, |p| p.len()));
        packet.extend_from_slice(&self.buf);
        if let Some(p) = self.payload {
            packet.extend_from_slice(&p);
        }
        packet
    }
}

// ---------------------------------------------------------------------------
// Mutable
// ---------------------------------------------------------------------------

crate::impl_mutable_packet!(MutableSll2Packet, SLL2_HEADER_LEN);

impl<'a> MutableSll2Packet<'a> {
    fn view(&self) -> Sll2Packet<'_> {
        Sll2Packet::new(&*self.buf).expect("validated in MutableSll2Packet::new")
    }

    fn payload_offset(&self) -> usize {
        SLL2_HEADER_LEN
    }

    pub fn protocol(&self) -> EtherType {
        self.view().protocol()
    }

    pub fn set_protocol(&mut self, et: EtherType) {
        write_u16be(&mut self.buf[0..2], et.into());
    }

    pub fn raw_protocol(&self) -> u16 {
        self.view().raw_protocol()
    }

    pub fn set_raw_protocol(&mut self, v: u16) {
        write_u16be(&mut self.buf[0..2], v);
    }

    pub fn interface_index(&self) -> u32 {
        self.view().interface_index()
    }

    pub fn set_interface_index(&mut self, idx: u32) {
        write_u32be(&mut self.buf[4..8], idx);
    }

    pub fn arphrd_type(&self) -> u16 {
        self.view().arphrd_type()
    }

    pub fn set_arphrd_type(&mut self, t: u16) {
        write_u16be(&mut self.buf[8..10], t);
    }

    pub fn packet_type(&self) -> u8 {
        self.buf[10]
    }

    pub fn set_packet_type(&mut self, t: u8) {
        self.buf[10] = t;
    }

    pub fn address_length(&self) -> u8 {
        self.buf[11]
    }

    pub fn set_address_length(&mut self, len: u8) {
        self.buf[11] = len;
    }

    pub fn address(&self) -> &[u8] {
        &self.buf[12..20]
    }

    pub fn address_mut(&mut self) -> &mut [u8] {
        &mut self.buf[12..20]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EtherType;
    use alloc::vec::Vec;

    /// Realistic `tcpdump -i any` SLL2 frame (IPv6 on loopback, ifindex 1).
    fn sample() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x86, 0xDD]); // protocol: IPv6
        buf.extend_from_slice(&[0x00, 0x00]); // reserved
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // ifindex: 1
        buf.extend_from_slice(&[0x03, 0x04]); // arphrd: 772 (loopback)
        buf.push(0x00); // packet type: unicast to us
        buf.push(0x00); // address length: 0
        buf.extend_from_slice(&[0x00; 8]); // address
        buf.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // start of IPv6 header
        buf
    }

    #[test]
    fn parse_known_sample() {
        let buf = sample();
        let sll2 = Sll2Packet::new(&buf).unwrap();
        assert_eq!(sll2.protocol(), EtherType::Ipv6);
        assert_eq!(sll2.reserved(), 0);
        assert_eq!(sll2.interface_index(), 1);
        assert_eq!(sll2.arphrd_type(), ARPHRD_LOOPBACK);
        assert_eq!(sll2.packet_type(), SLL_PKTTYPE_UNICAST as u8);
        assert_eq!(sll2.address_length(), 0);
        assert!(sll2.address_bytes().is_empty());
        assert_eq!(sll2.payload(), &[0x60, 0x00, 0x00, 0x00]);
        assert_eq!(sll2.as_bytes().len(), buf.len());
    }

    #[test]
    fn too_short() {
        assert!(Sll2Packet::new(&[0u8; SLL2_HEADER_LEN - 1]).is_none());
        assert!(Sll2Packet::new(&[]).is_none());
    }

    #[test]
    fn packet_type_constants_match_linux_values() {
        assert_eq!(SLL_PKTTYPE_UNICAST, 0);
        assert_eq!(SLL_PKTTYPE_BROADCAST, 1);
        assert_eq!(SLL_PKTTYPE_MULTICAST, 2);
        assert_eq!(SLL_PKTTYPE_OTHERHOST, 3);
        assert_eq!(SLL_PKTTYPE_OUTGOING, 4);
    }

    #[test]
    fn builder_roundtrip() {
        let frame = Sll2PacketBuilder::new()
            .protocol(EtherType::Arp)
            .interface_index(3)
            .arphrd_type(ARPHRD_ETHER)
            .packet_type(SLL_PKTTYPE_BROADCAST as u8)
            .address(&[0xFF; 6])
            .unwrap()
            .payload(&[0x00, 0x01])
            .build();

        let sll2 = Sll2Packet::new(&frame).unwrap();
        assert_eq!(sll2.protocol(), EtherType::Arp);
        assert_eq!(sll2.interface_index(), 3);
        assert_eq!(sll2.arphrd_type(), ARPHRD_ETHER);
        assert_eq!(sll2.packet_type(), SLL_PKTTYPE_BROADCAST as u8);
        assert_eq!(sll2.address_bytes(), &[0xFF; 6]);
        assert_eq!(sll2.payload(), &[0x00, 0x01]);
    }

    #[test]
    fn builder_pads_short_address() {
        let frame = Sll2PacketBuilder::new().address(&[0xAA; 6]).unwrap().build();
        let sll2 = Sll2Packet::new(&frame).unwrap();
        assert_eq!(sll2.address(), &[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00]);
        assert_eq!(sll2.address_length(), 6);
    }

    #[test]
    fn builder_rejects_oversized_address() {
        let err = Sll2PacketBuilder::new().address(&[0u8; 9]).unwrap_err();
        assert!(matches!(err, BuildError::InvalidField { field: "address", .. }));
    }

    #[test]
    fn mutable_sll2_accessors() {
        let mut frame = Sll2PacketBuilder::new().protocol(EtherType::Ipv4).build();
        {
            let mut mutable = MutableSll2Packet::new(&mut frame).unwrap();
            assert_eq!(mutable.interface_index(), 0);
            mutable.set_protocol(EtherType::Ipv6);
            mutable.set_interface_index(7);
            mutable.set_arphrd_type(ARPHRD_PPP);
            mutable.set_packet_type(SLL_PKTTYPE_OUTGOING as u8);
            mutable.set_address_length(6);
            mutable.address_mut().copy_from_slice(&[0x22; 8]);
        }

        let sll2 = Sll2Packet::new(&frame).unwrap();
        assert_eq!(sll2.protocol(), EtherType::Ipv6);
        assert_eq!(sll2.interface_index(), 7);
        assert_eq!(sll2.arphrd_type(), ARPHRD_PPP);
        assert_eq!(sll2.packet_type(), SLL_PKTTYPE_OUTGOING as u8);
        assert_eq!(sll2.address_bytes(), &[0x22; 6]);
    }

    #[test]
    fn debug_format() {
        let buf = sample();
        let sll2 = Sll2Packet::new(&buf).unwrap();
        let dbg = alloc::format!("{:?}", sll2);
        assert!(dbg.contains("Sll2Packet"));
    }
}
