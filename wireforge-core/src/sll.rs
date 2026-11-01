//! Linux cooked capture (SLL) link-layer parser and builder.
//!
//! The Linux cooked capture link type (`LINKTYPE_LINUX_SLL`, pcap DLT 113)
//! is what libpcap emits for captures taken on a cooked socket — most
//! notably `tcpdump -i any`. Unlike an Ethernet II frame, an SLL header
//! does not carry real MAC addresses: the 16-byte header contains a
//! packet type, the interface ARPHRD type, a truncated (up to 8-byte)
//! sender hardware address and the protocol (EtherType) of the payload.
//!
//! # Header layout (16 bytes)
//!
//! ```text
//!  0         2        4              6                      14     16
//! +---------+--------+--------------+----------------------+-------+
//! | pkttype | arphrd | addr length  | address (8 bytes)    | proto |
//! +---------+--------+--------------+----------------------+-------+
//! ```
//!
//! # Difference from Ethernet
//!
//! - Fixed 16-byte header (Ethernet: 14 bytes); all fields are big-endian.
//! - No destination address at all; the sender address is up to 8 bytes and
//!   only the first `address_length()` bytes are meaningful.
//! - `protocol` occupies the same trailing position as the Ethernet
//!   EtherType, so L3 dispatch works identically.
//!
//! # Examples
//!
//! ```
//! use wireforge_core::sll::{SllPacket, SllPacketBuilder, ARPHRD_ETHER, SLL_PKTTYPE_UNICAST};
//! use wireforge_core::types::EtherType;
//! use wireforge_core::util::PacketBuilder;
//!
//! let frame = SllPacketBuilder::new()
//!     .packet_type(SLL_PKTTYPE_UNICAST)
//!     .arphrd_type(ARPHRD_ETHER)
//!     .address(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
//!     .unwrap()
//!     .protocol(EtherType::Ipv4)
//!     .payload(&[0xDE, 0xAD, 0xBE, 0xEF])
//!     .build();
//!
//! let sll = SllPacket::new(&frame).unwrap();
//! assert_eq!(sll.packet_type(), SLL_PKTTYPE_UNICAST);
//! assert_eq!(sll.arphrd_type(), ARPHRD_ETHER);
//! assert_eq!(sll.address_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
//! assert_eq!(sll.protocol(), EtherType::Ipv4);
//! assert_eq!(sll.payload(), &[0xDE, 0xAD, 0xBE, 0xEF]);
//! ```

use alloc::vec::Vec;

use crate::types::EtherType;
use crate::util::{read_u16be, write_u16be, BuildError, PacketBuilder};

/// SLL header length (16 bytes).
pub const SLL_HEADER_LEN: usize = 16;

/// Maximum length of the sender address field (8 bytes).
pub const SLL_MAX_ADDRESS_LEN: usize = 8;

// Packet type values (Linux `PACKET_*` socket types).
/// Packet addressed to this host.
pub const SLL_PKTTYPE_UNICAST: u16 = 0;
/// Physical-layer broadcast packet.
pub const SLL_PKTTYPE_BROADCAST: u16 = 1;
/// Physical-layer multicast packet.
pub const SLL_PKTTYPE_MULTICAST: u16 = 2;
/// Packet addressed to another host (promiscuous capture).
pub const SLL_PKTTYPE_OTHERHOST: u16 = 3;
/// Packet originated by this host.
pub const SLL_PKTTYPE_OUTGOING: u16 = 4;

// ARPHRD_* device types (Linux `if_arp.h`).
/// Generic AX.25.
pub const ARPHRD_NETROM: u16 = 0;
/// Ethernet.
pub const ARPHRD_ETHER: u16 = 1;
/// Experimental Ethernet.
pub const ARPHRD_EETHER: u16 = 2;
/// AX.25 without KISS.
pub const ARPHRD_AX25: u16 = 3;
/// PROnet token ring.
pub const ARPHRD_PRONET: u16 = 4;
/// Chaosnet.
pub const ARPHRD_CHAOS: u16 = 5;
/// IEEE 802.2 Ethernet/TR/TB.
pub const ARPHRD_IEEE802: u16 = 6;
/// ARCnet.
pub const ARPHRD_ARCNET: u16 = 7;
/// AppleTalk.
pub const ARPHRD_ATALK: u16 = 8;
/// Frame Relay DLCI.
pub const ARPHRD_DLCI: u16 = 15;
/// InfiniBand.
pub const ARPHRD_INFINIBAND: u16 = 32;
/// SLIP.
pub const ARPHRD_SLIP: u16 = 256;
/// PPP.
pub const ARPHRD_PPP: u16 = 512;
/// Cisco HDLC.
pub const ARPHRD_CISCO: u16 = 513;
/// IP tunnel.
pub const ARPHRD_TUNNEL: u16 = 768;
/// IP6 tunnel.
pub const ARPHRD_TUNNEL6: u16 = 769;
/// Loopback device.
pub const ARPHRD_LOOPBACK: u16 = 772;
/// Fiber distributed data interface.
pub const ARPHRD_FDDI: u16 = 774;
/// IPv6-in-IPv4 tunnel.
pub const ARPHRD_SIT: u16 = 776;
/// IEEE 802.11.
pub const ARPHRD_IEEE80211: u16 = 801;
/// IEEE 802.11 radiotap header.
pub const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;
/// IEEE 802.15.4.
pub const ARPHRD_IEEE802154: u16 = 804;
/// Netlink device.
pub const ARPHRD_NETLINK: u16 = 824;
/// Zero header length device.
pub const ARPHRD_NONE: u16 = 0xFFFE;
/// Unknown device type.
pub const ARPHRD_VOID: u16 = 0xFFFF;

/// Zero-copy Linux cooked capture (SLL) parser.
///
/// Holds a reference to the underlying byte slice. All field accessors
/// are inline offset reads — no allocation.
#[derive(Debug, Clone)]
pub struct SllPacket<'a> {
    buf: &'a [u8],
}

impl<'a> SllPacket<'a> {
    crate::parser_new!(SLL_HEADER_LEN);

    /// Raw bytes backing this packet.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// Packet type (Linux `PACKET_*` value).
    #[inline]
    pub fn packet_type(&self) -> u16 {
        read_u16be(&self.buf[0..2])
    }

    /// ARPHRD device type of the captured interface.
    #[inline]
    pub fn arphrd_type(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }

    /// Number of meaningful bytes in the address field.
    #[inline]
    pub fn address_length(&self) -> u16 {
        read_u16be(&self.buf[4..6])
    }

    /// Full 8-byte address field (may contain trailing padding).
    #[inline]
    pub fn address(&self) -> &'a [u8] {
        &self.buf[6..14]
    }

    /// The meaningful part of the address field, truncated to
    /// `address_length()` bytes (clamped to 8).
    #[inline]
    pub fn address_bytes(&self) -> &'a [u8] {
        let len = (self.address_length() as usize).min(SLL_MAX_ADDRESS_LEN);
        &self.buf[6..6 + len]
    }

    /// Protocol (EtherType) of the payload.
    #[inline]
    pub fn protocol(&self) -> EtherType {
        EtherType::from(read_u16be(&self.buf[14..16]))
    }

    /// Raw protocol value.
    #[inline]
    pub fn raw_protocol(&self) -> u16 {
        read_u16be(&self.buf[14..16])
    }

    /// Payload following the SLL header.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[SLL_HEADER_LEN..]
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing Linux cooked capture (SLL) frames.
#[derive(Debug, Clone)]
pub struct SllPacketBuilder {
    buf: [u8; SLL_HEADER_LEN],
    payload: Option<Vec<u8>>,
}

impl Default for SllPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SllPacketBuilder {
    pub fn new() -> Self {
        Self {
            buf: [0u8; SLL_HEADER_LEN],
            payload: None,
        }
    }

    /// Set the packet type (Linux `PACKET_*` value).
    pub fn packet_type(mut self, t: u16) -> Self {
        write_u16be(&mut self.buf[0..2], t);
        self
    }

    /// Set the ARPHRD device type.
    pub fn arphrd_type(mut self, t: u16) -> Self {
        write_u16be(&mut self.buf[2..4], t);
        self
    }

    /// Set the address length field directly.
    pub fn address_length(mut self, len: u16) -> Self {
        write_u16be(&mut self.buf[4..6], len);
        self
    }

    /// Set the sender hardware address (at most 8 bytes).
    ///
    /// Shorter addresses are zero-padded to the full 8-byte field and the
    /// address length field is updated automatically.
    pub fn address(mut self, addr: &[u8]) -> Result<Self, BuildError> {
        if addr.len() > SLL_MAX_ADDRESS_LEN {
            return Err(BuildError::InvalidField {
                field: "address",
                reason: "SLL address field is at most 8 bytes",
            });
        }
        self.buf[6..14].fill(0);
        self.buf[6..6 + addr.len()].copy_from_slice(addr);
        write_u16be(&mut self.buf[4..6], addr.len() as u16);
        Ok(self)
    }

    /// Set the payload protocol (EtherType).
    pub fn protocol(mut self, et: EtherType) -> Self {
        write_u16be(&mut self.buf[14..16], et.into());
        self
    }

    /// Set the raw protocol value.
    pub fn raw_protocol(mut self, v: u16) -> Self {
        write_u16be(&mut self.buf[14..16], v);
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = Some(data.to_vec());
        self
    }

    /// Assemble the complete SLL frame.
    pub fn build(self) -> Vec<u8> {
        <Self as PacketBuilder>::build(self)
    }
}

impl PacketBuilder for SllPacketBuilder {
    type Output = Vec<u8>;

    fn build(self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(SLL_HEADER_LEN + self.payload.as_ref().map_or(0, |p| p.len()));
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

crate::impl_mutable_packet!(MutableSllPacket, SLL_HEADER_LEN);

impl<'a> MutableSllPacket<'a> {
    fn view(&self) -> SllPacket<'_> {
        SllPacket::new(&*self.buf).expect("validated in MutableSllPacket::new")
    }

    fn payload_offset(&self) -> usize {
        SLL_HEADER_LEN
    }

    pub fn packet_type(&self) -> u16 {
        self.view().packet_type()
    }

    pub fn set_packet_type(&mut self, t: u16) {
        write_u16be(&mut self.buf[0..2], t);
    }

    pub fn arphrd_type(&self) -> u16 {
        self.view().arphrd_type()
    }

    pub fn set_arphrd_type(&mut self, t: u16) {
        write_u16be(&mut self.buf[2..4], t);
    }

    pub fn address_length(&self) -> u16 {
        self.view().address_length()
    }

    pub fn set_address_length(&mut self, len: u16) {
        write_u16be(&mut self.buf[4..6], len);
    }

    pub fn address(&self) -> &[u8] {
        &self.buf[6..14]
    }

    pub fn address_mut(&mut self) -> &mut [u8] {
        &mut self.buf[6..14]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EtherType;
    use alloc::vec::Vec;

    /// Realistic `tcpdump -i any` SLL frame: unicast Ethernet-bound IPv4.
    fn sample() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x00]); // packet type: unicast to us
        buf.extend_from_slice(&[0x00, 0x01]); // arphrd: Ethernet
        buf.extend_from_slice(&[0x00, 0x06]); // address length: 6
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00]); // addr + pad
        buf.extend_from_slice(&[0x08, 0x00]); // protocol: IPv4
        buf.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]); // start of IPv4 header
        buf
    }

    #[test]
    fn parse_known_sample() {
        let buf = sample();
        let sll = SllPacket::new(&buf).unwrap();
        assert_eq!(sll.packet_type(), SLL_PKTTYPE_UNICAST);
        assert_eq!(sll.arphrd_type(), ARPHRD_ETHER);
        assert_eq!(sll.address_length(), 6);
        assert_eq!(sll.address(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00]);
        assert_eq!(sll.address_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(sll.protocol(), EtherType::Ipv4);
        assert_eq!(sll.payload(), &[0x45, 0x00, 0x00, 0x14]);
        assert_eq!(sll.as_bytes().len(), buf.len());
    }

    #[test]
    fn too_short() {
        assert!(SllPacket::new(&[0u8; SLL_HEADER_LEN - 1]).is_none());
        assert!(SllPacket::new(&[]).is_none());
    }

    #[test]
    fn address_bytes_clamped_to_field() {
        // address_length=8 → full field; absurd length → clamped to 8.
        let buf = SllPacketBuilder::new()
            .address_length(8)
            .address(&[0xFF; 8])
            .unwrap()
            .build();
        let sll = SllPacket::new(&buf).unwrap();
        assert_eq!(sll.address_bytes(), &[0xFF; 8]);

        let buf = SllPacketBuilder::new().address_length(100).build();
        let sll = SllPacket::new(&buf).unwrap();
        assert_eq!(sll.address_bytes().len(), SLL_MAX_ADDRESS_LEN);
    }

    #[test]
    fn builder_roundtrip() {
        let frame = SllPacketBuilder::new()
            .packet_type(SLL_PKTTYPE_OUTGOING)
            .arphrd_type(ARPHRD_LOOPBACK)
            .address(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            .unwrap()
            .protocol(EtherType::Ipv6)
            .payload(&[0x60, 0x00])
            .build();

        let sll = SllPacket::new(&frame).unwrap();
        assert_eq!(sll.packet_type(), SLL_PKTTYPE_OUTGOING);
        assert_eq!(sll.arphrd_type(), ARPHRD_LOOPBACK);
        assert_eq!(sll.address_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(sll.protocol(), EtherType::Ipv6);
        assert_eq!(sll.payload(), &[0x60, 0x00]);
    }

    #[test]
    fn builder_pads_short_address() {
        let frame = SllPacketBuilder::new().address(&[0xAA; 6]).unwrap().build();
        let sll = SllPacket::new(&frame).unwrap();
        assert_eq!(sll.address(), &[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00]);
        assert_eq!(sll.address_length(), 6);
    }

    #[test]
    fn builder_rejects_oversized_address() {
        let err = SllPacketBuilder::new().address(&[0u8; 9]).unwrap_err();
        assert!(matches!(err, BuildError::InvalidField { field: "address", .. }));
    }

    #[test]
    fn mutable_sll_accessors() {
        let mut frame = SllPacketBuilder::new()
            .packet_type(SLL_PKTTYPE_UNICAST)
            .arphrd_type(ARPHRD_ETHER)
            .build();
        {
            let mut mutable = MutableSllPacket::new(&mut frame).unwrap();
            assert_eq!(mutable.packet_type(), SLL_PKTTYPE_UNICAST);
            mutable.set_packet_type(SLL_PKTTYPE_MULTICAST);
            mutable.set_arphrd_type(ARPHRD_IEEE80211);
            mutable.set_address_length(4);
            mutable.address_mut().copy_from_slice(&[0x11; 8]);
            assert_eq!(mutable.packet_type(), SLL_PKTTYPE_MULTICAST);
            assert_eq!(mutable.arphrd_type(), ARPHRD_IEEE80211);
            assert_eq!(mutable.address_length(), 4);
            assert_eq!(mutable.address()[..4], [0x11; 4]);
        }

        let sll = SllPacket::new(&frame).unwrap();
        assert_eq!(sll.packet_type(), SLL_PKTTYPE_MULTICAST);
        assert_eq!(sll.address_bytes(), &[0x11; 4]);
    }

    #[test]
    fn debug_format() {
        let buf = sample();
        let sll = SllPacket::new(&buf).unwrap();
        let dbg = alloc::format!("{:?}", sll);
        assert!(dbg.contains("SllPacket"));
    }
}
