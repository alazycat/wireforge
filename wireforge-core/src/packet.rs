//! Common traits for packet manipulation.
//!
//! These traits provide a uniform interface over the zero-copy packet parsers,
//! so generic code can operate on any packet type:
//!
//! ```
//! use wireforge_core::ether::EthernetPacket;
//! use wireforge_core::packet::{Packet, PacketSize};
//!
//! fn payload_len<T: Packet>(packet: &T) -> usize {
//!     packet.payload().len()
//! }
//!
//! let frame = [0u8; 60];
//! let eth = EthernetPacket::new(&frame).unwrap();
//! assert_eq!(payload_len(&eth), 46);
//! assert_eq!(eth.packet_size(), 60);
//! ```

use alloc::boxed::Box;

use crate::arp::{ArpPacket, ARP_HEADER_LEN};
use crate::ether::EthernetPacket;
use crate::gre::GrePacket;
use crate::icmp::{IcmpPacket, Icmpv6Packet};
use crate::igmp::IgmpPacket;
use crate::ipv4::Ipv4Packet;
use crate::ipv6::Ipv6Packet;
use crate::tcp::TcpPacket;
use crate::udp::UdpPacket;
use crate::vlan::VlanPacket;

/// A parsed network packet backed by a byte buffer.
pub trait Packet {
    /// The complete packet buffer, including headers.
    fn packet(&self) -> &[u8];

    /// The bytes following the packet's own header.
    fn payload(&self) -> &[u8];
}

impl<T: Packet + ?Sized> Packet for Box<T> {
    fn packet(&self) -> &[u8] {
        self.as_ref().packet()
    }

    fn payload(&self) -> &[u8] {
        self.as_ref().payload()
    }
}

impl<T: Packet + ?Sized> Packet for &T {
    fn packet(&self) -> &[u8] {
        (*self).packet()
    }

    fn payload(&self) -> &[u8] {
        (*self).payload()
    }
}

/// A mutable packet backed by a writable byte buffer.
///
/// Implementations are added by the mutable packet API; this trait defines the
/// shared operations.
pub trait MutablePacket: Packet {
    /// The complete packet buffer, mutable.
    fn packet_mut(&mut self) -> &mut [u8];

    /// The bytes following the packet's own header, mutable.
    fn payload_mut(&mut self) -> &mut [u8];

    /// Overwrite this packet's buffer with the contents of `other`.
    ///
    /// Panics if this packet's buffer is smaller than `other`'s packet.
    fn clone_from<T: Packet>(&mut self, other: &T) {
        let source = other.packet();
        let destination = self.packet_mut();
        assert!(
            destination.len() >= source.len(),
            "destination packet buffer is too small"
        );
        destination[..source.len()].copy_from_slice(source);
    }
}

/// A packet's size in bytes.
///
/// Implemented for every [`Packet`] as the length of its backing buffer.
pub trait PacketSize: Packet {
    /// The packet size in bytes.
    fn packet_size(&self) -> usize;
}

impl<T: Packet + ?Sized> PacketSize for T {
    fn packet_size(&self) -> usize {
        self.packet().len()
    }
}

/// Conversion from a wire-format packet to an owned representation.
///
/// The `from_packet` name matches libpnet's `FromPacket` trait.
#[allow(clippy::wrong_self_convention)]
pub trait FromPacket: Packet {
    /// The owned type produced by [`from_packet`](Self::from_packet).
    type T;

    /// Convert this packet into its owned representation.
    fn from_packet(&self) -> Self::T;
}

// ---------------------------------------------------------------------------
// Implementations for the core protocol parsers
// ---------------------------------------------------------------------------

impl<'a> Packet for EthernetPacket<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> Packet for VlanPacket<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.inner()
    }
}

impl<'a> Packet for ArpPacket<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        &self.as_bytes()[ARP_HEADER_LEN..]
    }
}

impl<'a> Packet for Ipv4Packet<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> Packet for Ipv6Packet<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> Packet for TcpPacket<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> Packet for UdpPacket<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> Packet for IcmpPacket<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> Packet for Icmpv6Packet<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.body()
    }
}

impl<'a> Packet for IgmpPacket<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}

impl<'a> Packet for GrePacket<'a> {
    fn packet(&self) -> &[u8] {
        self.as_bytes()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }
}
