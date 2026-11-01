//! Transport-layer channel API — a `pnet_transport` equivalent.
//!
//! This module mirrors libpnet's `pnet_transport` surface on top of standard
//! IPv4 raw sockets (`socket2`):
//!
//! - [`transport_channel`] replaces `transport_channel(buffer_size, channel_type)`
//! - [`TransportSender::send_to`] / [`TransportSender::set_ttl`] /
//!   [`TransportSender::set_ecn`] replace `TransportSender`
//! - [`TransportReceiver::tcp_packets`] / [`udp_packets`] / [`icmp_packets`]
//!   and [`TransportReceiver::next_with_timeout`] replace `TransportReceiver`
//!
//! The channel is created for a single IP protocol
//! ([`TransportChannelType::Layer4`]). The sender transmits transport-layer
//! PDUs (header + payload); the kernel builds the IP header, honoring TTL and
//! ECN set via the sender. The receiver captures matching IP datagrams,
//! strips the IPv4 header, and yields the transport PDU together with the
//! source address.
//!
//! # Platform notes
//!
//! Raw sockets require elevated privileges: root / `CAP_NET_RAW` on Linux,
//! Administrator on Windows. Windows blocks raw sockets for the TCP
//! protocol; ICMP and UDP work. macOS is not covered by CI but uses the same
//! standard BSD raw sockets.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::net::{IpAddr, Ipv4Addr};
//! use std::time::Duration;
//!
//! use wireforge_core::icmp::IcmpPacketBuilder;
//! use wireforge_core::types::IpProtocol;
//! use wireforge_io::transport::{transport_channel, TransportChannelType};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let (mut tx, mut rx) =
//!     transport_channel(4096, TransportChannelType::Layer4(IpProtocol::Icmp))?;
//! tx.set_ttl(64)?;
//!
//! let request = IcmpPacketBuilder::echo_request()
//!     .identifier(0x4242)
//!     .sequence_number(1)
//!     .payload(b"wireforge")
//!     .build();
//! tx.send_to(&request, IpAddr::V4(Ipv4Addr::LOCALHOST))?;
//!
//! for reply in rx.icmp_packets() {
//!     let icmp = reply.packet();
//!     if icmp.type_() == 0 {
//!         // echo reply
//!         break;
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use wireforge_core::icmp::IcmpPacket;
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::tcp::TcpPacket;
use wireforge_core::types::IpProtocol;
use wireforge_core::udp::UdpPacket;

use crate::common;
use crate::error::IoError;

/// Selects the transport channel flavor, mirroring libpnet's
/// `TransportChannelType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportChannelType {
    /// A raw IPv4 socket for one specific IP protocol.
    Layer4(IpProtocol),
}

/// Create a transport channel for the given channel type.
///
/// Returns `(sender, receiver)` like libpnet. `buffer_size` is the maximum
/// datagram size the receiver will accept (clamped to at least 576 bytes).
///
/// Requires root (Linux/macOS) or Administrator (Windows).
pub fn transport_channel(
    buffer_size: usize,
    channel_type: TransportChannelType,
) -> Result<(TransportSender, TransportReceiver), IoError> {
    let TransportChannelType::Layer4(protocol) = channel_type;
    let proto = Protocol::from(i32::from(u8::from(protocol)));
    let rx = Socket::new(Domain::IPV4, Type::RAW, Some(proto))?;
    // Windows requires binding raw sockets before receiving; binding to
    // INADDR_ANY is harmless (no filtering) on Linux/macOS.
    let any = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
    rx.bind(&any)?;
    let tx = Socket::new(Domain::IPV4, Type::RAW, Some(proto))?;
    Ok((
        TransportSender { sock: tx, tos: 0 },
        TransportReceiver {
            sock: rx,
            buf: vec![0u8; buffer_size.max(576)],
            protocol,
            source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            offset: 0,
        },
    ))
}

/// Sender half of a transport channel.
///
/// Sends transport-layer PDUs (e.g. a TCP segment or ICMP message); the
/// kernel builds the enclosing IPv4 header.
#[derive(Debug)]
pub struct TransportSender {
    sock: Socket,
    tos: u8,
}

impl TransportSender {
    /// Send a transport-layer PDU to `dst`.
    pub fn send_to(&self, packet: &[u8], dst: IpAddr) -> Result<usize, IoError> {
        match dst {
            IpAddr::V4(v4) => {
                let addr = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(v4, 0)));
                Ok(self.sock.send_to(packet, &addr)?)
            }
            IpAddr::V6(_) => Err(IoError::Socket(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IPv6 destination on an IPv4 transport channel",
            ))),
        }
    }

    /// Set the TTL of the IP header the kernel builds.
    pub fn set_ttl(&self, ttl: u8) -> Result<(), IoError> {
        Ok(self.sock.set_ttl(u32::from(ttl))?)
    }

    /// Set the ECN field (2 bits) of the IP header, preserving the DSCP value
    /// previously configured on this sender.
    pub fn set_ecn(&mut self, ecn: u8) -> Result<(), IoError> {
        self.tos = (self.tos & 0xFC) | (ecn & 0x03);
        Ok(self.sock.set_tos(u32::from(self.tos))?)
    }

    /// Set the full 8-bit DSCP/ECN TOS byte of the IP header.
    pub fn set_tos(&mut self, tos: u8) -> Result<(), IoError> {
        self.tos = tos;
        Ok(self.sock.set_tos(u32::from(tos))?)
    }
}

/// A received datagram: transport PDU plus its source address.
#[derive(Debug, Clone)]
pub struct TransportPacket {
    data: Vec<u8>,
    source: IpAddr,
    offset: usize,
    protocol: IpProtocol,
}

impl TransportPacket {
    /// Source IP address of the datagram.
    pub fn source(&self) -> IpAddr {
        self.source
    }

    /// The IP protocol this channel was created for.
    pub fn protocol(&self) -> IpProtocol {
        self.protocol
    }

    /// The complete IPv4 datagram, including header and options.
    pub fn as_ip_bytes(&self) -> &[u8] {
        &self.data
    }

    /// The transport-layer PDU (IPv4 header stripped).
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    /// Parse the enclosing IPv4 header.
    pub fn ipv4(&self) -> Ipv4Packet<'_> {
        Ipv4Packet::new(&self.data).expect("validated on receive")
    }

    /// Parse the payload as a TCP segment, if the channel carries TCP.
    pub fn tcp(&self) -> Option<TcpPacket<'_>> {
        TcpPacket::new(self.as_bytes())
    }

    /// Parse the payload as a UDP datagram, if the channel carries UDP.
    pub fn udp(&self) -> Option<UdpPacket<'_>> {
        UdpPacket::new(self.as_bytes())
    }

    /// Parse the payload as an ICMPv4 message, if the channel carries ICMP.
    pub fn icmp(&self) -> Option<IcmpPacket<'_>> {
        IcmpPacket::new(self.as_bytes())
    }
}

/// Receiver half of a transport channel.
#[derive(Debug)]
pub struct TransportReceiver {
    sock: Socket,
    buf: Vec<u8>,
    protocol: IpProtocol,
    source: IpAddr,
    offset: usize,
}

impl TransportReceiver {
    /// Receive the next matching datagram (blocks until one arrives or the
    /// configured timeout, if any, expires).
    // Named `next` for parity with libpnet's `TransportReceiver::next`.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<TransportPacket, IoError> {
        let data = self.fill()?;
        Ok(TransportPacket {
            data,
            source: self.source,
            offset: self.offset,
            protocol: self.protocol,
        })
    }

    /// Receive the next matching datagram with a timeout.
    ///
    /// Returns `Ok(None)` on timeout. The previous receive timeout (if any)
    /// is restored afterwards.
    pub fn next_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<TransportPacket>, IoError> {
        let previous = self.sock.read_timeout();
        self.sock.set_read_timeout(Some(timeout))?;
        let result = self.next();
        if let Ok(Some(prev)) = previous {
            let _ = self.sock.set_read_timeout(Some(prev));
        }
        match result {
            Ok(packet) => Ok(Some(packet)),
            Err(IoError::Timeout) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Set the default receive timeout for [`next`](Self::next).
    /// `None` means blocking.
    pub fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        Ok(self.sock.set_read_timeout(dur)?)
    }

    /// Iterate over received datagrams parsed as TCP segments.
    pub fn tcp_packets(&mut self) -> TcpPackets<'_> {
        TcpPackets { rx: self }
    }

    /// Iterate over received datagrams parsed as UDP datagrams.
    pub fn udp_packets(&mut self) -> UdpPackets<'_> {
        UdpPackets { rx: self }
    }

    /// Iterate over received datagrams parsed as ICMPv4 messages.
    pub fn icmp_packets(&mut self) -> IcmpPackets<'_> {
        IcmpPackets { rx: self }
    }

    /// Read the next matching datagram into an owned buffer and record the
    /// source address and payload offset.
    fn fill(&mut self) -> Result<Vec<u8>, IoError> {
        loop {
            let n = self.sock.read(&mut self.buf).map_err(common::recv_error)?;
            if n == 0 {
                return Err(IoError::Socket(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "raw socket closed",
                )));
            }
            if let Some(pkt) = Ipv4Packet::new(&self.buf[..n]) {
                if pkt.protocol() == self.protocol {
                    self.source = IpAddr::V4(pkt.source());
                    self.offset = n - pkt.payload().len();
                    return Ok(self.buf[..n].to_vec());
                }
            }
            // Not an IPv4 datagram for this channel — skip it.
        }
    }
}

// ---------------------------------------------------------------------------
// Typed iterators
// ---------------------------------------------------------------------------

macro_rules! typed_packets {
    (
        $(#[$view_doc:meta])*
        $view:ident, $iter:ident, $rx_method:ident, $parse_method:ident, $ty:ident;
        $(#[$iter_doc:meta])*
    ) => {
        $(#[$view_doc])*
        #[derive(Debug, Clone)]
        pub struct $view {
            inner: TransportPacket,
        }

        impl $view {
            /// The parsed transport-layer packet.
            pub fn packet(&self) -> $ty<'_> {
                self.inner.$parse_method().expect("validated by the iterator")
            }

            /// Source IP address.
            pub fn source(&self) -> IpAddr {
                self.inner.source()
            }

            /// The transport-layer PDU bytes.
            pub fn as_bytes(&self) -> &[u8] {
                self.inner.as_bytes()
            }

            /// The complete IPv4 datagram, including header.
            pub fn as_ip_bytes(&self) -> &[u8] {
                self.inner.as_ip_bytes()
            }
        }

        $(#[$iter_doc])*
        ///
        /// Iteration stops on receive errors (including timeouts), mirroring
        /// libpnet's channel iterators.
        pub struct $iter<'a> {
            rx: &'a mut TransportReceiver,
        }

        impl Iterator for $iter<'_> {
            type Item = $view;

            fn next(&mut self) -> Option<$view> {
                loop {
                    match self.rx.next() {
                        Ok(p) => {
                            if p.$parse_method().is_some() {
                                return Some($view { inner: p });
                            }
                        }
                        Err(_) => return None,
                    }
                }
            }
        }
    };
}

typed_packets! {
    /// A received TCP segment with its source address.
    TcpPacketView, TcpPackets, tcp_packets, tcp, TcpPacket;
    /// Iterator over received TCP segments.
}

typed_packets! {
    /// A received UDP datagram with its source address.
    UdpPacketView, UdpPackets, udp_packets, udp, UdpPacket;
    /// Iterator over received UDP datagrams.
}

typed_packets! {
    /// A received ICMPv4 message with its source address.
    IcmpPacketView, IcmpPackets, icmp_packets, icmp, IcmpPacket;
    /// Iterator over received ICMPv4 messages.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root (raw ICMP socket)"]
    fn icmp_echo_loopback() {
        let (tx, mut rx) =
            transport_channel(4096, TransportChannelType::Layer4(IpProtocol::Icmp))
                .expect("open ICMP transport channel");

        let request = wireforge_core::icmp::IcmpPacketBuilder::echo_request()
            .identifier(0x5746)
            .sequence_number(1)
            .payload(b"wireforge")
            .build();
        tx.send_to(&request, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("send echo request");

        let reply = rx
            .next_with_timeout(Duration::from_secs(2))
            .expect("receive")
            .expect("got a reply within 2s");
        assert_eq!(reply.source(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let icmp = reply.icmp().expect("ICMP message");
        assert_eq!(icmp.type_(), 0, "echo reply");
        assert_eq!(icmp.payload(), b"wireforge");
    }

    #[test]
    #[ignore = "requires root (raw UDP socket)"]
    fn udp_packets_iterator_yields_source_address() {
        let (_tx, mut rx) =
            transport_channel(4096, TransportChannelType::Layer4(IpProtocol::Udp))
                .expect("open UDP transport channel");
        rx.set_timeout(Some(Duration::from_millis(100)))
            .expect("set timeout");

        // No traffic is sent to us; the iterator simply ends on timeout.
        assert_eq!(rx.udp_packets().count(), 0);
    }
}
