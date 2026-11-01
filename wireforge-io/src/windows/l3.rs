//! Windows L3 I/O: IPv4/IPv6 raw sockets for sending, and Npcap for IPv6
//! receive (Windows raw IPv6 sockets do not deliver the IPv6 header).

use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};
use std::os::raw::c_int;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::ipv6::Ipv6Packet;
use wireforge_core::types::IpProtocol;

use crate::common;
use crate::error::IoError;
use crate::traits::{L2Reader, L3Reader, L3ReaderV6, L3Writer, L3WriterV6};

use super::npcap::NpcapReader;

// Windows socket constants
const SOL_SOCKET: i32 = 0xFFFF;
const SO_RCVTIMEO: i32 = 0x1006;
const IPPROTO_IP: i32 = 0;
const IP_HDRINCL: i32 = 2;

extern "system" {
    fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
}

/// Set `SO_RCVTIMEO` (a `DWORD` in milliseconds on Windows).
fn set_recv_timeout(sock: &Socket, dur: Option<Duration>) -> Result<(), IoError> {
    use std::os::windows::io::AsRawSocket;
    let fd = sock.as_raw_socket() as usize;
    let timeout_ms: u32 = dur.map(|d| d.as_millis() as u32).unwrap_or(0);
    unsafe {
        let ret = setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout_ms as *const _ as *const u8,
            std::mem::size_of::<u32>() as i32,
        );
        if ret != 0 {
            return Err(IoError::Socket(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Windows raw socket L3 receiver.
pub struct WinL3Receiver {
    sock: Socket,
}

impl WinL3Receiver {
    pub fn new(protocol: IpProtocol) -> Result<Self, IoError> {
        let proto = i32::from(u8::from(protocol));
        let sock = Socket::new(Domain::IPV4, Type::from(3i32), Some(Protocol::from(proto)))?; // SOCK_RAW = 3
        let local = socket2::SockAddr::from(std::net::SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            0,
        )));
        sock.bind(&local)?;
        Ok(Self { sock })
    }

    /// Receive a single IPv4 packet and parse it.
    pub fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> {
        let mut buf = [MaybeUninit::uninit(); 65536];
        let n = match self.sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => return Err(common::recv_error(e)),
        };
        // SAFETY: the first n bytes are initialized by recv
        let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        Ipv4Packet::new(data).ok_or(IoError::Parse("invalid IPv4 packet"))
    }

    /// Enable or disable IP_HDRINCL (header included in send).
    pub fn set_header_included(&mut self, on: bool) -> Result<(), IoError> {
        use std::os::windows::io::AsRawSocket;
        let fd = self.sock.as_raw_socket() as usize;
        let val: c_int = if on { 1 } else { 0 };
        unsafe {
            let ret = setsockopt(
                fd,
                IPPROTO_IP,
                IP_HDRINCL,
                &val as *const _ as *const u8,
                std::mem::size_of::<c_int>() as i32,
            );
            if ret != 0 {
                return Err(IoError::Socket(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    /// Set receive timeout (DWORD milliseconds on Windows).
    pub fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        set_recv_timeout(&self.sock, dur)
    }
}

// Trait impl delegates to inherent methods
impl L3Reader for WinL3Receiver {
    fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> {
        self.recv()
    }
    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        self.set_timeout(dur)
    }
    fn set_header_included(&mut self, on: bool) -> Result<(), IoError> {
        self.set_header_included(on)
    }
}

/// Windows raw socket L3 sender.
pub struct WinL3Sender {
    sock: Socket,
}

impl WinL3Sender {
    pub fn new() -> Result<Self, IoError> {
        let sock = Socket::new(Domain::IPV4, Type::from(3i32), Some(Protocol::from(255)))?; // SOCK_RAW = 3
        Ok(Self { sock })
    }

    /// Send an IPv4 packet to the given destination.
    pub fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError> {
        let addr = socket2::SockAddr::from(std::net::SocketAddr::V4(dst));
        let n = self.sock.send_to(packet, &addr)?;
        Ok(n)
    }
}

impl L3Writer for WinL3Sender {
    fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError> {
        self.send_to(packet, dst)
    }
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/// Windows IPv6 L3 receiver backed by Npcap.
///
/// Windows raw IPv6 sockets never include the IPv6 header in received data,
/// regardless of `IPV6_HDRINCL`. This receiver captures Ethernet frames via
/// Npcap and extracts the IPv6 packet, so it requires Npcap to be installed.
pub struct WinL3ReceiverV6 {
    reader: NpcapReader,
    protocol: IpProtocol,
    datalink: c_int,
    buf: Vec<u8>,
}

impl WinL3ReceiverV6 {
    /// Open the first Npcap device, preferring a loopback adapter.
    pub fn new(protocol: IpProtocol) -> Result<Self, IoError> {
        let devices = super::npcap::npcap_devices()?;
        let device = devices
            .iter()
            .find(|device| {
                device.name.contains("Loopback")
                    || device
                        .description
                        .as_deref()
                        .is_some_and(|desc| desc.contains("Loopback"))
            })
            .or_else(|| devices.first())
            .ok_or_else(|| IoError::InterfaceNotFound("no Npcap devices found".into()))?;
        Self::with_interface(&device.name, protocol)
    }

    /// Open a specific Npcap device.
    pub fn with_interface(ifname: &str, protocol: IpProtocol) -> Result<Self, IoError> {
        let reader = NpcapReader::new(ifname)?;
        let datalink = reader.datalink()?;
        Ok(Self {
            reader,
            protocol,
            datalink,
            buf: Vec::new(),
        })
    }

    /// Receive the next IPv6 packet whose final protocol matches.
    pub fn recv(&mut self) -> Result<Ipv6Packet<'_>, IoError> {
        self.read_matching()?;
        Ipv6Packet::new(&self.buf).ok_or(IoError::Parse("invalid IPv6 packet"))
    }

    /// Fill `self.buf` with the next matching IPv6 packet.
    fn read_matching(&mut self) -> Result<(), IoError> {
        loop {
            let frame = self.reader.recv_raw()?;
            let Some(payload) = ipv6_payload(self.datalink, frame) else {
                continue;
            };
            let Some(packet) = Ipv6Packet::new(payload) else {
                continue;
            };
            if packet.final_protocol() != self.protocol {
                continue;
            }
            self.buf.clear();
            self.buf.extend_from_slice(payload);
            return Ok(());
        }
    }

    /// No-op: Npcap captures the full IPv6 header.
    pub fn set_header_included(&mut self, _on: bool) -> Result<(), IoError> {
        Ok(())
    }

    /// Set receive timeout.
    pub fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        self.reader.set_timeout(dur)
    }
}

impl L3ReaderV6 for WinL3ReceiverV6 {
    fn recv(&mut self) -> Result<Ipv6Packet<'_>, IoError> {
        self.recv()
    }
    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        self.set_timeout(dur)
    }
    fn set_header_included(&mut self, on: bool) -> Result<(), IoError> {
        self.set_header_included(on)
    }
}

/// Windows raw socket L3 IPv6 sender.
pub struct WinL3SenderV6 {
    sock: Socket,
}

impl WinL3SenderV6 {
    pub fn new() -> Result<Self, IoError> {
        let sock = Socket::new(Domain::IPV6, Type::from(3i32), Some(Protocol::from(255)))?; // SOCK_RAW = 3, IPPROTO_RAW = 255
        sock.set_header_included_v6(true)?;
        Ok(Self { sock })
    }

    /// Send an IPv6 packet to the given destination.
    pub fn send_to(&self, packet: &[u8], dst: SocketAddrV6) -> Result<usize, IoError> {
        let addr = socket2::SockAddr::from(std::net::SocketAddr::V6(dst));
        let n = self.sock.send_to(packet, &addr)?;
        Ok(n)
    }
}

impl L3WriterV6 for WinL3SenderV6 {
    fn send_to(&self, packet: &[u8], dst: SocketAddrV6) -> Result<usize, IoError> {
        self.send_to(packet, dst)
    }
}

// Npcap link-layer types (`DLT_*`).
const DLT_NULL: c_int = 0;
const DLT_EN10MB: c_int = 1;
const DLT_RAW: c_int = 12;
const DLT_RAW_ALT: c_int = 101;
const DLT_LOOP: c_int = 108;

/// Extract the IPv6 packet from a captured frame based on its link-layer type.
fn ipv6_payload(datalink: c_int, frame: &[u8]) -> Option<&[u8]> {
    match datalink {
        DLT_EN10MB => {
            if frame.len() >= 14 && frame[12..14] == [0x86, 0xDD] {
                Some(&frame[14..])
            } else {
                None
            }
        }
        // DLT_NULL / DLT_LOOP: a 4-byte address family, then the IP packet.
        DLT_NULL | DLT_LOOP => {
            if frame.len() > 4 && frame[4] >> 4 == 6 {
                Some(&frame[4..])
            } else {
                None
            }
        }
        // DLT_RAW: the frame starts with the IP header.
        DLT_RAW | DLT_RAW_ALT => {
            if !frame.is_empty() && frame[0] >> 4 == 6 {
                Some(frame)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use wireforge_core::icmp::Icmpv6PacketBuilder;
    use wireforge_core::ipv6::Ipv6PacketBuilder;

    #[test]
    fn ipv6_payload_handles_dlt_variants() {
        let mut ipv6 = vec![0u8; 40];
        ipv6[0] = 0x60;

        // DLT_NULL: 4-byte address family followed by the IPv6 header.
        let mut null = vec![0x18, 0x00, 0x00, 0x00];
        null.extend_from_slice(&ipv6);
        assert_eq!(ipv6_payload(DLT_NULL, &null), Some(ipv6.as_slice()));

        // DLT_EN10MB: 12-byte MAC header, 0x86DD, IPv6 header.
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x86, 0xDD]);
        eth.extend_from_slice(&ipv6);
        assert_eq!(ipv6_payload(DLT_EN10MB, &eth), Some(ipv6.as_slice()));

        // DLT_RAW: IPv6 header at offset 0.
        assert_eq!(ipv6_payload(DLT_RAW, &ipv6), Some(ipv6.as_slice()));

        // IPv4 frames are rejected.
        let ipv4 = [0x02, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x14];
        assert_eq!(ipv6_payload(DLT_NULL, &ipv4), None);

        // Unknown DLTs are rejected.
        assert_eq!(ipv6_payload(999, &ipv6), None);
    }

    #[test]
    #[ignore = "requires Administrator to open raw IPv4 sockets"]
    fn l3_v4_opens_icmp_socket_and_times_out() {
        let mut rx = WinL3Receiver::new(IpProtocol::Icmp).expect("open ICMP raw socket");
        rx.set_timeout(Some(Duration::from_millis(50)))
            .expect("set timeout");

        match rx.recv() {
            Ok(_) | Err(IoError::Timeout) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    #[ignore = "requires Npcap to capture IPv6 headers on Windows"]
    fn l3_v6_opens_icmpv6_socket_and_times_out() {
        let mut rx = WinL3ReceiverV6::new(IpProtocol::Icmpv6).expect("open ICMPv6 raw socket");
        rx.set_timeout(Some(Duration::from_millis(50)))
            .expect("set timeout");

        match rx.recv() {
            Ok(_) | Err(IoError::Timeout) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    #[ignore = "requires Npcap and Administrator (raw IPv6 send)"]
    fn l3_v6_send_and_receive_echo_request() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;

        let mut rx = WinL3ReceiverV6::new(IpProtocol::Icmpv6).expect("open ICMPv6 raw socket");
        rx.set_timeout(Some(Duration::from_millis(500)))
            .expect("set timeout");

        let icmp = Icmpv6PacketBuilder::echo_request()
            .identifier(0x1234)
            .sequence_number(1)
            .body(b"wireforge-v6")
            .build(src, dst);
        let ipv6 = Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .next_header(IpProtocol::Icmpv6)
            .hop_limit(64)
            .payload(&icmp)
            .expect("payload should fit")
            .build();

        let tx = match WinL3SenderV6::new() {
            Ok(tx) => tx,
            Err(IoError::Socket(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping: raw IPv6 send requires Administrator");
                return;
            }
            Err(e) => panic!("open IPv6 raw sender: {e}"),
        };
        tx.send_to(&ipv6, SocketAddrV6::new(dst, 0, 0, 0))
            .expect("send IPv6 packet");

        let mut received = false;
        for _ in 0..8 {
            match rx.recv() {
                Ok(packet) => {
                    if packet.source() == src && packet.destination() == dst {
                        received = true;
                        break;
                    }
                }
                Err(IoError::Timeout) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert!(received, "did not receive the sent IPv6 packet");
    }

    #[test]
    #[ignore = "requires Npcap to capture IPv6 headers on Windows"]
    fn l3_v6_captures_loopback_ping() {
        let mut rx = WinL3ReceiverV6::new(IpProtocol::Icmpv6).expect("open Npcap IPv6 receiver");
        rx.set_timeout(Some(Duration::from_millis(500)))
            .expect("set timeout");

        let mut child = std::process::Command::new("ping")
            .args(["-6", "-n", "2", "::1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn ping");

        let mut captured = false;
        for _ in 0..10 {
            match rx.recv() {
                Ok(_) => {
                    captured = true;
                    break;
                }
                Err(IoError::Timeout) => continue,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        let _ = child.wait();
        assert!(captured, "did not capture ICMPv6 loopback traffic");
    }
}
