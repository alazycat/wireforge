//! Application-layer packet dispatch for WireForge.
//!
//! This module provides a unified [`AppPacket`] enum covering the
//! application-layer protocols added in v1.1 and v1.2, plus helper functions
//! to dispatch a TCP or UDP payload to the correct parser based on the
//! well-known port.

use crate::llmnr::LlmnrPacket;
use crate::mdns::MdnsPacket;
use crate::modbus::ModbusTcpPacket;
use crate::mqtt::MqttPacket;
use crate::netbios::NetbiosNsPacket;
use crate::radius::RadiusPacket;
use crate::rdp::TpktHeader;
use crate::smb2::Smb2Header;
use crate::ssh::SshPacket;
use crate::tls::TlsClientHello;

/// Standard IANA ports used for application-layer dispatch.
mod ports {
    pub const TLS: u16 = 443;
    pub const SSH: u16 = 22;
    pub const MQTT: u16 = 1883;
    pub const MODBUS: u16 = 502;
    pub const SMB2: u16 = 445;
    pub const RDP: u16 = 3389;
    pub const RADIUS_AUTH: u16 = 1812;
    pub const RADIUS_ACCT: u16 = 1813;
    pub const MDNS: u16 = 5353;
    pub const LLMNR: u16 = 5355;
    pub const NETBIOS_NS: u16 = 137;
}

/// Unified application-layer packet enum covering v1.1 and v1.2 protocols.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum AppPacket<'a> {
    Tls(TlsClientHello<'a>),
    Ssh(SshPacket<'a>),
    Mqtt(MqttPacket<'a>),
    Modbus(ModbusTcpPacket<'a>),
    Radius(RadiusPacket<'a>),
    Mdns(MdnsPacket<'a>),
    Llmnr(LlmnrPacket<'a>),
    Netbios(NetbiosNsPacket<'a>),
    Smb2(Smb2Header<'a>),
    Rdp(TpktHeader<'a>),
}

impl<'a> AppPacket<'a> {
    /// Human-readable protocol name.
    pub fn protocol_name(&self) -> &'static str {
        match self {
            AppPacket::Tls(_) => "TLS",
            AppPacket::Ssh(_) => "SSH",
            AppPacket::Mqtt(_) => "MQTT",
            AppPacket::Modbus(_) => "ModbusTCP",
            AppPacket::Radius(_) => "RADIUS",
            AppPacket::Mdns(_) => "mDNS",
            AppPacket::Llmnr(_) => "LLMNR",
            AppPacket::Netbios(_) => "NetBIOS-NS",
            AppPacket::Smb2(_) => "SMB2",
            AppPacket::Rdp(_) => "RDP",
        }
    }
}

macro_rules! from_impl {
    ($variant:ident, $type:ty) => {
        impl<'a> From<$type> for AppPacket<'a> {
            fn from(p: $type) -> Self {
                AppPacket::$variant(p)
            }
        }
    };
}

from_impl!(Tls, TlsClientHello<'a>);
from_impl!(Ssh, SshPacket<'a>);
from_impl!(Mqtt, MqttPacket<'a>);
from_impl!(Modbus, ModbusTcpPacket<'a>);
from_impl!(Radius, RadiusPacket<'a>);
from_impl!(Mdns, MdnsPacket<'a>);
from_impl!(Llmnr, LlmnrPacket<'a>);
from_impl!(Netbios, NetbiosNsPacket<'a>);
from_impl!(Smb2, Smb2Header<'a>);
from_impl!(Rdp, TpktHeader<'a>);

#[inline]
fn port_matches(src: u16, dst: u16, port: u16) -> bool {
    src == port || dst == port
}

/// Dispatch a TCP payload to an application-layer parser based on port numbers.
///
/// Only the standard ports for TLS, SSH, MQTT, Modbus TCP, SMB2, and RDP are
/// recognized. The payload is parsed only when the port matches; if parsing
/// fails, `None` is returned.
///
/// # Example
///
/// ```rust,ignore
/// use wireforge_app::app_packet::parse_tcp_application;
///
/// let pkt = parse_tcp_application(&buf, 54321, 443).expect("TLS packet");
/// println!("{}", pkt.protocol_name());
/// ```
pub fn parse_tcp_application(buf: &[u8], src_port: u16, dst_port: u16) -> Option<AppPacket<'_>> {
    if port_matches(src_port, dst_port, ports::TLS) {
        return TlsClientHello::parse(buf).map(AppPacket::Tls);
    }
    if port_matches(src_port, dst_port, ports::SSH) {
        return SshPacket::parse(buf).map(AppPacket::Ssh);
    }
    if port_matches(src_port, dst_port, ports::MQTT) {
        return MqttPacket::parse(buf).map(AppPacket::Mqtt);
    }
    if port_matches(src_port, dst_port, ports::MODBUS) {
        return ModbusTcpPacket::new(buf).map(AppPacket::Modbus);
    }
    if port_matches(src_port, dst_port, ports::SMB2) {
        return Smb2Header::parse(buf).map(AppPacket::Smb2);
    }
    if port_matches(src_port, dst_port, ports::RDP) {
        return TpktHeader::parse(buf).map(AppPacket::Rdp);
    }
    None
}

/// Dispatch a UDP payload to an application-layer parser based on port numbers.
///
/// Recognizes RADIUS, mDNS, LLMNR, and NetBIOS-NS on their standard ports.
pub fn parse_udp_application(buf: &[u8], src_port: u16, dst_port: u16) -> Option<AppPacket<'_>> {
    if port_matches(src_port, dst_port, ports::RADIUS_AUTH)
        || port_matches(src_port, dst_port, ports::RADIUS_ACCT)
    {
        return RadiusPacket::new(buf).map(AppPacket::Radius);
    }
    if port_matches(src_port, dst_port, ports::MDNS) {
        return MdnsPacket::new(buf).map(AppPacket::Mdns);
    }
    if port_matches(src_port, dst_port, ports::LLMNR) {
        return LlmnrPacket::new(buf).map(AppPacket::Llmnr);
    }
    if port_matches(src_port, dst_port, ports::NETBIOS_NS) {
        return NetbiosNsPacket::new(buf).map(AppPacket::Netbios);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::builder::DnsPacketBuilder;
    use crate::dns::types::{DnsClass, DnsType};
    use crate::mqtt::MqttPacketBuilder;

    #[test]
    fn dispatch_tls_on_443() {
        let data = &[
            0x16, 0x03, 0x01, 0x00, 0x44, // record: handshake, len=68
            0x01, 0x00, 0x00, 0x40,       // handshake: client_hello, len=64
            0x03, 0x03,                   // client_version TLS 1.2 (legacy)
            // random (32 bytes)
            0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
            0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
            0x00,                         // session_id_len = 0
            0x00, 0x02, 0x13, 0x01,       // cipher_suites: TLS_AES_128_GCM
            0x01, 0x00,                   // compression: null
            0x00, 0x07,                   // extensions length = 7
            0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, // supported_versions: TLS 1.3
        ];
        let pkt = parse_tcp_application(data, 54321, 443).unwrap();
        assert!(matches!(pkt, AppPacket::Tls(_)));
        assert_eq!(pkt.protocol_name(), "TLS");
    }

    #[test]
    fn dispatch_ssh_on_22() {
        let data = b"SSH-2.0-OpenSSH_8.9\r\n";
        let pkt = parse_tcp_application(data, 22, 54321).unwrap();
        assert!(matches!(pkt, AppPacket::Ssh(SshPacket::Banner(_))));
        assert_eq!(pkt.protocol_name(), "SSH");
    }

    #[test]
    fn dispatch_mqtt_on_1883() {
        let data = MqttPacketBuilder::connect("sensor1");
        let pkt = parse_tcp_application(&data, 1883, 12345).unwrap();
        assert!(matches!(pkt, AppPacket::Mqtt(_)));
    }

    #[test]
    fn dispatch_modbus_on_502() {
        let data = &[0x00u8, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0A];
        let pkt = parse_tcp_application(data, 502, 12345).unwrap();
        assert!(matches!(pkt, AppPacket::Modbus(_)));
    }

    #[test]
    fn dispatch_smb2_on_445() {
        let mut hdr = [0u8; 64];
        hdr[4..8].copy_from_slice(b"\xfeSMB");
        let pkt = parse_tcp_application(&hdr, 445, 12345).unwrap();
        assert!(matches!(pkt, AppPacket::Smb2(_)));
    }

    #[test]
    fn dispatch_rdp_on_3389() {
        let data = [0x03u8, 0x00, 0x00, 0x2C, 0xE0];
        let pkt = parse_tcp_application(&data, 3389, 12345).unwrap();
        assert!(matches!(pkt, AppPacket::Rdp(_)));
    }

    #[test]
    fn dispatch_radius_on_1812() {
        let pkt = vec![1u8, 0, 0, 20, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let parsed = parse_udp_application(&pkt, 1812, 12345).unwrap();
        assert!(matches!(parsed, AppPacket::Radius(_)));
    }

    #[test]
    fn dispatch_mdns_on_5353() {
        let q = DnsPacketBuilder::query()
            .add_question("_http._tcp.local", DnsType::PTR, DnsClass::IN)
            .build();
        let pkt = parse_udp_application(&q, 5353, 12345).unwrap();
        assert!(matches!(pkt, AppPacket::Mdns(_)));
    }

    #[test]
    fn dispatch_llmnr_on_5355() {
        let q = DnsPacketBuilder::query()
            .add_question("wpad", DnsType::A, DnsClass::IN)
            .build();
        let pkt = parse_udp_application(&q, 12345, 5355).unwrap();
        assert!(matches!(pkt, AppPacket::Llmnr(_)));
    }

    #[test]
    fn dispatch_netbios_on_137() {
        let mut data = vec![0x00, 0x01, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut enc = [0u8; 32];
        let name = b"HOST1           ";
        for (i, b) in name.iter().enumerate() {
            enc[i * 2] = (b >> 4) + 0x41;
            enc[i * 2 + 1] = (b & 0x0F) + 0x41;
        }
        data.extend_from_slice(&enc);
        data.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        let pkt = parse_udp_application(&data, 137, 12345).unwrap();
        assert!(matches!(pkt, AppPacket::Netbios(_)));
    }

    #[test]
    fn unknown_tcp_port_returns_none() {
        assert!(parse_tcp_application(b"foo", 12345, 54321).is_none());
    }

    #[test]
    fn unknown_udp_port_returns_none() {
        assert!(parse_udp_application(b"foo", 12345, 54321).is_none());
    }

    #[test]
    fn known_port_bad_data_returns_none() {
        assert!(parse_tcp_application(b"not tls", 443, 12345).is_none());
        assert!(parse_udp_application(&[0u8; 10], 1812, 12345).is_none());
    }
}
