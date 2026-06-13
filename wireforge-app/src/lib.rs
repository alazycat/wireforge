//! WireForge App — application-layer protocol parsing, construction, and pcap I/O.
//!
//! This crate provides:
//! - DNS message parser and builder (RFC 1035)
//! - DHCPv4 message parser and builder (RFC 2131/2132)
//! - NTPv4 packet parser (RFC 5905)
//! - HTTP/1.1 request/response line parser
//! - TLS ClientHello parser with SNI extraction
//! - SSH banner and key exchange init parser
//! - MQTT 3.1.1/5.0 parser and builder
//! - Modbus TCP parser
//! - pcap and pcapng file reader/writer

pub mod dns;
pub mod dhcp;
pub mod ntp;
pub mod http;
pub mod tls;
pub mod ssh;
pub mod mqtt;
pub mod modbus;
pub mod pcap;
