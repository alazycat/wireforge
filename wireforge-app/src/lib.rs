//! WireForge App — application-layer protocol parsing, construction, and pcap I/O.
//!
//! This crate provides:
//! - DNS, mDNS, LLMNR — name resolution protocols
//! - DHCPv4 — network configuration
//! - NTPv4 — time synchronization
//! - HTTP/1.1 — request/response line parsing
//! - TLS ClientHello — SNI and extensions
//! - SSH — banner and key exchange
//! - MQTT 3.1.1/5.0 — IoT messaging
//! - Modbus TCP — industrial control
//! - RADIUS — authentication and accounting
//! - NetBIOS-NS — Windows name service
//! - SMB2 — file sharing negotiate
//! - RDP — remote desktop connection
//! - pcap/pcapng — packet capture I/O

pub mod dns;   pub mod dhcp;  pub mod ntp;
pub mod http;  pub mod tls;   pub mod ssh;
pub mod mqtt;  pub mod modbus;
pub mod radius;pub mod mdns;  pub mod llmnr;
pub mod netbios; pub mod smb2; pub mod rdp;
pub mod pcap;
