# Changelog

## [1.1.0] — 2026-07-10

### Added (wireforge-app)

- TLS ClientHello parser with SNI and supported_versions extraction
- SSH banner and key exchange init (`SshPacket`) parser
- MQTT 3.1.1/5.0 parser and builder
- Modbus TCP parser (MBAP header + function code dispatch)
- RADIUS authentication/accounting parser with AVP iteration
- mDNS parser (DNS wire format wrapper)
- LLMNR parser (DNS wire format wrapper)
- NetBIOS-NS name query parser with nibble name decoding
- SMB2 header parser (covers all SMB2 commands on port 445)
- RDP TPKT header parser
- `AppPacket` unified application-layer enum with `parse_tcp_application` and `parse_udp_application` port-based dispatch

### Changed (wireforge-packet)

- `Packet` enum is now `#[non_exhaustive]` to allow future L2–L4 protocol variants without breaking downstream exhaustive matches

### Fixed

- Corrected README architecture diagram and version badge to match the current crate dependency graph

---

## [1.0.0] — 2026-06-13

### Added (wireforge-core)
- IGMPv1/v2/v3 packet parser and builder
- GRE (RFC 2784 + RFC 2890) tunnel parser and builder with Key/Sequence/Checksum options
- IPv6 extension header chain parser with 8-layer depth limit
- TCP option parsing (MSS, Window Scale, SACK, Timestamp) with iterator
- ICMPv6/NDP message types (NS, NA, RS, RA)
- ArpHardwareType, ArpOperation, IpProtocol, EtherType enums with From/Into

### Added (wireforge-app)
- DNS message parser and builder with QNAME label compression
- DHCPv4 parser and builder with Option Overload support
- NTPv4 packet parser (RFC 5905)
- HTTP/1.1 request/response line parser with header iteration
- pcap reader/writer (full pcap format)
- pcapng reader/writer (SHB + IDB + EPB blocks)

### Added (wireforge-io)
- Cross-platform L2Reader/L2Writer/L3Reader/L3Writer traits
- Linux: AF_PACKET L2 + raw socket L3
- Windows: NPcap L2 capture via dynamic FFI to wpcap.dll
- Windows: raw socket L3
- macOS: BPF L2 + raw socket L3 (stubs, pending full implementation)
- list_interfaces() — Linux (SIOCGIFCONF), macOS (getifaddrs), Windows (IP Helper API)
- Interface struct with name, MAC, IPs, loopback, up status
- IoError with platform-specific variants

### Added (wireforge-packet)
- Packet enum with From impls for all protocol types
- parse_ethernet_frame(), parse_ipv4_payload(), parse_ipv6_payload() dispatch functions

### Added (infra)
- 13 protocol fuzz targets (cargo-fuzz)
- Criterion benchmarks (parse, build, checksum)
- Cross-platform examples (packet dump, packet send, list interfaces)
- CI matrix (ubuntu-latest, macos-latest, windows-latest)
- libpnet → WireForge migration guide

### Changed
- wireforge-io: from concrete structs to trait-based L2Reader/L2Writer/L3Reader/L3Writer
- IoError: added InterfaceNotFound, PermissionDenied, Bpf, Npcap, UnsupportedPlatform
- wireforge-io: platform code reorganized into linux/ macos/ windows/ subdirectories
- wireforge-core: lib.rs module declarations restructured

### Fixed
- Clippy warnings across all crates (unused imports, identity operations, collapsible if)
---
