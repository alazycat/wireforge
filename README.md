# WireForge

A pure Rust network packet processing library — a complete replacement for libpnet.

[![CI](https://github.com/wireforge/wireforge/actions/workflows/ci.yml/badge.svg)](https://github.com/wireforge/wireforge/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-1.1.0-blue)
![MSRV](https://img.shields.io/badge/rustc-1.75+-orange)

## Architecture

```
wireforge-core       (Zero-copy parsers, builders, types, checksums)
├── wireforge-packet  (Unified Packet enum and L2–L4 dispatch)
├── wireforge-app     (Application-layer protocols and pcap I/O)
└── wireforge-io      (Cross-platform raw socket I/O)
```

`wireforge-app` provides its own [`AppPacket`] enum for application-layer
protocol dispatch. It intentionally does not depend on `wireforge-packet`,
keeping the two dispatch layers independent.

## Quick Start

```bash
cargo add wireforge-core wireforge-packet wireforge-io wireforge-app
```

```rust
// Parse an Ethernet frame
use wireforge_core::ether::EthernetPacket;
let eth = EthernetPacket::new(&frame_bytes).unwrap();
println!("EtherType: {:?}", eth.ethertype());

// Build a DNS query
use wireforge_app::dns::builder::DnsPacketBuilder;
use wireforge_app::dns::types::{DnsType, DnsClass};
let query = DnsPacketBuilder::query()
    .add_question("example.com", DnsType::A, DnsClass::IN)
    .build();

// Capture packets (cross-platform)
use wireforge_io::{DefaultL2Reader, traits::L2Reader};
let mut rx = DefaultL2Reader::new("eth0")?;
let eth = rx.recv()?;
```

### Application-layer dispatch

```rust
use wireforge_app::{AppPacket, app_packet::{parse_tcp_application, parse_udp_application}};

// Classify a TCP payload by port
if let Some(pkt) = parse_tcp_application(tcp_payload, src_port, 443) {
    println!("{}: {:?}", pkt.protocol_name(), pkt);
}

// Classify a UDP payload by port
if let Some(pkt) = parse_udp_application(udp_payload, src_port, 5353) {
    println!("{}: {:?}", pkt.protocol_name(), pkt);
}
```

## Protocol Coverage

| Layer | Protocols | Crate |
|-------|-----------|-------|
| L2 | Ethernet II, 802.1Q VLAN, ARP | wireforge-core |
| L3 | IPv4, IPv6 (+ ext headers), ICMP/ICMPv6/NDP, IGMP, GRE | wireforge-core |
| L4 | TCP (+ options), UDP | wireforge-core |
| App | DNS, DHCP, NTP, HTTP/1.1, TLS ClientHello, SSH, MQTT, Modbus TCP, RADIUS, mDNS, LLMNR, NetBIOS-NS, SMB2 Negotiate, RDP | wireforge-app |
| I/O | pcap/pcapng read/write | wireforge-app |

## Platform Support

| Platform | L2 Capture | L3 Capture | Backend |
|----------|------------|------------|---------|
| Linux | AF_PACKET | raw socket | socket2 + libc |
| macOS | BPF | raw socket | /dev/bpf + libc |
| Windows | NPcap | raw socket | wpcap.dll FFI + WinSock |

## Migrating from libpnet

WireForge is a drop-in replacement for libpnet. See the **[Migration Guide](docs/migration-from-libpnet.md)** for detailed API comparison and code examples.

## Community

- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

MIT
