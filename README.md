# WireForge

A pure Rust network packet processing library — a complete replacement for libpnet.

[![CI](https://github.com/wireforge/wireforge/actions/workflows/ci.yml/badge.svg)](https://github.com/wireforge/wireforge/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![MSRV](https://img.shields.io/badge/rustc-1.75+-orange)

## Architecture

```
wireforge-io        (Cross-platform raw socket I/O)
    └── wireforge-packet  (Packet enum, protocol dispatch)
        └── wireforge-core   (Zerocopy parsers, builders, types, checksums)

wireforge-app       (DNS, DHCP, NTP, HTTP, pcap I/O)
    └── wireforge-packet
```

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

## Protocol Coverage

| Layer | Protocols | Crate |
|-------|-----------|-------|
| L2 | Ethernet II, 802.1Q VLAN, ARP | wireforge-core |
| L3 | IPv4, IPv6 (+ ext headers), ICMP/ICMPv6/NDP, IGMP, GRE | wireforge-core |
| L4 | TCP (+ options), UDP | wireforge-core |
| App | DNS, DHCP, NTP, HTTP/1.1 | wireforge-app |
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
