# WireForge

A pure Rust network packet processing library — zero-copy parsing and
building for common network protocols, with cross-platform capture I/O
and pcap/pcapng file support.

> **Status vs libpnet:** WireForge covers the packet-parsing subset of
> libpnet — plus a lightweight `define_protocol!` macro for custom
> protocols, a `pnet_transport`-style channel API, a much deeper
> application layer, and pcap file I/O — but it is **not yet** a complete
> replacement: platform I/O is only fully functional on Linux, and
> libpnet's per-field `Mutable*Packet` setters have no equivalent here.
> See **[libpnet parity gap analysis](docs/libpnet-parity-gap-analysis.md)**
> for an honest, module-by-module comparison.

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
| L2 | Ethernet II, 802.1Q VLAN, ARP, Linux cooked capture (SLL/SLL2), MAC control (PAUSE/PFC) | wireforge-core |
| Tunnel / capture formats | VXLAN, USBPcap headers | wireforge-core |
| L3 | IPv4 (+ options), IPv6 (+ ext headers), ICMP/ICMPv6/NDP, IGMP, GRE | wireforge-core |
| L4 | TCP (+ options), UDP | wireforge-core |
| Custom protocols | `define_protocol!` declarative macro (parser + builder + `Packet` trait) | wireforge-core |
| App | DNS, DHCP, NTP, HTTP/1.1, TLS ClientHello, SSH, MQTT, Modbus TCP, RADIUS, mDNS, LLMNR, NetBIOS-NS, SMB2 Negotiate, RDP | wireforge-app |
| I/O | pcap/pcapng read/write | wireforge-app |
| Transport I/O | `pnet_transport`-style channel API (TCP/UDP/ICMP raw sockets, TTL/ECN, timeouts) | wireforge-io |

## Platform Support

| Platform | L2 Capture | L3 Capture | Backend |
|----------|------------|------------|---------|
| Linux | AF_PACKET | raw socket | socket2 + libc |
| macOS | not implemented | not implemented | (planned: /dev/bpf + libc) |
| Windows | NPcap (capture only) | raw socket | wpcap.dll FFI + WinSock |

### Current limitations

- **macOS** — the BPF and raw-socket backends are stubs; every
  `L2Reader`/`L3Reader` call currently returns `UnsupportedPlatform`.
- **Windows** — NPcap **capture** works (including promiscuous mode and
  timeouts via `NpcapReader::with_options`), but **sending** L2 frames is
  not implemented yet; L3 raw-socket send/receive works.
- **Linux** — fully functional (AF_PACKET L2 + raw-socket L3).

## Migrating from libpnet

See the **[Migration Guide](docs/migration-from-libpnet.md)** for a
detailed API comparison and code examples — including which parts of
libpnet carry over as-is and which are not equivalent yet.

## Community

- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

MIT
