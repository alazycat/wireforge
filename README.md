# WireForge

A pure Rust network packet processing library — zero-copy parsers, builder-based constructors, Linux raw socket I/O, and application-layer protocol support.

## Features

- **Zero-copy parsing** — all parsers borrow from the input buffer, no heap allocation on the hot path
- **Builder API** — ergonomic construction with automatic checksum computation
- **L2–L4 protocols** — Ethernet, 802.1Q VLAN, ARP, IPv4, IPv6 (with extension headers), TCP (with options), UDP, ICMP/ICMPv6/NDP
- **Application-layer protocols** — DNS, DHCP, NTP, HTTP/1.1 (in `wireforge-app`)
- **pcap/pcapng I/O** — read and write packet capture files, pure Rust, no libpcap dependency
- **no_std core** — `wireforge-core` works without the standard library (requires `alloc`)
- **Raw socket I/O** — AF_PACKET L2 and SOCK_RAW L3 on Linux (`wireforge-io`)
- **Fuzz + benchmarks** — cargo-fuzz targets and criterion benchmarks for all protocols

## Architecture

```
wireforge-io        (Linux raw socket I/O)
     └── wireforge-packet  (Packet enum, protocol dispatch)
          └── wireforge-core   (Zerocopy parsers, builders, types, checksums)

wireforge-app       (DNS, DHCP, NTP, HTTP, pcap I/O)
     └── wireforge-packet
```

## Quick Start

```rust
use wireforge_core::ether::EthernetPacket;

let frame: &[u8] = &[/* raw bytes */];
if let Some(eth) = EthernetPacket::new(frame) {
    println!("EtherType: {:?}", eth.ethertype());
}
```

```rust
// DNS query construction
use wireforge_app::dns::builder::DnsPacketBuilder;
use wireforge_app::dns::types::{DnsType, DnsClass};

let query = DnsPacketBuilder::query()
    .add_question("example.com", DnsType::A, DnsClass::IN)
    .build();
```

```rust
// Read a pcap file
use wireforge_app::pcap::PcapReader;
use std::fs::File;

let reader = PcapReader::new(File::open("capture.pcap")?)?;
for packet in reader {
    let (ts, data) = packet?;
    println!("Packet at {:?}: {} bytes", ts, data.len());
}
```

## Platform Support

- **All platforms**: `wireforge-core`, `wireforge-packet`, `wireforge-app`
- **Linux only**: `wireforge-io` (raw socket send/receive)

## License

MIT
