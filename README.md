# WireForge

A pure Rust network packet processing library — zero-copy parsers, builder-based constructors, and Linux raw socket I/O.

## Features

- **Zero-copy parsing** — all parsers borrow from the input buffer, no heap allocation on the hot path
- **Builder API** — ergonomic construction with automatic checksum computation
- **Protocol coverage** — Ethernet, 802.1Q VLAN, ARP, IPv4, IPv6 (with extension headers), TCP, UDP, ICMP, ICMPv6/NDP
- **no_std core** — `wireforge-core` works without the standard library (requires `alloc`)
- **Raw socket I/O** — AF_PACKET L2 and SOCK_RAW L3 on Linux

## Architecture

```
wireforge-io        (Linux raw socket I/O)
    └── wireforge-packet  (Packet enum, protocol dispatch)
        └── wireforge-core   (Zerocopy parsers, builders, types, checksums)
```

## Quick Start

```rust
use wireforge_core::ether::EthernetPacket;

let frame: &[u8] = &[/* raw bytes */];
if let Some(eth) = EthernetPacket::new(frame) {
    println!("EtherType: {:?}", eth.ethertype());
    println!("Payload: {:?}", eth.payload());
}
```

See `examples/` for more complete usage.

## Platform Support

- **All platforms**: `wireforge-core` and `wireforge-packet` (parsing + building)
- **Linux only**: `wireforge-io` (raw socket send/receive)

## License

MIT
