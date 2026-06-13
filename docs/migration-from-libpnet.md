# Migrating from libpnet to WireForge

This guide helps you migrate existing libpnet code to WireForge.

## Quick Reference — API Mapping

| libpnet (`pnet_packet`) | WireForge (`wireforge_core`) | Notes |
|--------------------------|------------------------------|-------|
| `ethernet::EthernetPacket::new(buf)` | `ether::EthernetPacket::new(buf)` | Same signature |
| `vlan::VlanPacket::new(buf)` | `vlan::VlanPacket::new(buf)` | Same signature |
| `arp::ArpPacket::new(buf)` | `arp::ArpPacket::new(buf)` | Same signature |
| `ipv4::Ipv4Packet::new(buf)` | `ipv4::Ipv4Packet::new(buf)` | Same signature |
| `ipv6::Ipv6Packet::new(buf)` | `ipv6::Ipv6Packet::new(buf)` | Same + ext header chain |
| `tcp::TcpPacket::new(buf)` | `tcp::TcpPacket::new(buf)` | Same + option iter |
| `udp::UdpPacket::new(buf)` | `udp::UdpPacket::new(buf)` | Same signature |
| `icmp::IcmpPacket::new(buf)` | `icmp::IcmpPacket::new(buf)` | Same + typed messages |
| `igmp::IgmpPacket::new(buf)` | `igmp::IgmpPacket::new(buf)` | Same + typed messages |
| `gre::GrePacket::new(buf)` | `gre::GrePacket::new(buf)` | Same + option accessors |

| libpnet (`pnet_datalink`) | WireForge (`wireforge_io`) | Notes |
|----------------------------|----------------------------|-------|
| `datalink::channel(ni)` | `DefaultL2Reader::new(ifname)` | WireForge trait, not tuple |
| `datalink::interfaces()` | `list_interfaces()` | Same purpose |
| `datalink::NetworkInterface` | `Interface` | Similar fields |

| Builder pattern | libpnet | WireForge |
|-----------------|---------|-----------|
| Create | `MutableEthernetPacket::new(buf)` | `EthernetPacketBuilder::new().build()` |
| Set fields | `packet.set_destination(mac)` | `builder.dst_mac(mac)` |
| Serialize | in-place mutation | `builder.build() -> Vec<u8>` |

---

## Example 1: Parsing Ethernet → IPv4 → TCP

### libpnet
```rust
use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;

let eth = EthernetPacket::new(bytes).unwrap();
if let Some(ip) = Ipv4Packet::new(eth.payload()) {
    if let Some(tcp) = TcpPacket::new(ip.payload()) {
        println!("{} → {} :{}", ip.get_source(), ip.get_destination(), tcp.get_destination());
    }
}
```

### WireForge
```rust
use wireforge_core::ether::EthernetPacket;
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::tcp::TcpPacket;

let eth = EthernetPacket::new(bytes).unwrap();
if let Some(ip) = Ipv4Packet::new(eth.payload()) {
    if let Some(tcp) = TcpPacket::new(ip.payload()) {
        println!("{} → {} :{}", ip.source(), ip.destination(), tcp.destination_port());
    }
}
```

> Note: WireForge uses `source()`/`destination()` (snake_case accessors) instead of `get_source()`/`get_destination()`.

---

## Example 2: Building a Packet

### libpnet
```rust
let mut buf = [0u8; 64];
let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
eth.set_destination([0xFF; 6].into());
eth.set_source([0x00; 6].into());
eth.set_ethertype(EtherTypes::Ipv4);
// ... manually write IPv4 + payload
```

### WireForge
```rust
use wireforge_core::ether::EthernetPacketBuilder;
use wireforge_core::types::EtherType;

let frame = EthernetPacketBuilder::new()
    .dst_mac([0xFF; 6])
    .src_mac([0x00; 6])
    .ethertype(EtherType::Ipv4)
    .payload(&ipv4_bytes)
    .build();
// frame is Vec<u8>, ready to send
```

> WireForge Builder pattern: chain setters → `build()` → owned `Vec<u8>`.
> libpnet `MutablePacket` pattern: pre-allocate buffer, mutate in-place.

---

## Example 3: Computing Checksums

### libpnet
```rust
use pnet_packet::ipv4::checksum;
let csum = checksum(&header_bytes);
```

### WireForge
```rust
use wireforge_core::util::internet_checksum;
let csum = internet_checksum(&header_bytes);
```

> WireForge additionally provides `pseudo_header_checksum()` for TCP/UDP pseudo-header checksums.
> Also: most Builders auto-compute checksums. No need to call checksum functions manually.

---

## Example 4: Capturing Packets

### libpnet
```rust
use pnet_datalink::{self, Channel};
let interfaces = datalink::interfaces();
let interface = interfaces.into_iter()
    .find(|iface| iface.name == "eth0").unwrap();
let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
    Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
    _ => panic!(),
};
loop {
    match rx.next() {
        Ok(packet) => { /* use EthernetPacket */ }
        Err(e) => panic!("error: {}", e),
    }
}
```

### WireForge
```rust
use wireforge_io::{DefaultL2Reader, list_interfaces, traits::L2Reader};
use wireforge_core::ether::EthernetPacket;

let mut rx = DefaultL2Reader::new("eth0")?;
rx.set_timeout(Some(Duration::from_secs(1)))?;
loop {
    match rx.recv() {
        Ok(eth) => println!("EtherType: {:?}", eth.ethertype()),
        Err(IoError::Timeout) => continue,
        Err(e) => { eprintln!("error: {}", e); break; }
    }
}
```

> WireForge uses traits (`L2Reader`) instead of enum-based `Channel`. No tuple destructuring needed.
> Cross-platform: same code works on Linux (AF_PACKET) and macOS (BPF).

---

## Example 5: Sending a Packet

### libpnet
```rust
let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
    Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
    _ => panic!(),
};
tx.send_to(&frame, None).unwrap();
```

### WireForge
```rust
use wireforge_io::{DefaultL2Writer, traits::L2Writer};

let tx = DefaultL2Writer::new("eth0")?;
let n = tx.send(&frame)?;
println!("sent {} bytes", n);
```

---

## Key Differences Summary

| Feature | libpnet | WireForge |
|---------|---------|-----------|
| Parser output | `Option<Packet>` | `Option<Packet>` (same) |
| Builder pattern | `MutablePacket` (in-place) | `Builder::build() -> Vec<u8>` |
| Cross-platform | 3 platforms | 3 platforms (L2 trait) |
| `no_std` core | No | Yes |
| Application-layer | None | DNS, DHCP, NTP, HTTP |
| pcap I/O | No | Yes (read/write pcap/pcapng) |
| Checksum auto | Manual | Builder auto-computes |
| Fuzz testing | No | 13 fuzz targets |
| Extension headers | IPv6 basic | IPv6 + depth-limited chain + Iterator |

### WireForge Advantages

1. **Application-layer protocols** — DNS, DHCP, NTP, HTTP built-in
2. **pcap/pcapng I/O** — read/write packet captures, pure Rust
3. **no_std core** — use `wireforge-core` in embedded/bare-metal
4. **Auto-checksum** — Builders compute IPv4/TCP/UDP/ICMP checksums automatically
5. **Typed messages** — ICMP and IGMP have typed message enums (EchoRequest, DestUnreachable, etc.)
6. **Depth-limited extension headers** — IPv6 extension header chain with max-depth guard
