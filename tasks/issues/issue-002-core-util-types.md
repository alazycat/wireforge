# wireforge-core 工具层：类型定义、常量、校验和

## Description

实现 `wireforge-core/src/types.rs` 公共枚举类型 (EtherType, IpProtocol, ArpOperation, ArpHardwareType) 及其 From trait。实现 `util.rs` 内部辅助函数: 大端序字节读写 (read_u16be, read_u32be, write_u16be, write_u32be)、RFC 1071 Internet Checksum、TCP/UDP 伪头校验和。定义各协议模块的头部长度常量。

## Acceptance Criteria

- [ ] `types.rs`: EtherType 枚举 (Ipv4, Arp, Ipv6, Vlan, VlanDouble, Unknown), From<u16> + From<EtherType> for u16
- [ ] `types.rs`: IpProtocol 枚举 (Icmp, Tcp, Udp, Icmpv6, Unknown), From<u8> + From<IpProtocol> for u8
- [ ] `types.rs`: ArpOperation 枚举 (Request, Reply, Unknown)
- [ ] `types.rs`: ArpHardwareType 枚举 (Ethernet, Unknown)
- [ ] `util.rs`: `read_u16be(&[u8]) -> u16`, `read_u32be(&[u8]) -> u32`, `write_u16be(&mut [u8], u16)`, `write_u32be(&mut [u8], u32)` — 全部 `#[inline]`
- [ ] `util.rs`: `internet_checksum(&[u8]) -> u16` RFC 1071 标准实现，测试向量覆盖 (全零数据、已知字节串)
- [ ] `util.rs`: `pseudo_header_checksum(src, dst, protocol, transport_data) -> u16` 支持 IPv4/IPv6 伪头
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #1 (workspace 就绪)

## Type

infra

## Priority

high

## SPEC Reference

Section 3.2 — Core Type Definitions; Section 5.1 — 内部工具函数
