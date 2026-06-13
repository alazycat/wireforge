# UDP 解析与构造

## Description

实现 `UdpPacket` 零拷贝解析器和 `UdpPacketBuilder` 构造器。支持伪头校验和验证与自动计算。

## Acceptance Criteria

- [ ] `UdpPacket::new(&[u8]) -> Option<Self>` — len < 8 返回 None
- [ ] 字段: `source_port()`, `destination_port()`, `length()`, `checksum()`, `payload()`
- [ ] `verify_checksum(src: Ipv4Addr, dst: Ipv4Addr) -> bool` — 支持零校验和 (IPv4 UDP 可选)
- [ ] `UdpPacketBuilder`: `new()`, `source_port()`, `destination_port()`, `payload()`, `build()` — 自动计算伪头校验和
- [ ] 单元测试: 正常 UDP, 零校验和 UDP, 构造往返
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #5 (ipv4), Issue #6 (ipv6)

## Type

backend

## Priority

medium

## SPEC Reference

Section 4.1 — UDP API; PRD US-007
