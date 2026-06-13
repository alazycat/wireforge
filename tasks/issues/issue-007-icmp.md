# ICMP / ICMPv6 / NDP 解析与构造

## Description

实现 `IcmpPacket` (ICMPv4) 和 `Icmpv6Packet` (ICMPv6) 零拷贝解析器。ICMPv6 包含 NDP 消息 (NS/NA/RS/RA)。使用枚举表示各消息类型。提供 Builder 并自动计算校验和。

## Acceptance Criteria

- [ ] `IcmpPacket::new(&[u8]) -> Option<Self>` — len < 8 返回 None
- [ ] `IcmpPacket::message() -> IcmpMessage`: EchoRequest, EchoReply, DestUnreachable, TimeExceeded, Unknown
- [ ] `IcmpMessage::EchoRequest` 含 id, seq, data; `DestUnreachable` 含 code, data
- [ ] `Icmpv6Packet::new(&[u8]) -> Option<Self>` — len < 8 返回 None
- [ ] `Icmpv6Packet::message() -> Icmpv6Message`: NeighborSolicitation, NeighborAdvertisement, RouterSolicitation, RouterAdvertisement, Unknown
- [ ] NDP 消息正确提取 target address, flags, options 字段
- [ ] `IcmpPacketBuilder` / `Icmpv6PacketBuilder`: 按消息类型构造，自动计算校验和
- [ ] 单元测试: 每种消息类型至少一个已知样本
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #5 (ipv4), Issue #6 (ipv6)

## Type

backend

## Priority

medium

## SPEC Reference

Section 5.4 — ICMP/ICMPv6 消息类型; PRD US-005
