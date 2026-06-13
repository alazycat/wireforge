# IPv6 解析与构造（含扩展头链）

## Description

实现 `Ipv6Packet` 零拷贝解析器和 `Ipv6PacketBuilder` 构造器。支持 IPv6 固定头及扩展头链式解析（逐跳选项、路由头、分片头、目的选项），包含 `Ipv6ExtensionHeadersIter` 迭代器，防止无限循环。

## Acceptance Criteria

- [ ] `Ipv6Packet::new(&[u8]) -> Option<Self>` — len < 40 返回 None
- [ ] 字段: `version()`, `traffic_class()`, `flow_label()`, `payload_length()`, `next_header() -> IpProtocol`, `hop_limit()`, `source() -> Ipv6Addr`, `destination() -> Ipv6Addr`
- [ ] `extension_headers() -> Ipv6ExtensionHeadersIter` — 链式迭代
- [ ] `Ipv6ExtensionHeader` 枚举: HopByHop, Routing, Fragment, Destination
- [ ] `final_protocol() -> IpProtocol` — 跳过所有扩展头后的上层协议
- [ ] `payload() -> &[u8]` — 跳过所有头的有效载荷
- [ ] 迭代器最大深度限制（8 层），防循环引用
- [ ] `Ipv6PacketBuilder`: `new()`, setter, `add_extension_header()`, `build()`
- [ ] 单元测试: 无扩展头、单扩展头、多扩展头链、深度限制
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #2 (util + types 就绪)

## Type

backend

## Priority

medium

## SPEC Reference

Section 5.3 — IPv6 扩展头解析; PRD US-004
