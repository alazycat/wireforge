# GRE 解析与构造 (Key/Seq/Checksum options)

## Description

实现 GRE 隧道封装协议解析器和构造器（RFC 2784 + RFC 2890）。`GrePacket` 支持基础头 + 可选字段（Checksum, Key, Sequence, Routing）。`GrePacketBuilder` 支持构造带可选字段的 GRE 封包，可选自动计算 GRE checksum。

## Acceptance Criteria

- [ ] `wireforge-core/src/gre.rs` — 新文件
- [ ] `GrePacket::new(&[u8]) -> Option<Self>` — len < 4 返回 None
- [ ] 字段: `flags()`, `checksum_present()`, `routing_present()`, `key_present()`, `sequence_present()`, `strict_source_route()`, `recursion_control()`, `version()`, `protocol_type() -> EtherType`
- [ ] 可选字段: `checksum() -> Option<u16>`, `key() -> Option<u32>`, `sequence() -> Option<u32>`, `routing() -> Option<&[u8]>`
- [ ] `header_length() -> usize` — 4 + 4*(C+K+S) + routing_len
- [ ] `payload() -> &[u8]` — 跳过所有 GRE 头后的有效载荷
- [ ] `GrePacketBuilder`: new(protocol_type), key(), sequence(), checksum(), strict_source_route(), recursion_control(), version(), payload(), build()
- [ ] `build()` — C bit 设置时自动计算 GRE checksum（internet_checksum over GRE header + payload）
- [ ] `lib.rs` 添加 `pub mod gre;`
- [ ] 单元测试: 无选项 GRE (proto=IPv4)、含 Key GRE、含 Key+Seq GRE、header_length 各组合、构造往返、too_short
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

None (只依赖 `types.rs` 和 `util.rs`)

## Type

backend

## Priority

high

## SPEC Reference

Section 4 — GRE Protocol Specification; Section 4.2 Flags Bitmask; Section 4.3 Parser API; Section 4.4 Builder
