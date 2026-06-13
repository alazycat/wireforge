# TCP 解析与构造（含选项）

## Description

实现 `TcpPacket` 零拷贝解析器和 `TcpPacketBuilder` 构造器。支持 TCP 选项解析（MSS, Window Scale, SACK, Timestamp 等），通过 `TcpOptionsIter` 迭代器暴露。支持校验和验证（需提供 IP 伪头信息）和构造时自动计算。

## Acceptance Criteria

- [ ] `TcpPacket::new(&[u8]) -> Option<Self>` — len < 20 或 len < data_offset*4 返回 None
- [ ] 字段: `source_port()`, `destination_port()`, `sequence()`, `ack_number()`, `data_offset()`, `flags()`, `window()`, `checksum()`, `urgent_pointer()`
- [ ] flags helper: `syn()`, `ack()`, `fin()`, `rst()`, `psh()`, `urg()` 每个返回 bool
- [ ] `options() -> TcpOptionsIter` — 解析 TCP 选项 (MSS, Window Scale, SACK, Timestamp, EndOfList, NoOp, Unknown)
- [ ] `payload() -> &[u8]`, `header_length() -> usize`
- [ ] `verify_checksum(src: Ipv4Addr, dst: Ipv4Addr) -> bool`
- [ ] `TcpPacketBuilder`: `new()`, 字段 setter, `syn()`, `ack()`, `fin()`, `rst()`, `psh()`, `add_option()`, `payload()`, `build()` — 自动计算校验和
- [ ] 单元测试: 无选项 TCP, 含 MSS+Window Scale, 含 SACK, 含 Timestamp, 最小/最大 data_offset, 校验和验证, 构造往返
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #5 (ipv4), Issue #6 (ipv6)

## Type

backend

## Priority

high

## SPEC Reference

Section 4.1 — TCP API; Section 4.2 — Builder; Section 5.2 — TCP 选项; PRD US-006
