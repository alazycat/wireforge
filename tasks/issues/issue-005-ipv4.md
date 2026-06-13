# IPv4 解析与构造

## Description

实现 `Ipv4Packet` 零拷贝解析器（含 IP 选项字段）和 `Ipv4PacketBuilder` 构造器。支持校验和验证与构造时自动计算。正确处理可变长度头（IHL 字段）。

## Acceptance Criteria

- [ ] `Ipv4Packet::new(&[u8]) -> Option<Self>` — len < 20 或 len < IHL*4 返回 None
- [ ] 字段: `version()`, `ihl()`, `dscp()`, `ecn()`, `total_length()`, `identification()`, `flags()`, `fragment_offset()`, `ttl()`, `protocol() -> IpProtocol`, `checksum()`, `source() -> Ipv4Addr`, `destination() -> Ipv4Addr`
- [ ] `options() -> &[u8]` — 选项字节切片
- [ ] `payload() -> &[u8]` — 跳过 IHL 头长的 payload
- [ ] `header_length() -> usize`, `verify_checksum() -> bool`
- [ ] `Ipv4PacketBuilder`: `new()`, 所有字段 setter, `payload()`, `build() -> Result<Vec<u8>, BuildError>` — 自动计算校验和
- [ ] 单元测试: IHL=5 (最小), IHL=15 (最大), 校验和验证, 构造往返
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #2 (util + types 就绪)

## Type

backend

## Priority

high

## SPEC Reference

Section 4.1 — IPv4 API; PRD US-003
