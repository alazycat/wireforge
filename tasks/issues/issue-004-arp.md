# ARP 解析与构造

## Description

实现 `ArpPacket` 零拷贝解析器和 `ArpPacketBuilder` 构造器。支持 Ethernet/IPv4 硬件/协议类型组合，区分 Request (op=1) 和 Reply (op=2) 操作。

## Acceptance Criteria

- [ ] `ArpPacket::new(&[u8]) -> Option<Self>` — len < 28 (Ethernet/IPv4 ARP 最小长度) 返回 None
- [ ] 字段: `hardware_type() -> ArpHardwareType`, `protocol_type() -> EtherType`, `hw_addr_len() -> u8`, `proto_addr_len() -> u8`, `operation() -> ArpOperation`
- [ ] 字段: `sender_hw_addr() -> &[u8]`, `sender_proto_addr() -> &[u8]`, `target_hw_addr() -> &[u8]`, `target_proto_addr() -> &[u8]`
- [ ] `ArpPacketBuilder`: `new()`, 各字段 setter, `build() -> Vec<u8>`
- [ ] 单元测试: ARP Request 解析、ARP Reply 解析、构造后解析往返验证
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #2 (util + types 就绪)

## Type

backend

## Priority

high

## SPEC Reference

Section 3.2 — ARP 类型定义; PRD US-002
