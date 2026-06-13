# IGMP 解析与构造 (v1/v2/v3)

## Description

实现 IGMP 协议解析器和构造器（RFC 1112, RFC 2236, RFC 3376 基础）。`IgmpPacket` 支持 v1 Query、v2 Query、v1/v2 Report、v2 Leave、v3 Query/Report 消息类型的识别和字段提取。`IgmpPacketBuilder` 支持构造常用消息类型，自动计算 IGMP 校验和（RFC 1071 internet checksum over entire message）。

## Acceptance Criteria

- [ ] `wireforge-core/src/igmp.rs` — 新文件
- [ ] `IgmpPacket::new(&[u8]) -> Option<Self>` — len < 8 返回 None
- [ ] 字段: `type_()`, `max_response()`, `checksum()`, `group_address()`, `payload()`
- [ ] `verify_checksum() -> bool` — internet_checksum over entire message
- [ ] `IgmpMessage` 枚举: MembershipQuery (含 version, max_response, group_address, v3 suppressor/robustness/interval/sources), MembershipReportV1, MembershipReportV2, LeaveGroup, MembershipReportV3, Unknown
- [ ] `IgmpVersion` 枚举: V1 (type=0x11/0x12), V2 (type=0x16/0x17), V3 (type=0x22)
- [ ] `IgmpPacketBuilder`: new(), query_v1(), query_v2(), report_v2(addr), leave_v2(addr), group_address(), payload(), build() — 自动计算校验和
- [ ] `lib.rs` 添加 `pub mod igmp;`
- [ ] 单元测试: v1 query 样本、v2 query 样本、v2 report 样本、v2 leave 样本、校验和验证、构造往返、too_short
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

None (只依赖 `types.rs` 和 `util.rs`)

## Type

backend

## Priority

high

## SPEC Reference

Section 3 — IGMP Protocol Specification; Section 3.2 IGMP Message Types; Section 3.3 Parser API; Section 3.4 Builder
