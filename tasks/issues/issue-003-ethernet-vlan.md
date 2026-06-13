# Ethernet + VLAN 解析与构造

## Description

实现 `EthernetPacket` 零拷贝解析器和 `EthernetPacketBuilder` 构造器。支持 Ethernet II 帧格式。实现 `VlanPacket` 解析器及 `parse_vlan_chain()` 处理单层/双层 802.1Q / 802.1ad VLAN 标签。

## Acceptance Criteria

- [ ] `EthernetPacket::new(&[u8]) -> Option<Self>` — len < 14 返回 None
- [ ] `EthernetPacket` 字段访问器: `dst_mac() -> [u8; 6]`, `src_mac() -> [u8; 6]`, `ethertype() -> EtherType`, `payload() -> &[u8]`
- [ ] `EthernetPacketBuilder`: `new()`, `dst_mac()`, `src_mac()`, `ethertype()`, `payload()`, `build() -> Vec<u8>`
- [ ] `VlanPacket::new(&[u8]) -> Option<Self>` — len < 4 返回 None
- [ ] `VlanPacket` 字段: `pcp()`, `dei()`, `vid()`, `ethertype()`, `inner()`
- [ ] `parse_vlan_chain(buf: &[u8]) -> Option<(Vec<VlanPacket>, EtherType, &[u8])>` — 单层/双层标签
- [ ] 单元测试覆盖: 正常帧、最小帧、过短帧、payload 切片
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #2 (util + types 就绪)

## Type

backend

## Priority

high

## SPEC Reference

Section 4.1 — Ethernet API; Section 5.5 — VLAN 解析
