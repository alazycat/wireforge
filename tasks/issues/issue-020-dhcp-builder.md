# DHCP 构造器

## Description

实现 `DhcpPacketBuilder`，支持构造 DHCP Discover/Offer/Request/Ack 等消息类型，自动填充 magic cookie 和 End option。

## Acceptance Criteria

- [ ] `DhcpPacketBuilder::new()` — 初始化固定头（magic cookie 自动设置）
- [ ] `DhcpPacketBuilder::discover()` / `offer()` / `request()` / `ack()` 便捷构造器
- [ ] 字段 setter: `op()`, `htype()`, `hlen()`, `hops()`, `xid()`, `secs()`, `flags()`, `ciaddr()`, `yiaddr()`, `siaddr()`, `giaddr()`, `chaddr()`
- [ ] `add_option(option: &DhcpOption)` — 添加 DHCP option
- [ ] `build() -> Vec<u8>` — 自动追加 End option (255)
- [ ] 单元测试: 构造 Discover → 解析验证往返、构造 Offer → 解析验证往返
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #19 (dhcp types + parser)

## Type

backend

## Priority

high

## SPEC Reference

Section 3.6 — DHCP Types; Section 5.2 — Builder Contract
