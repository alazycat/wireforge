# 模糊测试全覆盖

## Description

为每个协议解析器添加 `cargo fuzz` target。覆盖 Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 共 9 个模块。确保任意字节输入不 panic。

## Acceptance Criteria

- [ ] Fuzz setup: `wireforge-core/fuzz/` 目录, `Cargo.toml` with `libfuzzer-sys`
- [ ] 9 个 fuzz target: `ether`, `vlan`, `arp`, `ipv4`, `ipv6`, `tcp`, `udp`, `icmp`, `icmpv6`
- [ ] 每个 target: `fuzz_target!(|data: &[u8]| { let _ = XxxPacket::new(data); })` + 调用所有字段访问器
- [ ] 每个 fuzz target 运行 30 秒无 crash
- [ ] CI 可选集成（文档中说明运行方式）

## Dependencies

Issue #3 (ethernet/vlan), #4 (arp), #5 (ipv4), #6 (ipv6), #7 (icmp), #8 (tcp), #9 (udp)

## Type

infra

## Priority

medium

## SPEC Reference

Section 9.4 — Fuzz Testing; PRD US-011
