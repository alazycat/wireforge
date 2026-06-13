# API 审计 + 稳定性标注

## Description

审计 WireForge 4 个 crate 的所有 `pub` 导出，逐项标注 Stability（Stable/Unstable）。`IpProtocol` 枚举考虑是否需要为 IGMP 和 GRE 添加显式变体。输出审计文档 `docs/api-audit-v1.md`。

## Acceptance Criteria

- [ ] 审计 `wireforge-core`: 所有 `pub` 类型/函数/常量 (~40 items)，按 SPEC §2.1 标注
- [ ] 审计 `wireforge-packet`: Packet enum + 3 dispatch fns + From impls
- [ ] 审计 `wireforge-io`: traits, IoError, Interface, type aliases, 平台实现
- [ ] 审计 `wireforge-app`: DNS/DHCP/NTP/HTTP/pcap 所有 pub 类型
- [ ] 生成 `docs/api-audit-v1.md` — 每个 pub item 标注 Stable / Unstable (+原因)
- [ ] macOS 平台实现 (BpfReader, BsdL3Receiver) 标注为 Unstable（待 macOS 验证）
- [ ] `IpProtocol` 枚举: 决定是否添加 `Igmp`/`Gre` 显式变体，或保持 `Unknown`
- [ ] `cargo doc --no-deps --workspace` 零警告

## Dependencies

None

## Type

audit

## Priority

high

## SPEC Reference

Section 2 — API Audit Checklist; Section 2.1–2.4 per-crate listings
