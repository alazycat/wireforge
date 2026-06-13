# v1.0 发布检查清单 + 版本号

## Description

完成 WireForge v1.0 发布前的最终检查：确认所有 P0 功能已完成、三平台 CI 绿色、API 文档完整、CHANGELOG 就绪、版本号升级为 1.0.0。

## Acceptance Criteria

- [ ] 确认所有 P0 功能已实现: IGMP ✅, GRE ✅, Linux I/O ✅, macOS BPF/L3, Windows NPcap L2
- [ ] 三平台 CI 全部绿色（或平台受限的已标记 blocked）
- [ ] `cargo doc --no-deps --workspace` 零警告
- [ ] `cargo clippy --workspace` 零警告
- [ ] `cargo test --workspace` 全部通过
- [ ] `CHANGELOG.md` 记录自 bootstrap 以来的所有功能:
  - 核心协议（Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP/NDP, IGMP, GRE）
  - 应用层（DNS, DHCP, NTP, HTTP）
  - pcap/pcapng I/O
  - 跨平台 I/O trait 架构
  - checker/bench/fuzz
- [ ] workspace `Cargo.toml` `[workspace.package]` version → `1.0.0`
- [ ] 所有 member crate `version.workspace = true` 确认继承
- [ ] README 更新: v1.0 状态 badge + 完整的 crate 架构图
- [ ] `cargo build --workspace` 成功

## Dependencies

Issue #37 (macOS BPF), #38 (macOS L3), #39 (Windows NPcap), #44 (IGMP), #45 (GRE), #46 (migration guide)

## Type

infra

## Priority

medium

## SPEC Reference

PRD US-007 — v1.0 发布检查清单
