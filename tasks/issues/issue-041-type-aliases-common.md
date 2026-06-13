# 类型别名完善 + common 工具 + 平台自适应

## Description

完善 `DefaultL2Reader` / `DefaultL2Writer` / `DefaultL3Reader` / `DefaultL3Writer` 四个平台自适应类型别名的 rustdoc。增强 `common/mod.rs` 的 Unix 共享工具函数。确保 `cargo doc --no-deps -p wireforge-io` 零警告。

## Acceptance Criteria

- [ ] `DefaultL2Reader` / `DefaultL2Writer` / `DefaultL3Reader` / `DefaultL3Writer` 各有 rustdoc: `/// The default L2 reader for the current platform. On Linux this is L2Receiver (AF_PACKET), on macOS BpfReader (BPF), on Windows NpcapReader (NPcap).`
- [ ] `common/mod.rs`: `duration_to_timeval(dur) -> libc::timeval` (Unix 平台共享)
- [ ] `common/mod.rs`: 现有 `set_socket_timeout` 重构为使用 `duration_to_timeval`
- [ ] `wireforge-io/src/lib.rs` crate-level docstring 列出各平台默认实现
- [ ] `cargo doc --no-deps -p wireforge-io` 零警告
- [ ] `cargo build --workspace` 三平台均可编译
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #37 (macOS BPF), #38 (macOS L3), #39 (Windows NPcap)
(类型别名需要所有平台实现就位才能正确编译)

## Type

infra

## Priority

medium

## SPEC Reference

Section 7 — Type Aliases + Common Utilities
