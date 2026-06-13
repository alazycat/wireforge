# 类型别名 + 共享工具 + 平台自适应

## Description

提供 `DefaultL2Reader`、`DefaultL2Writer`、`DefaultL3Reader`、`DefaultL3Writer` 四个平台自适应类型别名，让用户无需关心底层平台即可使用。抽取跨平台共享的工具函数（timeout 设置等）到 `common/mod.rs`。

## Acceptance Criteria

- [ ] `src/lib.rs` 定义 4 个类型别名，根据 `#[cfg(target_os)]` 自动指向对应平台实现
- [ ] `DefaultL2Reader` — Linux→L2Receiver, macOS→BpfReader, Windows→NpcapReader
- [ ] `DefaultL2Writer` / `DefaultL3Reader` / `DefaultL3Writer` 同理
- [ ] `common/mod.rs`: 共享 timeout 设置函数 `set_socket_timeout(fd, dur)` 等
- [ ] 类型别名有 rustdoc 说明
- [ ] `cargo doc --no-deps` 无警告
- [ ] `cargo build --workspace` 三平台均可编译
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #28 (Linux), #29 (macOS BPF), #31 (Windows NPcap)

## Type

infra

## Priority

low

## SPEC Reference

Section 2.2 — 类型别名; Section 2.4 — common/mod.rs
