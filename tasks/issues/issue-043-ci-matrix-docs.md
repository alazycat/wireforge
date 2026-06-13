# CI 矩阵 + 模块文档

## Description

配置 GitHub Actions 三平台 CI 矩阵（ubuntu-latest, macos-latest, windows-latest），确保每次提交三平台均通过编译、测试、clippy。为所有平台模块和公开 API 添加完整的 rustdoc 注释。

## Acceptance Criteria

- [ ] `.github/workflows/ci.yml` — 3 平台矩阵：ubuntu-latest, macos-latest, windows-latest
- [ ] 每个 job: `cargo build --workspace` + `cargo test --workspace` + `cargo clippy --workspace -- -D warnings` + `cargo doc --no-deps --workspace`
- [ ] Linux: `sudo cargo test --workspace -- --ignored` 运行需 root 的集成测试
- [ ] macOS: `sudo cargo test --workspace -- --ignored` 运行 BPF 集成测试
- [ ] Windows: 标准 `cargo test`（NPcap 集成测试检查 NPcap 是否存在后 skip）
- [ ] `linux/mod.rs` 有模块级 docstring: "Linux platform implementation using AF_PACKET (L2) and raw sockets (L3)."
- [ ] `macos/mod.rs` 有模块级 docstring: "macOS/BSD platform implementation using BPF devices (L2) and raw sockets (L3)."
- [ ] `windows/mod.rs` 有模块级 docstring: "Windows platform implementation using NPcap (L2, optional) and raw sockets (L3)."
- [ ] 所有 `pub` struct/method 有 rustdoc
- [ ] `cargo doc --no-deps --workspace` 零警告
- [ ] README 更新为反映三平台状态和 CI badge
- [ ] `cargo clippy` 无警告

## Dependencies

All previous issues (#37–#42)

## Type

infra

## Priority

medium

## SPEC Reference

Section 9 — CI Configuration; Section 9.3 Module Documentation
