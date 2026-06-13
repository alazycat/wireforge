# crates.io 发布

## Description

将 WireForge 4 个 crate 按依赖顺序发布到 crates.io。验证 `cargo add` 可正常安装使用。

## Acceptance Criteria

- [ ] 预发布检查: `cargo test --workspace` ✅, `cargo clippy --workspace` ✅, `cargo doc --no-deps --workspace` ✅
- [ ] `cargo publish --dry-run` 4 crate 全部通过
- [ ] 发布顺序: `wireforge-core` → `wireforge-packet` → `wireforge-io`, `wireforge-app`
- [ ] 发布后验证: `cargo add wireforge-core` 在新项目中可正常安装
- [ ] 发布后验证: `cargo add wireforge-app` 可正常安装（含所有传递依赖）
- [ ] crates.io 页面渲染正常（README + doc links）
- [ ] 确认版本号 1.0.0 在 crates.io 上可见

## Dependencies

Issue #48 (API audit), #49 (security audit), #50 (Cargo.toml metadata)

## Type

infra

## Priority

high

## SPEC Reference

Section 6 — crates.io Publication Steps
