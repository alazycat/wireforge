# Cargo Workspace 搭建

## Description

创建 WireForge 三层 crate workspace: `wireforge-core` (no_std + alloc)、`wireforge-packet`、`wireforge-io`。配置 release profile、clippy 规则、test/fuzz/bench 基础设施。

## Acceptance Criteria

- [ ] 根 `Cargo.toml` 定义 `[workspace]` 含 3 个 member crate
- [ ] `wireforge-core/Cargo.toml`: `no_std` + `extern crate alloc`, 零外部依赖
- [ ] `wireforge-packet/Cargo.toml`: 依赖 `wireforge-core`
- [ ] `wireforge-io/Cargo.toml`: 依赖 `wireforge-packet` + `socket2`
- [ ] `[profile.release]` 配置 `opt-level=3`, `lto=true`, `codegen-units=1`, `panic="abort"`
- [ ] `cargo build` workspace 级别成功
- [ ] `cargo clippy` 无警告

## Dependencies

None

## Type

infra

## Priority

high

## SPEC Reference

Section 2.4 — File Structure; Section 8.3 — Compiler Guidance
