# Cargo.toml v1.0 + crate 元数据

## Description

更新 workspace 和 4 个 crate 的 Cargo.toml 元数据：版本号 1.0.0、keywords/categories、MSRV、documentation link。验证 `cargo package --dry-run` 全部通过。

## Acceptance Criteria

- [ ] workspace `Cargo.toml` version → `1.0.0`
- [ ] `rust-version = "1.75"` (MSRV)
- [ ] 每个 crate 添加:
  - `keywords = ["networking", "packet", "parsing", "pcap"]`
  - `categories = ["network-programming", "parsing"]`
  - `documentation = "https://docs.rs/wireforge-{crate}"`
- [ ] `wireforge-io` description 更新为 "Cross-platform raw socket I/O"
- [ ] `wireforge-app` description 更新为 "Application-layer protocol parsers and pcap I/O"
- [ ] 所有 4 crate `cargo package --dry-run` 成功
- [ ] `cargo package --list` 确认没有意外文件被打包

## Dependencies

Issue #48 (API 审计完成后确认无 breaking change 需要额外处理)

## Type

infra

## Priority

high

## SPEC Reference

Section 7 — Cargo.toml v1.0 Changes
