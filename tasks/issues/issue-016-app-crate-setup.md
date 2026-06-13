# wireforge-app crate 搭建 + IoError 扩展

## Description

新建 `wireforge-app` member crate，加入 workspace。扩展 `wireforge-io::IoError` 添加应用层所需错误变体。创建所有协议模块骨架。

## Acceptance Criteria

- [ ] `wireforge-app/Cargo.toml`: 依赖 `wireforge-packet`，使用 workspace 属性
- [ ] 根 `Cargo.toml` workspace.members 添加 `"wireforge-app"`
- [ ] `wireforge-app/src/lib.rs`: `pub mod dns; pub mod dhcp; pub mod ntp; pub mod http; pub mod pcap;`
- [ ] 协议模块骨架文件: `dns/mod.rs`, `dhcp/mod.rs`, `ntp/mod.rs`, `http/mod.rs`, `pcap/mod.rs`
- [ ] `wireforge-io/src/error.rs` 新增变体: `InvalidMagic(u32)`, `UnsupportedVersion { major: u16, minor: u16 }`, `TruncatedRecord { expected: u32, got: usize }`, `NameTooLong(usize)`, `CompressionLoop`
- [ ] `wireforge-io/src/error.rs` 更新 `Display` 和 `Error` impl
- [ ] `cargo build --workspace` 成功
- [ ] `cargo clippy --workspace` 无警告

## Dependencies

None

## Type

infra

## Priority

high

## SPEC Reference

Section 2.4 — File Structure; Section 2.5 — Workspace Integration; Section 4.1 — Error Types
