# 定义 I/O trait 体系 + IoError 扩展

## Description

为 `wireforge-io` 定义 4 个平台无关的核心 trait（L2Reader、L2Writer、L3Reader、L3Writer），替换现有的具体 struct API。扩展 IoError 枚举以覆盖三平台的错误场景。重组 lib.rs 模块结构，创建 traits.rs 和平台子目录骨架。

## Acceptance Criteria

- [ ] `src/traits.rs`: 定义 `L2Reader`, `L2Writer`, `L3Reader`, `L3Writer` 四个 trait，每个 trait 有对应的 `recv/send/set_timeout` 等方法
- [ ] `L2Reader`: `recv(&mut self) -> Result<EthernetPacket<'_>, IoError>`, `set_timeout`, `set_promiscuous`
- [ ] `L2Writer`: `send(&self, packet: &[u8]) -> Result<usize, IoError>`
- [ ] `L3Reader`: `recv(&mut self) -> Result<Ipv4Packet<'_>, IoError>`, `set_timeout`, `set_header_included`
- [ ] `L3Writer`: `send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError>`
- [ ] `src/error.rs`: 新增 `InterfaceNotFound(String)`, `PermissionDenied`, `Bpf(&'static str)`, `Npcap(String)` (feature-gated), `UnsupportedPlatform`
- [ ] `Display` + `Error` impl 完整
- [ ] `src/lib.rs`: 声明 `mod traits; mod error; mod interface;` + 平台条件模块 `#[cfg(target_os)] mod linux/macos/windows;`
- [ ] 创建平台目录骨架: `src/linux/mod.rs`, `src/macos/mod.rs`, `src/windows/mod.rs`
- [ ] `Cargo.toml` 添加 feature flag `npcap` + 平台条件依赖
- [ ] `cargo build --workspace` 成功（所有平台）
- [ ] `cargo clippy` 无警告

## Dependencies

None

## Type

infra

## Priority

high

## SPEC Reference

Section 2.2 — Component Design; Section 3.1 — Trait Signatures; Section 3.5 — IoError Extension; Section 2.4 — File Structure
