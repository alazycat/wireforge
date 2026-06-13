# Windows NPcap L2 捕获实现

## Description

实现 Windows 平台上基于 NPcap SDK 的 L2 帧捕获和发送。`NpcapReader` 打开 NPcap 适配器并捕获 Ethernet 帧，`NpcapWriter` 发送 L2 帧。NPcap 依赖通过 feature flag `npcap` 控制。

## Acceptance Criteria

- [ ] `windows/npcap.rs`: `NpcapReader` struct 实现 `L2Reader` trait
- [ ] `windows/npcap.rs`: `NpcapWriter` struct 实现 `L2Writer` trait
- [ ] `Cargo.toml`: `npcap` feature flag，`npcap = { version = "0.1", optional = true }`
- [ ] `NpcapReader::new(ifname: &str) -> Result<Self, IoError>` — 通过 npcap crate 打开适配器
- [ ] `NpcapReader::open_all() -> Result<Self, IoError>` — 打开所有适配器
- [ ] `recv()` — `adapter.next_packet()` → `EthernetPacket`
- [ ] `set_promiscuous()` — `adapter.set_promiscuous(true)`
- [ ] `set_timeout()` — `adapter.set_timeout(dur)`
- [ ] `NpcapWriter::send()` — `adapter.send(packet)`
- [ ] NPcap 未安装时返回 `IoError::Npcap("NPcap not installed")`
- [ ] 集成测试: loopback 接口发送→接收验证
- [ ] `cargo test` (Windows) 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #27 (trait + error 就绪)

## Type

backend

## Priority

high

## SPEC Reference

Section 3.4 — Windows NPcap 实现细节; Section 2.5 — Feature Flags
