# Windows raw socket L3 收发

## Description

实现 Windows 平台上的 L3 raw socket 收发。Windows raw socket 与 Unix 有行为差异（IP_HDRINCL 的实现不同、部分 socket option 需要不同的常量），需要适配。

## Acceptance Criteria

- [ ] `windows/l3.rs`: `WinL3Receiver` struct 实现 `L3Reader` trait
- [ ] `windows/l3.rs`: `WinL3Sender` struct 实现 `L3Writer` trait
- [ ] `WinL3Receiver::new(protocol: IpProtocol) -> Result<Self, IoError>`
- [ ] `set_header_included()` — Windows 等效 IP_HDRINCL 设置
- [ ] `set_timeout()` — SO_RCVTIMEO (Windows 使用 DWORD 而非 timeval)
- [ ] `WinL3Sender::new() -> Result<Self, IoError>`
- [ ] `send_to()` — 使用 socket2 SockAddr
- [ ] 集成测试: loopback ICMP Echo 往返
- [ ] `cargo test` (Windows) 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #27 (trait), #31 (Windows 平台就绪)

## Type

backend

## Priority

medium

## SPEC Reference

Section 3.4 — Windows L3 实现细节
