# macOS raw socket L3 收发

## Description

实现 macOS 平台上的 L3 raw socket 收发（BSD 系 raw socket 与 Linux 基本一致）。复用 Linux 的大部分代码，差异仅在 `IP_HDRINCL` 常量名和部分 socket option 名称。

## Acceptance Criteria

- [ ] `macos/l3.rs`: `BsdL3Receiver` struct 实现 `L3Reader` trait
- [ ] `macos/l3.rs`: `BsdL3Sender` struct 实现 `L3Writer` trait
- [ ] `BsdL3Receiver::new(protocol: IpProtocol) -> Result<Self, IoError>`
- [ ] `set_header_included()` — IP_HDRINCL (macOS 常量)
- [ ] `set_timeout()` — SO_RCVTIMEO
- [ ] `BsdL3Sender::new() -> Result<Self, IoError>`
- [ ] `send_to()` — 使用 `socket2::SockAddr`
- [ ] 集成测试: lo0 ICMP Echo 往返
- [ ] `cargo test` (macOS) 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #27 (trait), #29 (macOS 平台就绪)

## Type

backend

## Priority

medium

## SPEC Reference

Section 3.4 — macOS L3 实现细节
