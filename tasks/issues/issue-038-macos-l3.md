# macOS L3 raw socket 完整实现

## Description

实现 macOS 平台上基于 BSD raw socket 的 L3 收发。BSD socket API 与 Linux 几乎一致，主要差异在常量名。将当前空壳实现替换为完整的 raw socket 收发逻辑。

## Acceptance Criteria

- [ ] `BsdL3Receiver` 完整实现: `Socket::new(Domain::IPV4, Type::RAW, proto)` 打开 raw socket
- [ ] `recv()` — `sock.recv(&mut buf)` → `Ipv4Packet`（使用 MaybeUninit 缓冲区）
- [ ] `set_header_included()` — `IP_HDRINCL` setsockopt（macOS 常量）
- [ ] `set_timeout()` — `SO_RCVTIMEO` setsockopt（使用 timeval 结构）
- [ ] `BsdL3Sender` 完整实现: `Socket::new(Domain::IPV4, Type::RAW, IPPROTO_RAW)`
- [ ] `send_to()` — `sock.send_to(packet, &addr)`
- [ ] 实现 `L3Reader` + `L3Writer` trait
- [ ] 集成测试: lo0 ICMP Echo 往返 (标记 `#[ignore]`，需 root)
- [ ] `cargo build` (macOS) 成功
- [ ] `cargo test` (macOS) 全部通过

## Dependencies

None (socket2 + libc 已是依赖)

## Type

backend

## Priority

high

## SPEC Reference

Section 4 — macOS L3 Implementation
