# L3 套接字 I/O (raw socket)

## Description

实现 Linux raw socket 封装。提供 `L3Receiver`（接收 IPv4 数据包）和 `L3Sender`（发送 IPv4 数据包），支持 IP_HDRINCL 选项和超时设置。

## Acceptance Criteria

- [ ] `L3Receiver::new(protocol: IpProtocol) -> Result<Self, IoError>` — 打开 AF_INET SOCK_RAW
- [ ] `L3Receiver::recv(&mut self) -> Result<Ipv4Packet<'_>, IoError>` — 接收 IPv4 数据包
- [ ] `L3Receiver::set_header_included(&mut self, on: bool) -> Result<(), IoError>` — IP_HDRINCL
- [ ] `L3Receiver::set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError>`
- [ ] `L3Sender::new() -> Result<Self, IoError>`
- [ ] `L3Sender::send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError>`
- [ ] 集成测试: lo 接口 ICMP Echo Request/Reply 往返
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #10 (packet dispatch)

## Type

backend

## Priority

medium

## SPEC Reference

Section 4.3 — I/O API (L3); PRD US-009
