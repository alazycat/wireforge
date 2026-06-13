# L2 套接字 I/O (AF_PACKET)

## Description

创建 `wireforge-io` crate，实现 Linux AF_PACKET 套接字封装。提供 `L2Receiver`（接收 Ethernet 帧）和 `L2Sender`（发送原始 L2 帧），支持混杂模式和超时设置。

## Acceptance Criteria

- [ ] `wireforge-io` crate 搭建，依赖 `wireforge-packet` + `socket2`
- [ ] `IoError` 枚举: Socket(std::io::Error), Parse(&'static str), Timeout
- [ ] `L2Receiver::new(ifname: &str) -> Result<Self, IoError>` — 打开 AF_PACKET, 绑定接口
- [ ] `L2Receiver::recv(&mut self) -> Result<EthernetPacket<'_>, IoError>` — 接收 L2 帧并解析
- [ ] `L2Receiver::set_promiscuous(&mut self, on: bool) -> Result<(), IoError>`
- [ ] `L2Receiver::set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError>`
- [ ] `L2Sender::new(ifname: &str) -> Result<Self, IoError>`
- [ ] `L2Sender::send(&self, packet: &[u8]) -> Result<usize, IoError>`
- [ ] 集成测试: lo 接口发送自定义 Ethernet 帧并接收验证
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #10 (packet dispatch)

## Type

backend

## Priority

medium

## SPEC Reference

Section 4.3 — I/O API (L2); PRD US-008
