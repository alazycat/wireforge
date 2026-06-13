# macOS BPF L2 捕获实现

## Description

实现 macOS/BSD 平台上的 BPF（Berkeley Packet Filter）L2 帧捕获和发送。`BpfReader` 通过 `/dev/bpf` 设备捕获 Ethernet 帧，`BpfWriter` 通过 BPF 设备发送 L2 帧。支持混杂模式、超时设置和缓冲区大小配置。

## Acceptance Criteria

- [ ] `macos/bpf.rs`: `BpfReader` struct 实现 `L2Reader` trait
- [ ] `macos/bpf.rs`: `BpfWriter` struct 实现 `L2Writer` trait
- [ ] `BpfReader::new(ifname: &str) -> Result<Self, IoError>` — 打开 /dev/bpf 设备，绑定指定接口
- [ ] `BpfReader::with_buffer_size(ifname: &str, buf_size: usize)` — 可配置缓冲区大小（默认 64KB）
- [ ] BPF 初始化序列: `open(/dev/bpfN)` → `BIOCSETIF` → `BIOCIMMEDIATE` → `BIOCSBLEN`
- [ ] `set_promiscuous()` — 通过 `BIOCPROMISC` ioctl
- [ ] `set_timeout()` — 通过 `BIOCSRTIMEOUT` ioctl
- [ ] `recv()` — `read(fd, buf)` → 剥离 BPF header (18/26 bytes) → `EthernetPacket`
- [ ] `BpfWriter::send()` — `write(fd, frame)`
- [ ] 单元测试: BPF header 剥离正确性
- [ ] 集成测试: lo0 接口发送→接收验证
- [ ] `cargo test` (macOS) 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #27 (trait + error 就绪)

## Type

backend

## Priority

high

## SPEC Reference

Section 3.4 — macOS BPF 实现细节; Section 5.2 — 集成测试
