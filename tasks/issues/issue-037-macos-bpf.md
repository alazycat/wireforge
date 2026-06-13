# macOS BPF L2 完整实现

## Description

实现 macOS 平台上基于 BPF 设备的 L2 帧捕获和发送。`BpfReader` 通过 `/dev/bpf` 设备捕获 Ethernet 帧并剥离 BPF header，`BpfWriter` 通过 BPF 设备发送 L2 帧。支持混杂模式、超时设置和缓冲区大小配置。

## Acceptance Criteria

- [ ] `BpfReader: /dev/bpf` 设备发现（遍历 0..256 找到首个可用设备）
- [ ] `BpfReader::new(ifname)` — BIOCSETIF 绑定接口 + BIOCIMMEDIATE 立即模式 + BIOCSBLEN 缓冲区（默认 64KB）
- [ ] `BpfReader::with_buffer_size(ifname, buf_size)` — 自定义缓冲区大小
- [ ] `recv()` — `read(fd, buf)` → 剥离 BPF header (bpf_hdr 18/26 bytes) → EthernetPacket
- [ ] bpf_hdr 剥离：读取 bh_hdrlen 字段确定实际头部长度，提取 bh_caplen 确定帧长度
- [ ] `set_promiscuous()` — BIOCPROMISC ioctl
- [ ] `set_timeout()` — BIOCSRTIMEOUT ioctl（使用 timeval 结构）
- [ ] `BpfWriter` — `write(fd, frame)` 通过 BPF 设备发送 L2 帧
- [ ] BPF 设备耗尽时返回 `IoError::Bpf("no free bpf devices")`
- [ ] 实现 `L2Reader` + `L2Writer` trait
- [ ] `impl Drop for BpfReader/BpfWriter` — close fd
- [ ] 单元测试: BPF header 剥离正确性（模拟 bpf_hdr + Ethernet 帧数据）
- [ ] 集成测试: lo0 接口发送→接收往返验证 (标记 `#[ignore]`，需 root)
- [ ] `cargo build` (macOS) 成功
- [ ] `cargo test` (macOS) 全部通过

## Dependencies

None (ioctl 常量独立声明，不依赖 libpcap)

## Type

backend

## Priority

high

## SPEC Reference

Section 3 — macOS BPF Implementation; Section 3.2 ioctl constants; Section 3.3 bpf_hdr structure
