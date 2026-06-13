# PRD: WireForge — Rust 网络数据包处理库

## Introduction

WireForge 是一个 Rust 编写的网络数据包处理库，旨在成为 libpnet 的完整替代方案。它提供数据包解析、构造以及原始套接字 I/O 能力，覆盖 L2-L4 所有主流协议，服务于通用网络工具开发场景。项目优先考虑零拷贝性能与内存安全，初期仅支持 Linux 平台。

项目名来源于 `wire`（线路/网络）+ `forge`（锻造），寓意在数据链路层锻造和解析数据包。

## Goals

- 提供与 libpnet 功能对等的数据包解析 API（零拷贝、基于 `&[u8]` 切片）
- 提供类型安全的数据包构造 API（Builder 模式）
- 提供跨协议的原始套接字 I/O 抽象（AF_PACKET L2 收发、raw socket L3 收发）
- 覆盖 libpnet 支持的全部 L2-L4 协议
- 解析性能与 libpnet 相当或更优
- 核心路径 zero `unsafe`，必要时将 `unsafe` 封装至最小模块并附带安全证明

## User Stories

### US-001: 链路层数据包解析
**Description:** 作为网络工具开发者，我需要解析 Ethernet II 帧和 802.1Q VLAN 标签，以便在抓包工具中识别链路层信息。

**Acceptance Criteria:**
- [ ] `EthernetPacket::new(&[u8])` 从字节切片零拷贝解析 Ethernet II 帧头
- [ ] 正确提取 dst_mac、src_mac、ethertype 字段
- [ ] 支持 802.1Q VLAN 标签解析（单层/双层标签）
- [ ] 无效输入（过短切片）返回 `None`，不 panic
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-002: ARP 数据包解析与构造
**Description:** 作为网络工具开发者，我需要解析和构造 ARP 请求/应答数据包，以便实现网络扫描和 ARP 欺骗检测工具。

**Acceptance Criteria:**
- [ ] `ArpPacket::new(&[u8])` 解析 ARP 数据包，提取硬件类型、协议类型、操作码、地址字段
- [ ] 区分 ARP 请求 (op=1) 和 ARP 应答 (op=2)
- [ ] 提供 `ArpPacketBuilder` 构造 ARP 数据包
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-003: IPv4 数据包解析与构造
**Description:** 作为网络工具开发者，我需要解析和构造 IPv4 数据包（含选项字段），以便实现 IP 层路由追踪和包过滤工具。

**Acceptance Criteria:**
- [ ] `Ipv4Packet::new(&[u8])` 零拷贝解析 IPv4 头，提取 version、ihl、total_length、protocol、src/dst 等字段
- [ ] 正确处理 IP 选项字段（可变长度头）
- [ ] 校验和验证方法
- [ ] `Ipv4PacketBuilder` 支持设置所有字段并自动计算校验和
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-004: IPv6 数据包解析与构造
**Description:** 作为网络工具开发者，我需要解析和构造 IPv6 数据包（含扩展头），以便支持 IPv6 环境下的网络工具。

**Acceptance Criteria:**
- [ ] `Ipv6Packet::new(&[u8])` 解析 IPv6 固定头
- [ ] 支持逐跳选项、路由头、分片头、目的选项等扩展头链式解析
- [ ] `Ipv6PacketBuilder` 构造 IPv6 数据包（含扩展头）
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-005: ICMP / ICMPv6 解析与构造
**Description:** 作为网络工具开发者，我需要解析和构造 ICMP（v4）及 ICMPv6 消息，以便实现 ping/traceroute 等诊断工具。

**Acceptance Criteria:**
- [ ] `IcmpPacket::new(&[u8])` 解析 ICMPv4 消息（Echo Request/Reply, Dest Unreachable, Time Exceeded 等）
- [ ] `Icmpv6Packet::new(&[u8])` 解析 ICMPv6 消息（含 ND/RS/RA/NS/NA）
- [ ] 提供对应 Builder 用于构造各类型消息
- [ ] 自动计算 ICMP 校验和
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-006: TCP 数据包解析与构造
**Description:** 作为网络工具开发者，我需要解析和构造 TCP 段（含选项），以便实现 SYN 扫描、连接监控等工具。

**Acceptance Criteria:**
- [ ] `TcpPacket::new(&[u8])` 解析 TCP 头，提取 ports、seq、ack、flags、window 等字段
- [ ] 解析 TCP 选项（MSS, Window Scale, SACK, Timestamp 等）
- [ ] `TcpPacketBuilder` 构造 TCP 段，支持选项设置和校验和计算
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-007: UDP 数据包解析与构造
**Description:** 作为网络工具开发者，我需要解析和构造 UDP 数据报，以便实现 DNS/DHCP 等基于 UDP 的应用层工具。

**Acceptance Criteria:**
- [ ] `UdpPacket::new(&[u8])` 解析 UDP 头（ports, length, checksum）
- [ ] `UdpPacketBuilder` 构造 UDP 数据报，支持伪头校验和计算
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-008: 数据链路层原始套接字 I/O
**Description:** 作为网络工具开发者，我需要通过 AF_PACKET 套接字在 L2 层收发 Ethernet 帧，以便实现抓包和原始数据包注入。

**Acceptance Criteria:**
- [ ] 打开 AF_PACKET 套接字、绑定网络接口
- [ ] 接收 L2 数据帧（返回 `&[u8]` 供解析器使用）
- [ ] 发送已构造的 L2 数据帧
- [ ] 支持 promiscuous 模式
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-009: 网络层原始套接字 I/O
**Description:** 作为网络工具开发者，我需要通过 raw socket 在 L3 层收发 IP 数据包，以便实现 ping/traceroute 等工具。

**Acceptance Criteria:**
- [ ] 打开 AF_INET/SOCK_RAW 套接字
- [ ] 接收 IPv4 数据包
- [ ] 发送 IPv4 数据包（需手动构造 IP 头或由内核填充）
- [ ] 支持 IP_HDRINCL 选项
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-010: 数据包迭代器与高层抽象
**Description:** 作为网络工具开发者，我需要一个统一的数据包迭代器，能够从网络接口持续接收数据包并以类型安全的方式分发到各层解析器。

**Acceptance Criteria:**
- [ ] 提供 `PacketReceiver` trait，统一 L2/L3 接收行为
- [ ] `L2Receiver` 实现返回 `EthernetPacket` 的迭代器式接口
- [ ] `L3Receiver` 实现返回 `Ipv4Packet`/`Ipv6Packet` 的迭代器式接口
- [ ] 支持超时设置
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

### US-011: 模糊测试与安全性验证
**Description:** 作为库维护者，我需要确保解析器在面对恶意/畸形输入时不会 panic 或产生未定义行为。

**Acceptance Criteria:**
- [ ] 为每个协议解析器添加 `cargo fuzz` 目标（Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP）
- [ ] 每个 fuzz 目标运行 30 秒无 crash
- [ ] CI 集成模糊测试（可选）
- [ ] `cargo test` 全部通过

### US-012: 基准测试与性能对比
**Description:** 作为库维护者，我需要与 libpnet 进行性能对比，确保解析性能不劣于 libpnet。

**Acceptance Criteria:**
- [ ] 为每个协议解析器添加 `criterion` 基准测试
- [ ] 基准测试覆盖：解析速度、构造速度、校验和计算
- [ ] 文档中记录与 libpnet 的性能对比数据
- [ ] `cargo bench` 可正常运行

### US-013: 项目文档与示例
**Description:** 作为库使用者，我需要清晰的 API 文档和实用示例，以便快速上手。

**Acceptance Criteria:**
- [ ] 所有公开 API 有 rustdoc 注释
- [ ] `lib.rs` 顶部包含库级别的使用概述
- [ ] `examples/` 目录包含：抓包示例、数据包构造与发送示例、简单 ping 实现
- [ ] README 包含快速开始指南

## Functional Requirements

- FR-1: 系统必须以零拷贝方式（`&[u8]` 切片引用）解析数据包，不进行不必要的内存分配
- FR-2: 系统必须为每个协议提供独立的 `Packet` 类型和 `PacketBuilder` 类型
- FR-3: 系统必须在解析无效数据时返回 `Option` 或 `Result`，不允许 panic
- FR-4: 系统必须支持 L2 Ethernet II + 802.1Q VLAN 解析与构造
- FR-5: 系统必须支持 ARP/RARP 解析与构造
- FR-6: 系统必须支持 IPv4（含选项）解析与构造，包括校验和计算
- FR-7: 系统必须支持 IPv6（含扩展头链）解析与构造
- FR-8: 系统必须支持 ICMPv4 和 ICMPv6（含 NDP 消息）解析与构造
- FR-9: 系统必须支持 TCP（含选项）解析与构造，包括校验和计算
- FR-10: 系统必须支持 UDP 解析与构造，包括校验和计算
- FR-11: 系统必须提供 Linux AF_PACKET 套接字封装，用于 L2 收发
- FR-12: 系统必须提供 Linux raw socket 封装，用于 L3 收发
- FR-13: 系统必须提供 `no_std` 兼容的核心类型（协议头常量和基本类型定义）
- FR-14: 所有解析器必须通过模糊测试验证，确保畸形输入不会导致 panic

## Non-Goals (Out of Scope)

- 不在此版本支持 macOS / Windows / BSD 平台（后续版本考虑）
- 不提供应用层协议解析（HTTP, DNS, DHCP, TLS 等 — 可作为扩展 crate）
- 不提供 BPF/eBPF 集成
- 不提供异步 I/O（tokio/async-std 集成 — 可作为扩展层）
- 不提供 pcap 文件读写（可使用外部 pcap crate）
- 不提供 libpnet 的 C FFI 兼容层

## Technical Considerations

- **核心架构:** 三层设计
  - `wireforge-core`: 协议类型定义、解析器、构造器（`no_std` 兼容）
  - `wireforge-packet`: 数据包枚举和分发逻辑
  - `wireforge-io`: Linux 套接字 I/O 抽象
- **零拷贝实现:** 所有 `Packet` 类型持有 `&[u8]` 引用，字段通过偏移量访问（类似 `nom` 的切片方式，但基于固定偏移而非解析器组合子）
- **Builder 模式:** 每个协议 Builder 内部维护 `Vec<u8>` 缓冲区，提供链式 setter，`build()` 返回完整数据包字节
- **校验和计算:** 采用增量计算或查表优化（RFC 1071），避免逐字节累加
- **`unsafe` 策略:** 仅在需要进行字节切片到类型转换的底层原语中使用 `unsafe`，所有 `unsafe` 块必须带 `// SAFETY:` 注释说明不变量
- **依赖最小化:** 核心层零外部依赖，I/O 层仅依赖 `libc` 或直接使用 syscall
- **测试策略:** 使用已知数据包样本（wireshark 导出 pcap 字节）进行回归测试

## Success Metrics

- 解析吞吐量 ≥ libpnet 的 95%（以 Gbps/Mpps 计，通过 criterion 基准测试验证）
- 所有公开 API 无 panic（由 `cargo fuzz` 和 `#[no_panic]` 保证）
- 核心协议解析器代码覆盖率 ≥ 90%
- `cargo build` 时间在合理范围内（< 30s 干净构建）
- 库二进制大小与 libpnet 相当或更小

## Open Questions

- 是否需要支持数据包分片重组？（IPv4 fragmentation reassembly）
- 是否需要提供类似于 libpnet 的 `transport` 层抽象（自动处理 IP 之上的传输层协议）？
- Builder 是否需要支持从现有数据包修改后重建（`to_builder()` 方法）？
- 是否需要提供数据包过滤器（类似 BPF 的简单过滤器 DSL）？
