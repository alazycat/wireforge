# libpnet → WireForge 迁移指南

## Description

编写一份从 libpnet 迁移到 WireForge 的对照文档。包含 API 对照表、5 个迁移代码示例（解析、构造、校验和、捕获、发送），以及关键差异说明。

## Acceptance Criteria

- [ ] `docs/migration-from-libpnet.md` — 新文件
- [ ] API 对照表: 覆盖 Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, IGMP, GRE 的解析和构造
- [ ] 5 个迁移代码示例（libpnet 写法 vs WireForge 写法）:
  - 1. 解析 Ethernet → IPv4 → TCP 链
  - 2. 构造 Ethernet + IPv4 + ICMP 并序列化
  - 3. 计算和验证 IP/TCP checksum
  - 4. 从网络接口接收数据包
  - 5. 构造并发送数据包
- [ ] 关键差异说明:
  - Builder 模式不同（libpnet 用 MutablePacket，WireForge 用 Builder → build() → Vec<u8>）
  - 跨平台 datalink 不同（libpnet 用 channel()，WireForge 用 L2Reader/L2Writer trait）
  - no_std 支持差异
  - WireForge 额外的应用层协议和 pcap I/O
- [ ] README 添加迁移指南链接
- [ ] `cargo clippy` 无警告（非代码文件，编译不受影响）

## Dependencies

Issue #44 (IGMP), #45 (GRE) — 迁移指南需覆盖这两个新增协议

## Type

docs

## Priority

medium

## SPEC Reference

Section 5 — Migration Guide; Section 5.1 Document Structure; Section 5.2 Required Examples
