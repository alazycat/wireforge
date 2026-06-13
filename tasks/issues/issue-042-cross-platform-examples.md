# 跨平台示例（3 个）

## Description

创建三个跨平台示例程序：数据包转储、数据包发送、接口列表。每个示例使用 `DefaultL2Reader` 等类型别名，顶部有平台说明和权限提示。

## Acceptance Criteria

- [ ] `examples/cross_platform_dump.rs` — 从命令行参数或 `list_interfaces()` 获取接口名，捕获并打印 10 个 Ethernet 帧（含 MAC 地址、EtherType、长度）
- [ ] `examples/cross_platform_send.rs` — 构造 Ethernet + IPv4 + ICMP Echo Request 并通过 DefaultL2Writer 发送到指定 MAC 地址
- [ ] `examples/list_interfaces.rs` — 调用 `list_interfaces()` 表格化打印所有接口（名称、友好名称、MAC、IPs、状态）
- [ ] 每个示例使用 `DefaultL2Reader` / `DefaultL3Writer` 等类型别名（平台自适应）
- [ ] 每个示例顶部注释：支持的平台、需要的权限（sudo/Administrator）、用法示例
- [ ] `cargo build --example cross_platform_dump` 三平台均可编译
- [ ] `cargo build --example cross_platform_send` 可编译
- [ ] `cargo build --example list_interfaces` 可编译（不需要 root）
- [ ] `list_interfaces` 示例可在非 root 下运行
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #41 (类型别名 + list_interfaces 就绪)

## Type

infra

## Priority

medium

## SPEC Reference

Section 8 — Examples
