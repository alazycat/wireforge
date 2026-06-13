# 跨平台示例

## Description

编写三个跨平台示例程序，展示如何在 Linux/macOS/Windows 上使用 WireForge I/O 进行数据包捕获、发送和接口枚举。每个示例顶部包含平台说明和权限提示。

## Acceptance Criteria

- [ ] `examples/cross_platform_dump.rs` — 从命令行参数指定接口，捕获并打印 Ethernet 帧信息
- [ ] `examples/cross_platform_send.rs` — 构造 Ethernet + IPv4 + ICMP 帧并发送
- [ ] `examples/list_interfaces.rs` — 列出本机所有接口及其属性
- [ ] 每个示例使用 `DefaultL2Reader` / `DefaultL3Reader` 等类型别名（平台自适应）
- [ ] 每个示例顶部注释说明: 支持的平台、需要的权限（root/Administrator）
- [ ] `cargo run --example cross_platform_dump` 可编译
- [ ] `cargo run --example list_interfaces` 可编译（不需要 root）
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #34 (类型别名就绪)

## Type

infra

## Priority

low

## SPEC Reference

Section 2.4 — examples/ 目录; PRD US-009
