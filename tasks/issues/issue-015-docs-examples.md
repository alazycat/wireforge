# 文档、示例、README

## Description

完善所有公开 API 的 rustdoc 注释，编写实用示例（抓包、数据包构造与发送、简单 ping 实现），编写 README 快速开始指南。

## Acceptance Criteria

- [ ] 所有 `pub` 类型/方法有 rustdoc 注释
- [ ] `wireforge-core/src/lib.rs` 包含 crate-level 使用概述和代码示例
- [ ] `wireforge-io/src/lib.rs` 包含 crate-level 使用概述和代码示例
- [ ] `examples/packet_dump.rs` — 从指定接口抓包并打印各层信息
- [ ] `examples/packet_build.rs` — 构造 Ethernet + IPv4 + TCP SYN 并发送
- [ ] `examples/simple_ping.rs` — 发送 ICMP Echo Request 并等待 Echo Reply
- [ ] `README.md` 包含: 项目简介、快速开始、核心 API 示例、平台要求
- [ ] 所有示例 `cargo run --example` 可编译通过
- [ ] `cargo doc --no-deps` 无警告

## Dependencies

Issue #11 (l2 io), Issue #12 (l3 io)

## Type

infra

## Priority

low

## SPEC Reference

PRD US-013
