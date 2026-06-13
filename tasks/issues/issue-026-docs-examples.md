# 文档、示例、模块 docstring

## Description

为 `wireforge-app` 的所有公开 API 添加 rustdoc 注释。每个协议模块有模块级 docstring 和基本使用示例。更新 README 说明新增的 wireforge-app crate。

## Acceptance Criteria

- [ ] 所有 `pub` 类型/方法有 rustdoc 注释
- [ ] `dns/mod.rs` 包含模块级 docstring 和使用示例
- [ ] `dhcp/mod.rs` 包含模块级 docstring 和使用示例
- [ ] `ntp/mod.rs` 包含模块级 docstring 和使用示例
- [ ] `http/mod.rs` 包含模块级 docstring 和使用示例
- [ ] `pcap/mod.rs` 包含模块级 docstring 和使用示例
- [ ] `wireforge-app/src/lib.rs` 包含 crate-level 使用概述
- [ ] README.md 更新：添加 wireforge-app 说明和 quick start 示例
- [ ] `cargo doc --no-deps` 无警告

## Dependencies

Issue #18 (dns), #20 (dhcp), #21 (ntp), #22 (http), #23 (pcap), #24 (pcapng)

## Type

infra

## Priority

low

## SPEC Reference

PRD US-007
