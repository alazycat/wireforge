# Linux AF_PACKET + raw socket 适配新 trait

## Description

将现有 `L2Receiver`/`L2Sender`/`L3Receiver`/`L3Sender` 实现移动到 `src/linux/` 目录，并为它们实现对应的 trait（`L2Reader`/`L2Writer`/`L3Reader`/`L3Writer`）。保持 struct 名称和构造函数签名不变，确保现有 Linux 用户代码无需修改即可编译。

## Acceptance Criteria

- [ ] 移动 `src/l2.rs` → `src/linux/l2.rs`，`src/l3.rs` → `src/linux/l3.rs`
- [ ] `impl L2Reader for L2Receiver` — `recv`, `set_timeout`, `set_promiscuous`
- [ ] `impl L2Writer for L2Sender` — `send`
- [ ] `impl L3Reader for L3Receiver` — `recv`, `set_timeout`, `set_header_included`
- [ ] `impl L3Writer for L3Sender` — `send_to`
- [ ] 原有直接方法（`L2Receiver::recv()` 等）仍然可用
- [ ] `src/linux/mod.rs` 正确导出所有类型
- [ ] `cargo build` (Linux) 成功
- [ ] `cargo test` (Linux) 现有集成测试通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #27 (trait + error 就绪)

## Type

backend

## Priority

high

## SPEC Reference

Section 3.4 — Linux 实现细节; Section 5.2 — 集成测试
