# NTP 类型定义 + 解析器

## Description

实现 NTPv4 消息解析器（RFC 5905）。包括 leap indicator、mode、stratum 等字段，以及 NTP 时间戳（64-bit 定点数，epoc 1900）到 `core::time::Duration` 的转换。

## Acceptance Criteria

- [ ] `ntp/types.rs`: `NtpMode` 枚举 (Reserved, SymmetricActive, SymmetricPassive, Client, Server, Broadcast, Control, Unknown)
- [ ] `ntp/types.rs`: `NtpLeapIndicator` 枚举 (NoWarning, LastMinute61, LastMinute59, Alarm)
- [ ] `NtpPacket::new(&[u8]) -> Option<Self>` — len < 48 返回 None
- [ ] 字段: `leap()`, `version()`, `mode()`, `stratum()`, `poll_interval()`, `precision()`, `root_delay()`, `root_dispersion()`, `reference_id()`, `reference_timestamp()`, `origin_timestamp()`, `receive_timestamp()`, `transmit_timestamp()`
- [ ] 时间戳字段返回 `Option<Duration>` — 零值返回 None
- [ ] NTP epoch (1900) 正确换算为 Unix epoch (1970)，处理 `NTP_EPOCH_DELTA = 2_208_988_800`
- [ ] 单元测试: NTP client 请求样本、server 响应样本、version 4 验证
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #16 (crate 就绪)

## Type

backend

## Priority

medium

## SPEC Reference

Section 3.9 — NTP Types; Section 3.10 — NTP Parser API
