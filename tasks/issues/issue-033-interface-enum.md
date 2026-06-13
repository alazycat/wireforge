# 网络接口枚举 list_interfaces()

## Description

实现跨平台的网络接口枚举功能。`Interface` struct 包含接口名、友好名称、MAC 地址、IP 列表、loopback 标志、up 状态。`list_interfaces()` 在三平台上分别使用不同的系统 API。

## Acceptance Criteria

- [ ] `interface.rs`: `Interface` struct — name, friendly_name, mac_address, ips, is_loopback, is_up
- [ ] `pub fn list_interfaces() -> Result<Vec<Interface>, IoError>`
- [ ] Linux 实现: `SIOCGIFCONF` 获取接口列表，`SIOCGIFFLAGS` 获取 flags，`SIOCGIFHWADDR` 获取 MAC
- [ ] macOS 实现: `getifaddrs()` 获取接口信息
- [ ] Windows 实现: npcap `Adapter::list()` 或 Win32 `GetAdaptersInfo` 获取接口
- [ ] loopback 接口测试: 至少验证存在一个 loopback 接口
- [ ] `cargo test`（各平台）通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #28 (Linux 平台就绪，提供 Linux 实现参考)

## Type

backend

## Priority

medium

## SPEC Reference

Section 3.3 — Interface 类型; Section 3.4 — 各平台接口枚举细节
