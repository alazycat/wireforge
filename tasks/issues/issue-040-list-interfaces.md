# list_interfaces() 三平台完整实现

## Description

替换当前 `interface.rs` 中的占位符，实现 Linux/macOS/Windows 三平台的网络接口枚举。`Interface` struct 包含接口名、友好名称、MAC 地址、IP 列表、loopback 标志和 up 状态。所有平台均不需要 root 权限。

## Acceptance Criteria

- [ ] `Interface` struct 所有字段正确填充 (name, friendly_name, mac_address, ips, is_loopback, is_up)
- [ ] Linux: `SIOCGIFCONF` 获取接口列表 → 逐个 `SIOCGIFFLAGS` / `SIOCGIFHWADDR` / `SIOCGIFADDR`
- [ ] Linux: 使用临时 `Socket::new(Domain::IPV4, Type::DGRAM, None)` 获取 socket fd 用于 ioctl
- [ ] macOS: `getifaddrs()` 获取链表 → 聚合 AF_LINK (MAC + ifname) + AF_INET/AF_INET6 (IPs)
- [ ] macOS: `ifa_flags` 提取 `IFF_UP` 和 `IFF_LOOPBACK`
- [ ] Windows: `GetAdaptersAddresses` (IP Helper API) FFI → 提取 AdapterName, FriendlyName, PhysicalAddress, OperStatus
- [ ] Windows: 两次调用 — 第一次获取 size，第二次获取数据
- [ ] 至少返回 loopback 接口
- [ ] 无 root/Administrator 权限要求
- [ ] 单元测试: 三平台均验证 list_interfaces() 返回非空列表且包含 loopback
- [ ] `cargo build` 三平台均通过
- [ ] `cargo test` 各平台通过

## Dependencies

None (所有 API 均为系统自带)

## Type

backend

## Priority

high

## SPEC Reference

Section 6 — list_interfaces() Implementation; Section 6.1 Linux; Section 6.2 macOS; Section 6.3 Windows
