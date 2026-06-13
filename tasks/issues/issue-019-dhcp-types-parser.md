# DHCP 类型定义 + 解析器

## Description

实现 DHCPv4 消息解析器（RFC 2131/2132）。包括固定头字段访问、DHCP Option 迭代器，以及 Option Overload（RFC 2132 Section 9.6）的处理——当 options 溢出到 file 和 sname 字段时正确合并。

## Acceptance Criteria

- [ ] `dhcp/types.rs`: `DhcpMessageType` 枚举 (Discover, Offer, Request, Declined, Ack, Nak, Release, Inform, Unknown)
- [ ] `dhcp/types.rs`: `DhcpOption` 枚举 (SubnetMask, Router, DnsServer, HostName, DomainName, BroadcastAddr, RequestedIp, LeaseTime, MessageType, ServerId, ParameterList, RenewalTime, RebindingTime, End, Unknown)
- [ ] `DhcpPacket::new(&[u8]) -> Option<Self>` — len < 240 或 magic cookie != 0x63825363 返回 None
- [ ] 字段: `op()`, `htype()`, `hlen()`, `hops()`, `xid()`, `secs()`, `flags()`, `ciaddr()`, `yiaddr()`, `siaddr()`, `giaddr()`, `chaddr()`, `sname()`, `file()`, `magic_cookie()`
- [ ] `options() -> DhcpOptionIter` — 迭代 options 区
- [ ] `message_type() -> Option<DhcpMessageType>` — 便利方法
- [ ] Option Overload 处理: 检测 option 52，按需附加解析 file/sname 字段中的 options
- [ ] 单元测试: DHCP Discover + Offer 已知样本、含 option overload 的样本
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #16 (crate 就绪)

## Type

backend

## Priority

high

## SPEC Reference

Section 3.6 — DHCP Types; Section 3.7 — DHCP Parser API; Section 3.8 — DHCP Option Overload
