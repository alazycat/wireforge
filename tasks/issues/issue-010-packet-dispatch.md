# Packet 统一枚举与协议分发

## Description

创建 `wireforge-packet` crate，实现 `Packet` 统一枚举和协议分发逻辑。从 Ethernet 帧或 IPv4/IPv6 数据报自动分发到下层协议解析器。

## Acceptance Criteria

- [ ] `wireforge-packet` crate 搭建，依赖 `wireforge-core`
- [ ] `Packet<'a>` 枚举: Ethernet, Arp, Ipv4, Ipv6, Tcp, Udp, Icmp, Icmpv6
- [ ] `parse_ethernet_frame(buf: &[u8]) -> Option<(EthernetPacket, Option<Packet>)>` — 解析 Ethernet + 按 ethertype 分发
- [ ] `parse_ipv4_payload(ip: &Ipv4Packet) -> Option<Packet>` — 按 protocol 分发到 ICMP/TCP/UDP
- [ ] `parse_ipv6_payload(ip: &Ipv6Packet) -> Option<Packet>` — 跳过扩展头，按 final_protocol 分发
- [ ] `impl From<EthernetPacket> for Packet`, `From<Ipv4Packet> for Packet`, 等
- [ ] 单元测试: Ethernet→IPv4→TCP 链式解析
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #8 (tcp), Issue #9 (udp)

## Type

backend

## Priority

medium

## SPEC Reference

Section 5.6 — 协议分发; PRD US-010
