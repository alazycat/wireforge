# DNS 类型定义 + QNAME 压缩解析

## Description

实现 DNS 协议的基础类型（DnsType, DnsClass, DnsOpcode, DnsRcode）及其 From trait。实现 QNAME 标签压缩解析器（RFC 1035 Section 4.1.4），支持普通标签和压缩指针，防止无限循环。

## Acceptance Criteria

- [ ] `dns/types.rs`: `DnsType` 枚举 (A=1, AAAA=28, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16, SRV=33, Unknown), From<u16> + From<DnsType> for u16
- [ ] `dns/types.rs`: `DnsClass` 枚举 (IN=1, CS=2, CH=3, HS=4, Unknown)
- [ ] `dns/types.rs`: `DnsOpcode` 枚举 (Query, IQuery, Status, Notify, Update, Unknown)
- [ ] `dns/types.rs`: `DnsRcode` 枚举 (NoError, FormatError, ServerFailure, NameError, NotImplemented, Refused, Unknown)
- [ ] `dns/name.rs`: `parse_name(buf: &[u8], start: usize) -> Option<(String, usize)>` — 返回解压后的完整域名 + 消耗的字节数
- [ ] 压缩指针跳转限制 10 次，超过返回 None
- [ ] 标签长度 > 63 返回 None
- [ ] 单元测试: 无压缩域名、单指针压缩、多指针跳转、循环指针防御
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #16 (crate 就绪)

## Type

backend

## Priority

high

## SPEC Reference

Section 3.1 — DNS Types; Section 3.3 — DNS Name Compression
