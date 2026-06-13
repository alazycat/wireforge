# DNS 解析器 + 构造器

## Description

实现 `DnsPacket` 零拷贝解析器，支持 Header flags 访问、Question/Answer/Authority/Additional section 迭代。实现 `DnsPacketBuilder` 构造器。支持 RFC 1035 标准 DNS 消息。

## Acceptance Criteria

- [ ] `DnsPacket::new(&[u8]) -> Option<Self>` — len < 12 返回 None
- [ ] 字段: `transaction_id()`, `flags()`, `questions_count()`, `answers_count()`, `authorities_count()`, `additionals_count()`
- [ ] flags helper: `qr() -> bool`, `opcode() -> DnsOpcode`, `aa() -> bool`, `tc() -> bool`, `rd() -> bool`, `ra() -> bool`, `rcode() -> DnsRcode`
- [ ] `questions() -> DnsQuestionIter` — 迭代 Question section (QNAME + QTYPE + QCLASS)
- [ ] `answers() -> DnsRecordIter`, `authorities() -> DnsRecordIter`, `additionals() -> DnsRecordIter`
- [ ] `DnsRecord` 枚举: A(addr), AAAA(addr), CNAME(cname), MX(preference, exchange), NS(nsdname), PTR(ptrdname), SOA(mname,rname,serial,refresh,retry,expire,minimum), TXT(data), SRV(priority,weight,port,target), Unknown(name,qtype,ttl,rdata)
- [ ] `DnsPacketBuilder`: `query()/response()`, `transaction_id()`, `add_question()`, `add_answer()`, `add_authority()`, `add_additional()`, `build()` — 自动更新 count 字段
- [ ] 单元测试: 真实 DNS 查询样本（A 记录）、DNS 响应样本（A + AAAA + CNAME）、构造→解析往返、压缩指针域名
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #17 (dns types + name)

## Type

backend

## Priority

high

## SPEC Reference

Section 3.2 — DNS Parser API; Section 3.4 — DNS Record Types; Section 3.5 — DNS Builder API
