# PRD: WireForge 高层协议支持（L4+ 应用层协议）

## Introduction

WireForge 已完成 L2–L4 协议解析/构造（Ethernet → IP → TCP/UDP/ICMP）以及 Linux raw socket I/O。下一个价值台阶是将协议栈向上延伸到应用层，覆盖 Rust 网络工具开发者最常用的场景：DNS 查询/响应解析、DHCP 客户端消息处理、HTTP/1.1 请求/响应行解析，以及 pcap/pcapng 文件读写。

本项目不追求覆盖所有应用层协议；优先选择「每个网络工具都会遇到」的协议，按实际使用频率排序。

## Goals

- 新增 6 个协议/文件格式模块，覆盖 Rust 网络开发者最常用的应用层交互
- 保持零拷贝解析器风格（`Packet::new(&[u8]) -> Option<Self>`）
- 保持 Builder + 自动校验和/长度计算的构造模式
- 所有模块通过单元测试、clippy、fuzz
- pcap/pcapng 模块支持读写，成为数据包分析工具的入口

## User Stories

### US-001: DNS 消息解析与构造
**Description:** 作为网络工具开发者，我需要解析和构造 DNS 查询/响应消息（RFC 1035），以便实现 DNS 客户端、监控工具或隧道检测。

**Acceptance Criteria:**
- [ ] `DnsPacket::new(&[u8]) -> Option<Self>` — len < 12 返回 None
- [ ] 字段: `transaction_id()`, `flags()`, `questions_count()`, `answers_count()`, `authorities_count()`, `additionals_count()`
- [ ] `DnsFlags` helper: `qr()`, `opcode()`, `aa()`, `tc()`, `rd()`, `ra()`, `rcode()` 每个返回具体类型/值
- [ ] `questions() -> DnsQuestionIter` — 迭代 Question section（QNAME + QTYPE + QCLASS）
- [ ] `answers() -> DnsRecordIter` — 迭代 Answer/Authority/Additional sections（NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA）
- [ ] `DnsRecord` 枚举: A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, SRV, Unknown
- [ ] `DnsPacketBuilder`: 支持构造查询和响应，自动更新各 section count
- [ ] 支持 QNAME 标签压缩解析（指针跳转，防循环）
- [ ] 单元测试: 真实 DNS 查询和响应包（至少 A 记录和 AAAA 记录各一个样本）
- [ ] `cargo test` 全部通过，`cargo clippy` 无警告

### US-002: DHCP 消息解析与构造
**Description:** 作为网络工具开发者，我需要解析和构造 DHCP 消息（RFC 2131/2132），以便实现 DHCP 客户端、服务器或探测工具。

**Acceptance Criteria:**
- [ ] `DhcpPacket::new(&[u8]) -> Option<Self>` — len < 240 返回 None
- [ ] 字段: `op()`, `htype()`, `hlen()`, `hops()`, `xid()`, `secs()`, `flags()`, `ciaddr()`, `yiaddr()`, `siaddr()`, `giaddr()`, `chaddr()`, `sname()`, `file()`, `cookie()`
- [ ] `options() -> DhcpOptionIter` — 解析 DHCP options（支持 option overload）
- [ ] `DhcpMessageType` 枚举: Discover, Offer, Request, Declined, Ack, Nak, Release, Inform
- [ ] `DhcpOption` 枚举: SubnetMask, Router, DnsServer, HostName, DomainName, BroadcastAddr, RequestedIp, LeaseTime, MessageType, ServerId, ParameterList, RenewalTime, RebindingTime, End, Unknown
- [ ] `DhcpPacketBuilder`: `new()`, 字段 setter, `add_option()`, `build()`
- [ ] 单元测试: DHCP Discover 和 Offer 各有已知样本
- [ ] `cargo test` 全部通过，`cargo clippy` 无警告

### US-003: NTP 时间协议解析
**Description:** 作为网络工具开发者，我需要解析 NTP 消息（RFC 5905），以便实现时间同步检测或 NTP 反射放大检测。

**Acceptance Criteria:**
- [ ] `NtpPacket::new(&[u8]) -> Option<Self>` — len < 48 返回 None
- [ ] 字段: `leap()`, `version()`, `mode()`, `stratum()`, `poll()`, `precision()`, `root_delay()`, `root_dispersion()`, `reference_id()`, `reference_timestamp()`, `origin_timestamp()`, `receive_timestamp()`, `transmit_timestamp()`
- [ ] `NtpMode` 枚举: Reserved, SymmetricActive, SymmetricPassive, Client, Server, Broadcast, Control, Private
- [ ] 时间戳转为 `core::time::Duration` 的辅助方法
- [ ] 单元测试: NTP client 请求、server 响应各一个已知样本
- [ ] `cargo test` 全部通过，`cargo clippy` 无警告

### US-004: HTTP/1.1 请求与响应行解析
**Description:** 作为网络工具开发者，我需要快速解析 HTTP/1.1 请求行和响应行，以便在流量分析中提取 URL、Host、状态码等关键信息。

**Acceptance Criteria:**
- [ ] `HttpRequest::parse(&[u8]) -> Option<Self>` — 解析 method + URI + version + headers
- [ ] 字段: `method()`, `uri()`, `version()`, `headers() -> HeaderIter`, `body()`
- [ ] `HttpResponse::parse(&[u8]) -> Option<Self>` — 解析 version + status_code + reason + headers + body
- [ ] `HeaderIter` 解析 name: value 对，处理 continuation lines（obsolete line folding）
- [ ] 不做完整的 HTTP 状态机 — 仅文本行解析，不处理 chunked encoding、压缩等
- [ ] 单元测试: GET 请求、200 OK 响应、含多个 header 的请求各一个已知样本
- [ ] `cargo test` 全部通过，`cargo clippy` 无警告

### US-005: pcap/pcapng 文件读写
**Description:** 作为网络工具开发者，我需要读写 pcap 和 pcapng 文件，以便导入 Wireshark/tcpdump 捕获的数据包或导出本工具捕获的数据包。

**Acceptance Criteria:**
- [ ] `PcapReader::new(path) -> Result<Self, IoError>` — 打开 pcap 文件，读取 global header
- [ ] `PcapReader` 实现 `Iterator<Item = Result<(timestamp, &[u8]), IoError>>` — 逐个返回数据包
- [ ] `PcapWriter::new(path, link_type) -> Result<Self, IoError>` — 创建 pcap 文件，写入 global header
- [ ] `PcapWriter::write(timestamp, packet_data)` — 写入单个数据包记录
- [ ] `PcapNgReader` / `PcapNgWriter` — pcapng 格式（Section Header Block + Interface Description Block + Enhanced Packet Block）
- [ ] 支持 link type: Ethernet（LINKTYPE_ETHERNET = 1）
- [ ] 单元测试: 写入→回读 5 个数据包的 roundtrip
- [ ] 不需要依赖 libpcap — 纯 Rust 实现
- [ ] `cargo test` 全部通过，`cargo clippy` 无警告

### US-006: 新增 crate `wireforge-app` 与应用层协议集中管理
**Description:** 作为库用户，我希望应用层协议解析器集中在一个 crate 中，且有统一的入口，不与 L2–L4 的核心解析器混在一起。

**Acceptance Criteria:**
- [ ] 新建 `wireforge-app/` member crate，加入 workspace
- [ ] `wireforge-app/Cargo.toml` 依赖 `wireforge-packet`
- [ ] `wireforge-app` 包含 `dns`, `dhcp`, `ntp`, `http` 四个协议模块
- [ ] `wireforge-app` 包含 `pcap` 模块（pcap/pcapng 读写）
- [ ] 所有模块通过 `pub mod` 暴露
- [ ] `cargo build --workspace` 成功
- [ ] `cargo test --workspace` 全部通过
- [ ] `cargo clippy --workspace` 无警告

### US-007: crate-level 文档与模块 docstring
**Description:** 作为库用户，我需要清晰的模块级文档，包括每个协议模块的概述和基本使用示例。

**Acceptance Criteria:**
- [ ] 每个 `pub` 类型/函数有 rustdoc
- [ ] 每个协议模块有模块级 docstring，含使用示例
- [ ] `wireforge-app/src/lib.rs` 有 crate-level docstring 和 overview
- [ ] `cargo doc --no-deps` 无警告

### US-008: 模糊测试覆盖
**Description:** 作为库维护者，我需要为每个新增协议解析器添加 fuzz target，确保任意字节输入不会 panic。

**Acceptance Criteria:**
- [ ] Fuzz target: `dns`, `dhcp`, `ntp`, `http` 共 4 个
- [ ] 每个 target 调用 `new()` + 所有字段访问器 + iterator 消费
- [ ] 添加到 `wireforge-app/fuzz/` 目录
- [ ] 每个 fuzz target 可编译（通过 `cargo +nightly fuzz check`）

### US-009: 基准测试
**Description:** 作为库维护者，我需要为关键路径建立基准测试，跟踪性能变化。

**Acceptance Criteria:**
- [ ] Bench target: `dns_parse_bench` — DNS 解析吞吐量
- [ ] Bench target: `pcap_read_bench` — pcap 读取吞吐量
- [ ] `cargo bench` 可正常运行

## Functional Requirements

- FR-1: 新增 `wireforge-app` crate，包含 DNS、DHCP、NTP、HTTP 四个应用层协议模块及 pcap 文件读写模块
- FR-2: DNS 解析器必须支持 QNAME 标签压缩指针（RFC 1035 Section 4.1.4），防止无限循环
- FR-3: DHCP 解析器必须支持 Option Overload（RFC 2132 Section 9.6），即 options 可能出现在 file 和 sname 字段中
- FR-4: HTTP 解析器必须是纯文本行解析，不实现完整的 HTTP/1.1 状态机（chunked transfer、compression 等不处理）
- FR-5: pcap/pcapng Reader 必须是 `Iterator`，支持流式读取大型捕获文件
- FR-6: pcap/pcapng Writer 必须在每次 `write()` 后立即 flush 到磁盘
- FR-7: 所有新增解析器遵循现有 `Packet::new(&[u8]) -> Option<Self>` 零拷贝模式
- FR-8: 所有新增 Builder 遵循现有构造器模式，自动计算依赖字段
- FR-9: 所有模块通过 `#[cfg(test)]` 单元测试
- FR-10: 所有模块有对应的 fuzz target

## Non-Goals

- ❌ 不做完整的 TLS/SSL 解析（ClientHello/ServerHello 外的证书链、加密协商等）— TLS 极其复杂，需要专门的 crate
- ❌ 不做 HTTP/2 或 HTTP/3 帧解析 — 需要完整的流状态机和 HPACK/QPACK 解码
- ❌ 不做 QUIC 协议解析 — QUIC 在 UDP 之上，有独立的连接管理和加密层
- ❌ 不做 DNS over HTTPS (DoH) / DNS over TLS (DoT) 的加密层处理
- ❌ 不做 DHCPv6 完整支持 — v1 可以标记为后续版本
- ❌ 不做 pcap filter expression parser（BPF 过滤器编译）— 使用外部 crate
- ❌ 不做完整的 HTTP body 解析（JSON/XML/form-data/multipart）— 仅做 header 行和原始 body
- ❌ 不做状态化协议跟踪（TCP stream reassembly、IP fragment reassembly）
- ❌ 不改变 `wireforge-core` 的 `no_std` 属性 — `wireforge-app` 可以使用 `std`

## Design Considerations

- **crate 结构:** 保持与现有三层架构一致 — `wireforge-app` 在最上层，依赖 `wireforge-packet` → `wireforge-core`
- **命名一致性:** 所有解析器使用 `XxxPacket` 命名，Builder 使用 `XxxPacketBuilder`
- **错误处理:** 解析器用 `Option<T>`（零开销），构造器用 `Result<T, BuildError>`，I/O 用 `Result<T, IoError>`
- **pcap 模块归属:** pcap 不是「协议」但有文件 I/O 依赖，放在 `wireforge-app` 中而不是 `wireforge-io`（后者专注于 socket I/O）
- **HTTP 的范围界定:** 仅解析请求行/响应行/headers，不做 body 内容类型感知。这是「80% 的实用需求，20% 的实现成本」

## Technical Considerations

- `wireforge-app` 可以使用 `std`（不需要 `no_std`），简化 pcap 文件 I/O 和字符串处理
- DNS QNAME 压缩指针解析是 RFC 1035 中最容易出错的点，需要特别关注递归防护
- pcapng 格式比 pcap 复杂得多，但 v1 只需支持最常用的 Block 类型（SHB + IDB + EPB）
- DHCP options 的「Option Overload」机制容易遗漏 — 需要在解析时合并来自 file/sname 字段的 options

## Success Metrics

- 用户可以仅依赖 `wireforge-app` 完成 DNS 查询构造、DHCP Discover 发送、pcap 文件读取三个最常用场景
- 每个协议模块至少有一个端到端测试（构造 → 序列化 → 解析 → 验证字段）
- Fuzz 覆盖所有新增解析器的 `new()` 路径
- Benchmark 显示 DNS 解析吞吐量 > 1M packets/sec

## Open Questions

- DHCPv6 是否应包含在 v1 范围内？当前定义为 Non-Goal，可在 v2 中添加
- pcapng 的 Section Header Block 是否需要支持多 section？v1 建议单 section
- HTTP 解析是否需要处理 obsolete line folding（RFC 7230 Section 3.2.4 已弃用）？建议不处理
- NTP 是否需要 SNTP（Simple NTP）模式支持？NTPv4 已兼容 SNTP，不需要单独处理
