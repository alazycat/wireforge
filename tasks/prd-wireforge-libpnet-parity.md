# PRD: WireForge — libpnet 功能对标与补齐计划

## Introduction

WireForge 目标是成为 libpnet 的纯 Rust 替代品。当前已覆盖 libpnet 核心协议栈的 ~80%，但仍有部分协议缺失、部分平台支持未完成。本文档逐项对比 WireForge 与 libpnet 的功能覆盖，输出补齐计划。

> **对比基准:** libpnet v0.35.0（pnet、pnet_datalink、pnet_packet、pnet_transport 四个 crate）

---

## 1. 协议覆盖对比

### 1.1 L2 协议

| 协议 | libpnet | WireForge | 状态 | 备注 |
|------|---------|-----------|------|------|
| Ethernet II | `ethernet.rs` | `wireforge-core::ether` | ✅ 完成 | 解析+构造+测试 |
| 802.1Q VLAN | `vlan.rs` | `wireforge-core::vlan` | ✅ 完成 | 单层/双层标签 |
| 802.1ad QinQ | — | `wireforge-core::vlan` | ✅ 完成 | 双层 VLAN 链解析 |

### 1.2 L2.5 / L3 协议

| 协议 | libpnet | WireForge | 状态 | 备注 |
|------|---------|-----------|------|------|
| ARP | `arp.rs` | `wireforge-core::arp` | ✅ 完成 | Request/Reply + Builder |
| IPv4 | `ipv4.rs` | `wireforge-core::ipv4` | ✅ 完成 | 选项+校验和+Builder |
| IPv6 | `ipv6.rs` | `wireforge-core::ipv6` | ✅ 完成 | 扩展头链+Builder |
| ICMP | `icmp.rs` | `wireforge-core::icmp` | ✅ 完成 | ICMPv4 + ICMPv6/NDP |
| **IGMP** | `igmp.rs` | — | ❌ 缺失 | 成员关系查询/报告（RFC 2236） |
| **GRE** | `gre.rs` | — | ❌ 缺失 | 通用路由封装（RFC 2784） |
| **MPLS** | 不直接支持 | — | ⚠️ 可选 | MPLS 标签栈解析 |

### 1.3 L4 协议

| 协议 | libpnet | WireForge | 状态 | 备注 |
|------|---------|-----------|------|------|
| TCP | `tcp.rs` | `wireforge-core::tcp` | ✅ 完成 | 选项迭代器+Builder |
| UDP | `udp.rs` | `wireforge-core::udp` | ✅ 完成 | 伪头校验和 |

### 1.4 应用层协议

| 协议 | libpnet | WireForge (app) | 状态 | 备注 |
|------|---------|-----------------|------|------|
| DNS | — | `wireforge-app::dns` | ✅ 新增 | libpnet 不包含 |
| DHCP | — | `wireforge-app::dhcp` | ✅ 新增 | libpnet 不包含 |
| NTP | — | `wireforge-app::ntp` | ✅ 新增 | libpnet 不包含 |
| HTTP/1.1 | — | `wireforge-app::http` | ✅ 新增 | 行解析 |

### 1.5 协议分发

| 功能 | libpnet | WireForge | 状态 |
|------|---------|-----------|------|
| Packet 枚举 | `pnet_packet` | `wireforge-packet::Packet` | ✅ 完成 |
| Ethernet→上层分发 | 手动 | `parse_ethernet_frame()` | ✅ 完成 |
| IPv4→transport 分发 | 手动 | `parse_ipv4_payload()` | ✅ 完成 |
| IPv6→transport 分发 | 手动 | `parse_ipv6_payload()` | ✅ 完成 |

---

## 2. 数据链路层 I/O 对比

| 功能 | libpnet (`pnet_datalink`) | WireForge (`wireforge-io`) | 状态 |
|------|---------------------------|----------------------------|------|
| Linux AF_PACKET | ✅ | ✅ L2Receiver/L2Sender | ✅ 完成 |
| Linux raw socket | ✅ | ✅ L3Receiver/L3Sender | ✅ 完成 |
| macOS BPF | ✅ | ⚠️ BpfReader 空壳 | ❌ 待实现 |
| macOS raw socket | ✅ | ⚠️ BsdL3Receiver 空壳 | ❌ 待实现 |
| Windows NPcap/WinPcap | ✅ | ⚠️ NpcapReader 空壳 | ❌ 待实现 |
| Windows raw socket | ✅ | ✅ WinL3Receiver/Sender | ✅ 完成 |
| 接口枚举 `list_interfaces()` | ✅ | ✅ 三平台已实现 | ✅ 完成 |
| trait 抽象 (跨平台) | 无 | ✅ L2Reader/L2Writer trait | ✅ 完成 |

---

## 3. 工具层对比

| 功能 | libpnet | WireForge | 状态 |
|------|---------|-----------|------|
| Internet Checksum (RFC 1071) | ✅ | ✅ `internet_checksum()` | ✅ 完成 |
| Pseudo-header checksum | ✅ | ✅ `pseudo_header_checksum()` | ✅ 完成 |
| 大端序字节读写 | ✅ | ✅ `read/write_u16be/u32be` | ✅ 完成 |
| pcap/pcapng 读写 | ❌ | ✅ `wireforge-app::pcap` | ✅ 新增 |
| 模糊测试 | ❌ | ✅ 13 个 fuzz target | ✅ 新增 |
| 基准测试 | ❌ | ✅ criterion benches | ✅ 新增 |

---

## 4. API 设计对比

| 方面 | libpnet | WireForge | 评价 |
|------|---------|-----------|------|
| 解析器返回类型 | `Packet::new() -> Option<Self>` | 同 | 一致 |
| 构造器返回类型 | `MutablePacket` (in-place) | `Builder::build() -> Vec<u8>` | WireForge 更简单（堆分配） |
| 错误处理 | 无（解析失败返回 None） | `Option<T>` + `Result<_, BuildError>` | WireForge 更明确 |
| 零拷贝 | ✅ 引用原始 buffer | ✅ 同 | 一致 |
| no_std 支持 | ❌ | ✅ `wireforge-core` | WireForge 更优 |
| 跨平台 | 3 平台 | 3 平台 (部分待完) | 追赶中 |

---

## 5. 缺失功能优先级矩阵

```
                    影响面大
                        │
          IGMP (L3)     │    macOS BPF + L3
          GRE (隧道)     │    Windows NPcap L2
                        │
    ─────────────────────────────────────── 紧急度
                        │
          MPLS (可选)   │    API 文档完善
                        │    性能调优指南
                        │
                    影响面小
```

### P0 — libpnet 替代的硬门槛（本 PRD 范围）

| ID | 功能 | 原因 |
|----|------|------|
| GAP-1 | **IGMP 解析与构造** | libpnet 支持的协议，网络组播工具需要 |
| GAP-2 | **GRE 解析与构造** | libpnet 支持的协议，VPN/隧道工具需要 |
| GAP-3 | **macOS BPF L2 实现** | macOS 抓包工具的必要依赖 |
| GAP-4 | **macOS L3 实现** | macOS 网络工具的必要依赖 |
| GAP-5 | **Windows NPcap L2 实现** | Windows 抓包工具的必要依赖 |

### P1 — 可选增强

| ID | 功能 | 原因 |
|----|------|------|
| GAP-6 | **MPLS 标签解析** | 运营商网络分析需要，libpnet 也不直接支持 |
| GAP-7 | **GRE 完整选项支持** (Key, Sequence, Checksum) | 部分 GRE 部署使用这些选项 |
| GAP-8 | **IGMPv3 支持** (Source-Specific Multicast) | IGMPv3 是当前主流版本 |

---

## 6. User Stories

### US-001: IGMP 解析与构造（GAP-1）
**Description:** 作为网络工具开发者，我需要解析和构造 IGMPv1/v2/v3 消息，以实现组播组成员关系查询和报告。

**Acceptance Criteria:**
- [ ] `IgmpPacket::new(&[u8]) -> Option<Self>` — len < 8 返回 None
- [ ] `IgmpMessage` 枚举: MembershipQuery(v1/v2/v3), MembershipReport(v1/v2), LeaveGroup(v2), Unknown
- [ ] `IgmpPacket::verify_checksum() -> bool`
- [ ] `IgmpPacketBuilder` — 按消息类型构造，自动计算校验和
- [ ] 单元测试: v1 Query, v2 Query, v2 Report, v2 Leave 各一个已知样本
- [ ] `cargo test` 全部通过，`cargo clippy` 无警告

### US-002: GRE 解析与构造（GAP-2）
**Description:** 作为网络工具开发者，我需要解析和构造 GRE 隧道封装头，以处理 VPN 和隧道流量。

**Acceptance Criteria:**
- [ ] `GrePacket::new(&[u8]) -> Option<Self>` — len < 4 返回 None
- [ ] 字段: `checksum_present()`, `routing_present()`, `key_present()`, `sequence_present()`, `strict_source_route()`, `recursion_control()`, `version()`, `protocol_type() -> EtherType`
- [ ] `key() -> Option<u32>`, `sequence() -> Option<u32>`, `checksum() -> Option<u16>`, `routing() -> Option<&[u8]>`
- [ ] `payload() -> &[u8]` — 跳过所有 GRE 选项头后的有效载荷
- [ ] `GrePacketBuilder` — 支持 Key, Sequence, Checksum 可选字段
- [ ] 单元测试: 无选项 GRE、含 Key GRE、含 Key+Seq GRE、构造往返
- [ ] `cargo test` 全部通过，`cargo clippy` 无警告

### US-003: macOS BPF L2 完整实现（GAP-3）— 同 #37
### US-004: macOS L3 完整实现（GAP-4）— 同 #38
### US-005: Windows NPcap L2 完整实现（GAP-5）— 同 #39

### US-006: libpnet 迁移指南
**Description:** 作为从 libpnet 迁移过来的开发者，我需要一份对照文档，说明如何用 WireForge API 替换 libpnet API。

**Acceptance Criteria:**
- [ ] `docs/migration-from-libpnet.md` — 逐项对照表（libpnet API → WireForge API）
- [ ] 覆盖: 解析、构造、校验和、发送/接收、接口枚举
- [ ] 至少 5 个迁移代码示例（"在 libpnet 中这样做，在 WireForge 中这样做"）

### US-007: v1.0 发布检查清单
**Description:** 作为库维护者，我需要一份 v1.0 发布前必须完成的检查清单。

**Acceptance Criteria:**
- [ ] 所有 P0 缺失功能已实现（IGMP, GRE, macOS L2, macOS L3, Windows L2）
- [ ] 三平台 CI 全部绿色
- [ ] API 文档 100% 覆盖
- [ ] README 有完整的 quick start 和 migration guide 链接
- [ ] `Cargo.toml` 版本号改为 1.0.0
- [ ] CHANGELOG.md 记录所有协议和 API

---

## 7. Functional Requirements

- FR-1: IGMP 解析器必须支持 IGMPv1 (RFC 1112), IGMPv2 (RFC 2236), IGMPv3 基础 (RFC 3376)
- FR-2: GRE 解析器必须支持 RFC 2784 基础 GRE 头 + RFC 2890 Key/Sequence 扩展
- FR-3: macOS BPF 实现必须通过 `/dev/bpf` 设备，不使用 libpcap
- FR-4: Windows NPcap 实现必须通过 `LoadLibrary` + FFI，不依赖外部 Rust crate
- FR-5: 迁移指南必须覆盖 libpnet 所有公开 API 的对应 WireForge API

## Non-Goals

- ❌ 不做 IGMPv3 完整 Source-Specific Multicast 状态机 — 仅解析消息格式
- ❌ 不做 GRE 的 NVGRE/VXLAN 扩展 — 这些是独立隧道协议，不是 GRE
- ❌ 不做 pnet 的 `transport` 层等价物（TCP/UDP 之上的抽象传输层）
- ❌ 不做 libpnet 的 `pnet_macros` 等价物（Rust 的过程宏已经足够）
- ❌ 不做 RIP/OSPF/BGP 路由协议解析 — libpnet 也不支持

## Success Metrics

- WireForge 覆盖 libpnet v0.35 所有公开协议模块的 100%
- 三平台 `cargo test --workspace` 全部通过
- `cargo doc --no-deps` 零警告
- 迁移指南至少 5 个代码示例
- 与 libpnet 的 API 对比表不超过 1 页

## Open Questions

- GRE 是否需要支持 ERSPAN (Encapsulated Remote SPAN) 类型？libpnet 不支持，建议 v2
- IGMPv3 的 Group Record 解析是否需要完整的 filter mode 和 source list？建议 v1 只做基础头部解析
- 迁移指南是否需要覆盖 pnet 的 `datalink` channel API（`datalink::channel()` 返回 tx/rx 对）？WireForge 的 trait 模式不同，需要单独说明
