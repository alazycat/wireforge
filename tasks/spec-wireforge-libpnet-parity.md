# SPEC: WireForge — libpnet 功能对标实现 (IGMP, GRE, 迁移指南)

> Technical specification derived from: [tasks/prd-wireforge-libpnet-parity.md](prd-wireforge-libpnet-parity.md)
> Generated: 2026-06-13 | Target branch: main

## 1. Summary

### 1.1 What This SPEC Covers

本 SPEC 定义 WireForge 补齐 libpnet 功能差距的两个新协议模块（IGMP、GRE）以及 libpnet→WireForge 迁移指南文档。平台补齐（macOS BPF/L3、Windows NPcap）已在 `spec-wireforge-cross-platform-finish.md` 中定义。

### 1.2 PRD Reference

- Source: `tasks/prd-wireforge-libpnet-parity.md`
- User Stories covered: US-001 (IGMP), US-002 (GRE), US-006 (迁移指南), US-007 (v1.0 checklist)

### 1.3 Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| IGMP 存放位置 | `wireforge-core/src/igmp.rs` | L3 协议，与 ICMP 同级 |
| GRE 存放位置 | `wireforge-core/src/gre.rs` | L3 隧道封装，与 IPv4/IPv6 同级 |
| IGMP 版本范围 | v1 + v2 + v3 基础头部 | v3 完整 source-filter 状态机是 v2 范围 |
| GRE 选项支持 | C(1)+K(1)+S(1)+strict(1)+rec(3)+reserved(9)+ver(3)+proto(16) → 完整 bitmask | 与 libpnet 一致，支持所有 RFC 2890 选项 |
| 迁移指南位置 | `docs/migration-from-libpnet.md` | 独立文档，README 链接 |

---

## 2. Architecture

### 2.1 New Modules

```
wireforge-core/src/
├── igmp.rs        [NEW] — IGMPv1/v2/v3 parser + builder
├── gre.rs         [NEW] — GRE parser + builder
└── lib.rs         [MODIFY] — pub mod igmp; pub mod gre;

docs/
└── migration-from-libpnet.md  [NEW] — libpnet → WireForge 迁移指南
```

### 2.2 No changes to existing modules

IGMP 和 GRE 是独立的协议模块，不依赖其他 WireForge 模块（仅依赖 `types.rs` 和 `util.rs`）。

---

## 3. IGMP Protocol Specification (US-001)

### 3.1 Wire Format

IGMP 消息通过 IP 协议号 2 传输，封装在 IPv4 包中。

**IGMPv1/v2 通用头 (8 bytes):**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      | Max Resp Time |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Group Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**IGMPv3 Membership Query (12+ bytes):**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type = 0x11  | Max Resp Code |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Group Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Resv |S| QRV |     QQIC      |     Number of Sources (N)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address [1]                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address [2]                      |
+-                                                             -+
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 IGMP Message Types

```rust
// Type constants
const IGMP_TYPE_QUERY_V1: u8 = 0x11;      // Membership Query
const IGMP_TYPE_REPORT_V1: u8 = 0x12;     // v1 Membership Report
const IGMP_TYPE_REPORT_V2: u8 = 0x16;     // v2 Membership Report
const IGMP_TYPE_LEAVE_V2: u8 = 0x17;      // v2 Leave Group
const IGMP_TYPE_REPORT_V3: u8 = 0x22;     // v3 Membership Report
```

```rust
pub enum IgmpMessage<'a> {
    MembershipQuery {
        version: IgmpVersion,      // v1, v2, or v3
        max_response: u8,           // in 1/10 seconds (v1/v2) or coded (v3)
        group_address: Ipv4Addr,    // 0.0.0.0 = general query
        supress_router_side: bool,  // v3: S flag
        robustness: u8,             // v3: QRV
        query_interval: u8,         // v3: QQIC
        sources: &'a [u8],          // v3: source addresses
    },
    MembershipReportV1 {
        group_address: Ipv4Addr,
    },
    MembershipReportV2 {
        max_response: u8,
        group_address: Ipv4Addr,
    },
    LeaveGroup {
        max_response: u8,
        group_address: Ipv4Addr,
    },
    MembershipReportV3 {
        group_records: &'a [u8],    // raw group records, parsed later
    },
    Unknown {
        type_: u8,
        data: &'a [u8],
    },
}

pub enum IgmpVersion { V1, V2, V3 }
```

### 3.3 IgmpPacket Parser API

```rust
pub const IGMP_MIN_LEN: usize = 8;

pub struct IgmpPacket<'a> { buf: &'a [u8] }

impl<'a> IgmpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self>;  // len < 8 → None
    pub fn type_(&self) -> u8;                   // byte 0
    pub fn max_response(&self) -> u8;            // byte 1 (alias: code)
    pub fn checksum(&self) -> u16;               // byte 2-3
    pub fn group_address(&self) -> Ipv4Addr;     // byte 4-7
    pub fn payload(&self) -> &'a [u8];          // byte 8+

    pub fn verify_checksum(&self) -> bool;       // internet_checksum over entire msg
    pub fn message(&self) -> IgmpMessage<'a>;    // typed message dispatch
}
```

Checksum: RFC 1071 internet checksum over the entire IGMP message (same algorithm as ICMP).

### 3.4 IgmpPacketBuilder

```rust
pub struct IgmpPacketBuilder { buf: Vec<u8>, payload: Option<Vec<u8>> }

impl IgmpPacketBuilder {
    pub fn new(type_: u8, max_response: u8) -> Self;
    pub fn group_address(mut self, addr: Ipv4Addr) -> Self;
    pub fn payload(mut self, data: &[u8]) -> Self;
    pub fn build(mut self) -> Vec<u8>;  // auto-compute checksum

    // Convenience constructors
    pub fn query_v1() -> Self;           // type=0x11, group=0.0.0.0
    pub fn query_v2() -> Self;           // type=0x11, max_resp=100
    pub fn report_v2(addr: Ipv4Addr) -> Self;  // type=0x16
    pub fn leave_v2(addr: Ipv4Addr) -> Self;   // type=0x17
}
```

### 3.5 Tests

| Test | Input | Expected |
|------|-------|----------|
| `parse_v1_query` | Known bytes `[0x11, 0x00, csum, 0,0,0,0]` | `MembershipQuery { version=V1, group=0.0.0.0 }` |
| `parse_v2_report` | Known bytes `[0x16, 0x00, csum, 224,0,0,1]` | `MembershipReportV2 { group=224.0.0.1 }` |
| `parse_v2_leave` | Known bytes `[0x17, 0x00, csum, 224,0,0,1]` | `LeaveGroup` |
| `parse_too_short` | `&[], &[0u8; 7]` | None |
| `verify_checksum` | Builder output | `true` |
| `build_roundtrip` | `query_v1().build()` → parse → verify | round-trip fields match |

---

## 4. GRE Protocol Specification (US-002)

### 4.1 Wire Format

GRE 通过 IP 协议号 47 传输。基础头 4 bytes（RFC 2784），加上可选扩展（RFC 2890）。

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C|R|K|S|s|Recur|  Flags  |  Ver  |         Protocol Type      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Checksum (optional)      |       Reserved1 (optional)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Key (optional)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (optional)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Routing (optional, variable)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.2 Flags Bitmask

```rust
const GRE_FLAG_CHECKSUM: u16 = 0x8000;       // C bit
const GRE_FLAG_ROUTING: u16 = 0x4000;        // R bit
const GRE_FLAG_KEY: u16 = 0x2000;            // K bit
const GRE_FLAG_SEQUENCE: u16 = 0x1000;       // S bit
const GRE_FLAG_STRICT_ROUTE: u16 = 0x0800;   // s bit
const GRE_FLAG_RECURSION: u16 = 0x0700;      // Recursion Control (3 bits)
const GRE_FLAG_VERSION: u16 = 0x0007;        // Version (3 bits, usually 0)
```

### 4.3 GrePacket Parser API

```rust
pub const GRE_MIN_LEN: usize = 4;

pub struct GrePacket<'a> { buf: &'a [u8] }

impl<'a> GrePacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self>; // len < 4 → None

    // Flags (from first 2 bytes)
    pub fn flags(&self) -> u16;
    pub fn checksum_present(&self) -> bool;     // C bit
    pub fn routing_present(&self) -> bool;      // R bit
    pub fn key_present(&self) -> bool;          // K bit
    pub fn sequence_present(&self) -> bool;     // S bit
    pub fn strict_source_route(&self) -> bool;  // s bit
    pub fn recursion_control(&self) -> u8;      // Rec (3 bits)
    pub fn version(&self) -> u8;                // Ver (3 bits, header version)

    // Protocol type (encapsulated payload)
    pub fn protocol_type(&self) -> EtherType;   // byte 2-3

    // Optional fields
    pub fn checksum(&self) -> Option<u16>;
    pub fn key(&self) -> Option<u32>;
    pub fn sequence(&self) -> Option<u32>;
    pub fn routing(&self) -> Option<&[u8]>;

    // Payload offset depends on which optional fields are present
    pub fn header_length(&self) -> usize;
    pub fn payload(&self) -> &'a [u8];
}
```

**header_length() 计算逻辑:**

```
base = 4
if C: base += 4       // checksum(2) + reserved(2)
if K: base += 4       // key(4)
if S: base += 4       // sequence(4)
if R: routing_len = parse_routing_len(buf); base += routing_len
```

routing 字段: 如果 R bit 设置，routing 信息在 S field 之后（或 K field 之后如果没有 S）。routing 由 length-prefixed SRE (Source Route Entry) 组成。

**简化处理:** v1 不解析 routing SRE 列表，仅返回 `Option<&[u8]>` 原始字节。v2 可增加 SRE 迭代器。

### 4.4 GrePacketBuilder

```rust
pub struct GrePacketBuilder { buf: Vec<u8>, payload: Option<Vec<u8>> }

impl GrePacketBuilder {
    pub fn new(protocol_type: EtherType) -> Self;
    pub fn key(mut self, key: u32) -> Self;         // sets K bit
    pub fn sequence(mut self, seq: u32) -> Self;     // sets S bit
    pub fn checksum(mut self, csum: u16) -> Self;    // sets C bit
    pub fn strict_source_route(mut self, v: bool) -> Self; // sets s bit
    pub fn recursion_control(mut self, v: u8) -> Self;
    pub fn version(mut self, v: u8) -> Self;
    pub fn payload(mut self, data: &[u8]) -> Self;
    pub fn build(mut self) -> Vec<u8>;  // auto-compute GRE checksum if C set
}
```

### 4.5 Tests

| Test | Input | Expected |
|------|-------|----------|
| `parse_basic_gre` | `[0,0,0x08,0x00, payload...]` (proto=IPv4) | `key=None, seq=None, checksum=None` |
| `parse_gre_with_key` | `[0x20,0x00,0x08,0x00, key:4, payload...]` | `key=Some(_)` |
| `parse_gre_with_key_seq` | `[0x30,0x00,0x08,0x00, key:4, seq:4, ...]` | `key=Some, seq=Some` |
| `header_length_basic` | (no options) | `4` |
| `header_length_with_key_seq` | (K+S) | `12` |
| `build_roundtrip` | Builder with key+seq → parse → verify | all fields match |
| `parse_too_short` | `&[], &[0u8; 3]` | None |

---

## 5. Migration Guide (US-006)

### 5.1 Document Structure

`docs/migration-from-libpnet.md`:

```markdown
# Migrating from libpnet to WireForge

## Quick Reference

| libpnet API | WireForge API | Notes |
|-------------|---------------|-------|
| `pnet_packet::ethernet::EthernetPacket::new()` | `wireforge_core::ether::EthernetPacket::new()` | Same signature |
| `pnet_packet::ipv4::Ipv4Packet::new()` | `wireforge_core::ipv4::Ipv4Packet::new()` | Same signature |
| ... | ... | ... |

## Parsing

### libpnet
\```rust
use pnet_packet::ethernet::EthernetPacket;
let eth = EthernetPacket::new(bytes).unwrap();
\```

### WireForge
\```rust
use wireforge_core::ether::EthernetPacket;
let eth = EthernetPacket::new(bytes).unwrap();
\```

// ... 5 examples minimum
```

### 5.2 Required Examples

1. **Parsing**: Ethernet → IPv4 → TCP chain
2. **Building**: Construct and serialize a packet
3. **Checksum**: Compute and verify IP/TCP checksums
4. **Capture**: Receive packets from a network interface
5. **Send**: Construct and send a packet

---

## 6. Implementation Plan

### 6.1 Issue Mapping

| Issue | SPEC Sections | Priority | Depends On |
|-------|--------------|----------|------------|
| #44 | 3.1–3.5 IGMP parser + builder | high | — |
| #45 | 4.1–4.5 GRE parser + builder | high | — |
| #46 | 5.1–5.2 Migration guide | medium | #44, #45 |
| #47 | v1.0 release checklist + version bump | medium | #37–#39, #44, #45 |

### 6.2 Ordering

```
#44 (IGMP) ──┐
             ├── #46 (migration guide) ── #47 (v1.0 release)
#45 (GRE)  ──┘
```

#37–#39 (macOS BPF, macOS L3, Windows NPcap) are on a separate track and not required before #44/#45.

---

## 7. Open Questions & Risks

### 7.1 Technical Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| IGMPv3 group records are complex | P2: partial v3 support | v1 only parses message type; group records as raw bytes |
| GRE routing SRE parsing is variable-length and recursion-prone | P2: complex if full | v1 returns routing as `Option<&[u8]>` raw bytes |

### 7.2 Assumptions

- IGMP 总是封装在 IPv4 中（IPv6 使用 MLD，是独立协议）
- GRE 的 protocol_type 是 EtherType 枚举（与现有 `types.rs` 一致）
- GRE checksum 计算使用与 ICMP 相同的 `internet_checksum()` 函数（覆盖整个 GRE 头 + payload）
- 迁移指南不需要覆盖 libpnet 的 `datalink::channel()` 返回的双工 tuple 模式（WireForge 用独立 reader/writer trait）
