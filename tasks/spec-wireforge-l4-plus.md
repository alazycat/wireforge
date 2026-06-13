# SPEC: WireForge 高层协议支持（L4+ 应用层协议）

> 技术规格说明基于: [tasks/prd-wireforge-l4-plus.md](prd-wireforge-l4-plus.md)
> 生成: 2026-06-13 | 项目: wireforge | 目标分支: main

## 1. Summary

### 1.1 What This SPEC Covers

本 SPEC 定义 WireForge 的第四个 crate — `wireforge-app`，在现有 L2–L4 协议栈之上增加应用层协议解析/构造（DNS、DHCP、NTP、HTTP/1.1）以及 pcap/pcapng 文件读写。

### 1.2 PRD Reference

- Source: `tasks/prd-wireforge-l4-plus.md`
- User Stories covered: US-001 ~ US-009
- Functional Requirements covered: FR-1 ~ FR-10

### 1.3 Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Crate 归属 | 单一 `wireforge-app` | 应用层协议体积小、依赖相同、统一入口减少认知负担 |
| DNS name 表示 | 分配 `String` | 压缩指针需要拼接多段标签，零拷贝在指针场景返回非连续片段 API 过于复杂 |
| HTTP 解析深度 | 纯行解析 | 80% 使用场景只需 method/URI/status/headers，body 作为 `&[u8]` 透传 |
| pcap 归属 | `wireforge-app` 内部模块 | 避免 crate 膨胀；pcap 天然与协议解析配对使用 |
| 解析错误风格 | `Option<T>` (同 core) | 热路径零开销，与现有 L2–L4 解析器一致 |
| 构造错误风格 | `Result<T, BuildError>` (同 core) | 复用 `wireforge-core::BuildError` |
| I/O 错误风格 | `IoError` (同 io crate) | 复用 `wireforge_io::IoError` |
| 文件 I/O 范式 | `std::io::Read/Write` 包装 | pcap 读写遵循 Rust 标准 I/O trait，兼容所有 `Read`/`Write` 实现 |

---

## 2. Architecture

### 2.1 System Context

```
┌──────────────────────────────────────────────────┐
│                   应用层 (用户代码)                 │
│         抓包工具 / 扫描器 / DNS 工具 / 分析器        │
└──────────────┬──────────────────────┬────────────┘
               │                      │
     ┌─────────▼────────┐  ┌─────────▼─────────┐
     │  wireforge-app   │  │  wireforge-io     │
     │ DNS/DHCP/NTP/HTTP│  │ 套接字封装 & 收发  │
     │ pcap/pcapng 读写  │  └─────────┬─────────┘
     └─────────┬────────┘            │
               │                      │
     ┌─────────▼──────────────────────▼─────────┐
     │              wireforge-packet             │
     │  协议分发 & Packet 枚举                    │
     └─────────┬────────────────────────────────┘
               │
     ┌─────────▼────────────────────────────────┐
     │              wireforge-core               │
     │  解析器 / 构造器 / 类型 / 校验和 / 宏      │
     │  (no_std + alloc)                         │
     └───────────────────────────────────────────┘
```

### 2.2 Component Design

#### wireforge-app (NEW)

- **职责:** DNS、DHCP、NTP、HTTP/1.1 协议解析/构造；pcap/pcapng 文件读写
- **依赖:** `wireforge-packet` (可访问 `wireforge-core` 类型)、`std`
- **不负责:** 套接字 I/O、加密、HTTP body 内容解析、TLS

| 模块 | 职责 | 关键类型 |
|------|------|----------|
| `dns` | DNS 消息解析/构造（RFC 1035） | `DnsPacket`, `DnsRecord`, `DnsPacketBuilder` |
| `dhcp` | DHCPv4 消息解析/构造（RFC 2131/2132） | `DhcpPacket`, `DhcpOption`, `DhcpPacketBuilder` |
| `ntp` | NTPv4 消息解析（RFC 5905） | `NtpPacket`, `NtpMode` |
| `http` | HTTP/1.1 请求/响应行解析 | `HttpRequest`, `HttpResponse`, `HeaderIter` |
| `pcap` | pcap/pcapng 文件读写 | `PcapReader`, `PcapWriter`, `PcapNgReader`, `PcapNgWriter` |

### 2.3 Module Interactions

```
DNS 解析流程:
  UdpPacket::new(&buf) → payload()
    → DnsPacket::new(payload) → questions() / answers()
    → 业务逻辑处理 DNS records

pcap 读取流程:
  PcapReader::new("capture.pcap")?
    → for packet in reader { ... }  // Iterator
    → EthernetPacket::new(&packet_data)?
    → 逐层协议分发
```

### 2.4 File Structure

```
wireforge-app/
├── Cargo.toml                    # 依赖 wireforge-packet
├── src/
│   ├── lib.rs                    # pub mod dns/dhcp/ntp/http/pcap
│   ├── dns/
│   │   ├── mod.rs                # pub mod parser/builder/types
│   │   ├── parser.rs             # DnsPacket, DnsRecord, DnsQuestion
│   │   ├── builder.rs            # DnsPacketBuilder
│   │   ├── types.rs              # DnsType, DnsClass, DnsOpcode, DnsRcode
│   │   └── name.rs               # QNAME 压缩解析/构造
│   ├── dhcp/
│   │   ├── mod.rs
│   │   ├── parser.rs             # DhcpPacket, DhcpOption
│   │   ├── builder.rs            # DhcpPacketBuilder
│   │   └── types.rs              # DhcpMessageType, DhcpOptionKind
│   ├── ntp/
│   │   ├── mod.rs
│   │   ├── parser.rs             # NtpPacket
│   │   └── types.rs              # NtpMode, NtpLeapIndicator
│   ├── http/
│   │   ├── mod.rs
│   │   ├── request.rs            # HttpRequest
│   │   ├── response.rs           # HttpResponse
│   │   └── headers.rs            # HeaderIter, Header
│   └── pcap/
│       ├── mod.rs
│       ├── reader.rs             # PcapReader + Iterator impl
│       ├── writer.rs             # PcapWriter
│       ├── ng_reader.rs          # PcapNgReader
│       ├── ng_writer.rs          # PcapNgWriter
│       └── types.rs              # PcapHeader, PcapNgBlockType, LinkType
├── fuzz/
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── dns.rs, dhcp.rs, ntp.rs, http.rs
└── benches/
    ├── dns_parse_bench.rs
    └── pcap_read_bench.rs
```

### 2.5 Workspace Integration

`Cargo.toml` (根) 修改:
```toml
[workspace]
members = [
    "wireforge-core",
    "wireforge-packet",
    "wireforge-io",
    "wireforge-app",   # NEW
]
```

---

## 3. Data Model

### 3.1 DNS Types (`dns/types.rs`)

```rust
/// DNS record types (QTYPE) per RFC 1035 + extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsType {
    A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, Unknown(u16),
}

impl From<u16> for DnsType { /* match 1→A, 28→AAAA, 2→NS, 5→CNAME, 6→SOA, 12→PTR, 15→MX, 16→TXT, 33→SRV */ }
impl From<DnsType> for u16 { /* reverse */ }

/// DNS class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClass { IN, CS, CH, HS, Unknown(u16) }

/// DNS opcode (from flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOpcode { Query, IQuery, Status, Notify, Update, Unknown(u8) }

/// DNS response code (from flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode { NoError, FormatError, ServerFailure, NameError, NotImplemented, Refused, Unknown(u8) }
```

### 3.2 DNS Parser API (`dns/parser.rs`)

```rust
pub struct DnsPacket<'a> { buf: &'a [u8] }

impl<'a> DnsPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self>; // len < 12 → None

    // Header fields
    pub fn transaction_id(&self) -> u16;
    pub fn flags(&self) -> u16;
    pub fn qr(&self) -> bool;            // bit 15: 0=query, 1=response
    pub fn opcode(&self) -> DnsOpcode;   // bits 14-11
    pub fn aa(&self) -> bool;            // bit 10
    pub fn tc(&self) -> bool;            // bit 9
    pub fn rd(&self) -> bool;            // bit 8
    pub fn ra(&self) -> bool;            // bit 7
    pub fn rcode(&self) -> DnsRcode;     // bits 3-0
    pub fn questions_count(&self) -> u16;
    pub fn answers_count(&self) -> u16;
    pub fn authorities_count(&self) -> u16;
    pub fn additionals_count(&self) -> u16;

    // Sections
    pub fn questions(&self) -> DnsQuestionIter<'a>;
    pub fn answers(&self) -> DnsRecordIter<'a>;
    pub fn authorities(&self) -> DnsRecordIter<'a>;
    pub fn additionals(&self) -> DnsRecordIter<'a>;
}
```

### 3.3 DNS Name Compression (`dns/name.rs`)

QNAME 编码规则（RFC 1035 Section 4.1.4）:
- 普通标签: `<length:u8><label...>`，length=0 终止
- 压缩指针: `<11xxxxxx:u16>` 高 2 bits = `11`，低 14 bits = 偏移量

压缩解析算法:
```rust
fn parse_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut jumped = false;
    let mut jump_count = 0u8;
    let mut end_pos = start;

    loop {
        if jump_count > 10 { return None; } // 防循环
        let label_len = buf[pos] as usize;
        if label_len & 0xC0 == 0xC0 {
            // 压缩指针
            if pos + 2 > buf.len() { return None; }
            let offset = read_u16be(&buf[pos..pos+2]) as usize & 0x3FFF;
            if !jumped { end_pos = pos + 2; }
            pos = offset;
            jumped = true;
            jump_count += 1;
        } else if label_len == 0 {
            if !jumped { end_pos = pos + 1; }
            break;
        } else {
            if pos + 1 + label_len > buf.len() { return None; }
            if !name.is_empty() { name.push('.'); }
            // ASCII only per RFC — labels are case-insensitive ASCII
            name.push_str(core::str::from_utf8(&buf[pos+1..pos+1+label_len]).ok()?);
            pos += 1 + label_len;
            if !jumped { end_pos = pos; }
        }
    }
    Some((name, end_pos))
}
```

### 3.4 DNS Record Types (`dns/parser.rs`)

```rust
pub struct DnsQuestion<'a> {
    pub name: String,       // 已解压完整域名
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

pub enum DnsRecord<'a> {
    A { name: String, ttl: u32, addr: Ipv4Addr },
    AAAA { name: String, ttl: u32, addr: Ipv6Addr },
    CNAME { name: String, ttl: u32, cname: String },
    MX { name: String, ttl: u32, preference: u16, exchange: String },
    NS { name: String, ttl: u32, nsdname: String },
    PTR { name: String, ttl: u32, ptrdname: String },
    SOA { name: String, ttl: u32, mname: String, rname: String, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    TXT { name: String, ttl: u32, data: &'a [u8] },
    SRV { name: String, ttl: u32, priority: u16, weight: u16, port: u16, target: String },
    Unknown { name: String, qtype: DnsType, ttl: u32, rdata: &'a [u8] },
}
```

### 3.5 DNS Builder API (`dns/builder.rs`)

```rust
pub struct DnsPacketBuilder {
    header: Vec<u8>,   // 12 bytes
    questions: Vec<Vec<u8>>,  // pre-encoded QNAME + QTYPE + QCLASS
    answers: Vec<Vec<u8>>,    // pre-encoded RRs
    authorities: Vec<Vec<u8>>,
    additionals: Vec<Vec<u8>>,
}

impl DnsPacketBuilder {
    pub fn new() -> Self;
    pub fn transaction_id(mut self, id: u16) -> Self;
    pub fn query() -> Self;     // 预设 QR=0, RD=1
    pub fn response() -> Self;  // 预设 QR=1, RA=1
    pub fn authoritative(mut self, aa: bool) -> Self;
    pub fn truncated(mut self, tc: bool) -> Self;
    pub fn recursion_desired(mut self, rd: bool) -> Self;
    pub fn recursion_available(mut self, ra: bool) -> Self;
    pub fn rcode(mut self, rcode: DnsRcode) -> Self;

    // Add sections
    pub fn add_question(mut self, name: &str, qtype: DnsType, qclass: DnsClass) -> Self;
    pub fn add_answer(mut self, record: &DnsRecord) -> Self;
    pub fn add_authority(mut self, record: &DnsRecord) -> Self;
    pub fn add_additional(mut self, record: &DnsRecord) -> Self;

    pub fn build(mut self) -> Vec<u8>;  // 自动更新各 count 字段
}
```

### 3.6 DHCP Types (`dhcp/types.rs`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover, Offer, Request, Declined, Ack, Nak, Release, Inform, Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOptionKind {
    SubnetMask, Router, DnsServer, HostName, DomainName,
    BroadcastAddr, RequestedIp, LeaseTime, MessageType,
    ServerId, ParameterList, RenewalTime, RebindingTime,
    End, Unknown(u8),
}

#[derive(Debug, Clone)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DnsServer(Vec<Ipv4Addr>),
    HostName(String),
    DomainName(String),
    BroadcastAddr(Ipv4Addr),
    RequestedIp(Ipv4Addr),
    LeaseTime(u32),
    MessageType(DhcpMessageType),
    ServerId(Ipv4Addr),
    ParameterList(Vec<u8>),
    RenewalTime(u32),
    RebindingTime(u32),
    End,
    Unknown { code: u8, data: Vec<u8> },
}
```

### 3.7 DHCP Parser API (`dhcp/parser.rs`)

```rust
pub const DHCP_MIN_LEN: usize = 240; // 固定头(236) + cookie(4)

pub struct DhcpPacket<'a> { buf: &'a [u8] }

impl<'a> DhcpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self>;  // len < 240 || cookie != MAGIC → None

    // Fixed fields
    pub fn op(&self) -> u8;           // 1=request, 2=reply
    pub fn htype(&self) -> u8;        // hardware type (1=Ethernet)
    pub fn hlen(&self) -> u8;         // hardware address length
    pub fn hops(&self) -> u8;
    pub fn xid(&self) -> u32;         // transaction ID
    pub fn secs(&self) -> u16;
    pub fn flags(&self) -> u16;       // bit 15 = broadcast
    pub fn ciaddr(&self) -> Ipv4Addr;
    pub fn yiaddr(&self) -> Ipv4Addr;
    pub fn siaddr(&self) -> Ipv4Addr; // next server
    pub fn giaddr(&self) -> Ipv4Addr; // relay agent
    pub fn chaddr(&self) -> &[u8];    // client hardware address (hlen bytes)
    pub fn sname(&self) -> &[u8];     // 64 bytes, may contain options
    pub fn file(&self) -> &[u8];      // 128 bytes, may contain options
    pub fn magic_cookie(&self) -> u32;

    // Options
    pub fn options(&self) -> DhcpOptionIter<'a>;
    pub fn message_type(&self) -> Option<DhcpMessageType>;  // convenience
}
```

### 3.8 DHCP Option Overload 处理

RFC 2132 Section 9.6: option 52 (Option Overload) 指示 options 可能溢出到 `file` 和/或 `sname` 字段。

解析逻辑:
1. 先解析 options 区 (从 byte 240 开始)，同时检查是否有 option 52
2. 如果 option 52 = 1: 附加解析 `file` 字段 (128 bytes)
3. 如果 option 52 = 2: 附加解析 `sname` 字段 (64 bytes)
4. 如果 option 52 = 3: 附加解析 file 和 sname
5. 遇到 `End` (code 0) 停止当前区
6. 迭代器合并三个区的结果

### 3.9 NTP Types (`ntp/types.rs`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtpMode { Reserved, SymmetricActive, SymmetricPassive, Client, Server, Broadcast, Control, Unknown(u8) }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtpLeapIndicator { NoWarning, LastMinute61, LastMinute59, Alarm }
```

### 3.10 NTP Parser API (`ntp/parser.rs`)

```rust
pub const NTP_PACKET_LEN: usize = 48;

pub struct NtpPacket<'a> { buf: &'a [u8] }

impl<'a> NtpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self>;  // len < 48 → None

    pub fn leap(&self) -> NtpLeapIndicator;
    pub fn version(&self) -> u8;
    pub fn mode(&self) -> NtpMode;
    pub fn stratum(&self) -> u8;
    pub fn poll_interval(&self) -> i8;   // signed, log2 seconds
    pub fn precision(&self) -> i8;       // signed, log2 seconds
    pub fn root_delay(&self) -> Duration;
    pub fn root_dispersion(&self) -> Duration;
    pub fn reference_id(&self) -> [u8; 4];
    pub fn reference_timestamp(&self) -> Option<Duration>; // since 1900-01-01
    pub fn origin_timestamp(&self) -> Option<Duration>;
    pub fn receive_timestamp(&self) -> Option<Duration>;
    pub fn transmit_timestamp(&self) -> Option<Duration>;
}
```

**NTP 时间戳转换** (RFC 5905):
- NTP 时间戳: 64-bit 定点数（32-bit 秒 + 32-bit 小数秒），epoc = 1900-01-01
- 转为 `Duration`: `(seconds - NTP_EPOCH_DELTA) as u64 * 1_000_000_000 + (fraction * 1_000_000_000 >> 32)`，其中 `NTP_EPOCH_DELTA = 2_208_988_800`（1900→1970 秒差）

### 3.11 HTTP Types (`http/`)

```rust
// http/headers.rs
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a [u8],  // raw bytes, caller may decode as UTF-8 or latin1
}

pub struct HeaderIter<'a> { data: &'a [u8] }

impl<'a> Iterator for HeaderIter<'a> {
    type Item = Option<Header<'a>>; // None = malformed line, caller decides
}

// http/request.rs
pub struct HttpRequest<'a> { buf: &'a [u8] }

impl<'a> HttpRequest<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self>;
    pub fn method(&self) -> &str;       // e.g. "GET", "POST"
    pub fn uri(&self) -> &str;          // raw URI bytes as UTF-8
    pub fn version(&self) -> &str;      // "HTTP/1.0" or "HTTP/1.1"
    pub fn headers(&self) -> HeaderIter;
    pub fn body(&self) -> &[u8];        // everything after \r\n\r\n
}

// http/response.rs
pub struct HttpResponse<'a> { buf: &'a [u8] }

impl<'a> HttpResponse<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self>;
    pub fn version(&self) -> &str;
    pub fn status_code(&self) -> u16;
    pub fn reason(&self) -> &str;       // e.g. "OK", "Not Found"
    pub fn headers(&self) -> HeaderIter;
    pub fn body(&self) -> &[u8];
}
```

**行解析规则:**
- 行终止符: `\r\n`（严格模式，不处理单独的 `\n`）
- 请求行: `METHOD SP URI SP VERSION\r\n`
- 响应行: `VERSION SP STATUS SP REASON\r\n`
- Header 行: `Name: Value\r\n`（value 可为空）
- 空行 `\r\n\r\n` 分隔 headers 和 body
- **不处理** obsolete line folding（RFC 7230 已弃用）

### 3.12 pcap Types (`pcap/types.rs`)

```rust
/// pcap global header (24 bytes).
#[repr(C)]
pub struct PcapHeader {
    pub magic_number: u32,   // 0xa1b2c3d4 or 0xd4c3b2a1 (swapped)
    pub version_major: u16,  // 2
    pub version_minor: u16,  // 4
    pub thiszone: i32,       // GMT offset
    pub sigfigs: u32,        // timestamp accuracy
    pub snaplen: u32,        // max packet length
    pub network: u32,        // link-layer type
}

/// pcap packet record header (16 bytes).
#[repr(C)]
pub struct PcapRecordHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,       // bytes actually in this record
    pub orig_len: u32,       // bytes on the wire
}

pub enum Endianness { Big, Little }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType { Ethernet, Raw, Unknown(u32) }

impl From<u32> for LinkType {
    fn from(v: u32) -> Self {
        match v { 1 => LinkType::Ethernet, 101 => LinkType::Raw, _ => LinkType::Unknown(v) }
    }
}
```

### 3.13 pcap Reader API (`pcap/reader.rs`)

```rust
pub struct PcapReader<R: Read> {
    reader: R,
    header: PcapHeader,
    endian: Endianness,
}

impl<R: Read> PcapReader<R> {
    /// Read pcap global header. Returns error if magic number is invalid.
    pub fn new(mut reader: R) -> Result<Self, IoError>;

    pub fn header(&self) -> &PcapHeader;
    pub fn link_type(&self) -> LinkType;
}

impl<R: Read> Iterator for PcapReader<R> {
    type Item = Result<(Duration, Vec<u8>), IoError>;
    // 读取 record header → 读取 incl_len 字节 → 返回 (timestamp, packet_data)
}
```

### 3.14 pcap Writer API (`pcap/writer.rs`)

```rust
pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut writer: W, link_type: LinkType) -> Result<Self, IoError>;
    pub fn write(&mut self, ts: Duration, packet: &[u8]) -> Result<(), IoError>;
    pub fn flush(&mut self) -> Result<(), IoError>;
}
```

### 3.15 pcapng 设计

pcapng 格式（RFC: draft-tuexen-opsawg-pcapng）最常用的 3 种 Block:

| Block | Type Code | 用途 |
|-------|-----------|------|
| Section Header Block (SHB) | 0x0A0D0D0A | 文件头，含字节序标记和版本 |
| Interface Description Block (IDB) | 0x00000001 | 接口信息（link type, snaplen） |
| Enhanced Packet Block (EPB) | 0x00000006 | 数据包（timestamp, captured_len, packet_data） |

**通用 Block 结构:**
```
[Block Type: u32][Block Total Length: u32]
[Block Body (variable)]
[Block Total Length: u32]  // 重复
```

```rust
pub struct PcapNgReader<R: Read> { /* ... */ }
pub struct PcapNgWriter<W: Write> { /* ... */ }

impl<W: Write> PcapNgWriter<W> {
    pub fn new(writer: W, link_type: LinkType) -> Result<Self, IoError>;
    pub fn write_epb(&mut self, ts: Duration, packet: &[u8]) -> Result<(), IoError>;
}

impl<R: Read> PcapNgReader<R> {
    pub fn new(reader: R) -> Result<Self, IoError>;
    pub fn link_type(&self) -> Option<LinkType>; // from first IDB
}
```

### 3.16 pcapng Block Iterator

```rust
pub enum PcapNgBlock {
    SectionHeader { byte_order: Endianness, version: u16 },
    InterfaceDescription { link_type: LinkType, snap_len: u32 },
    EnhancedPacket { timestamp: Duration, data: Vec<u8> },
    Unknown { block_type: u32, data: Vec<u8> },
}

impl<R: Read> Iterator for PcapNgReader<R> {
    type Item = Result<PcapNgBlock, IoError>;
}
```

---

## 4. Error Handling

### 4.1 Error Types

解析器沿用 `Option<T>` 风格（同 `wireforge-core`）。I/O 复用 `wireforge_io::IoError`:

```rust
// wireforge-io/src/error.rs (需扩展)
pub enum IoError {
    Socket(std::io::Error),
    Parse(&'static str),
    Timeout,
    // NEW: pcap-specific
    InvalidMagic(u32),
    UnsupportedVersion { major: u16, minor: u16 },
    TruncatedRecord { expected: u32, got: usize },
    // NEW: DNS-specific
    NameTooLong(usize),
    CompressionLoop,
}
```

### 4.2 Failure Modes

| 场景 | 错误 | 处理 |
|------|------|------|
| pcap magic number 不匹配 | `InvalidMagic` | 返回 Err，不尝试修复 |
| DNS name 压缩循环 | `CompressionLoop` | 限制最大跳转 10 次 |
| DNS name 标签过长（>63） | `NameTooLong` | 跳过该记录，继续解析 |
| DHCP cookie 不匹配 | `None` | 拒绝解析 |
| pcap record 截断 | `TruncatedRecord` | 返回 Err |
| HTTP 不是有效的 UTF-8 | `None` | 拒绝解析 |
| NTP 时间戳溢出 | `None` (timestamp 返回 None) | 字段级容错 |

---

## 5. API Design Summary

### 5.1 Parser Contract (所有协议模块)

```rust
impl<'a> XxxPacket<'a> {
    /// 零拷贝构造。失败返回 None（不 panic、不分配）。
    pub fn new(buf: &'a [u8]) -> Option<Self>;
}
```

### 5.2 Builder Contract

```rust
impl XxxPacketBuilder {
    /// 创建 Builder，提供合理默认值。
    pub fn new() -> Self;
    /// 序列化为 `Vec<u8>`。自动计算 checksum/length/count 等依赖字段。
    pub fn build(self) -> Vec<u8>;
}
```

### 5.3 I/O Contract (pcap 模块)

```rust
impl<R: Read> PcapReader<R> {
    pub fn new(reader: R) -> Result<Self, IoError>;
}
impl<R: Read> Iterator for PcapReader<R> { /* ... */ }

impl<W: Write> PcapWriter<W> {
    pub fn new(writer: W, link_type: LinkType) -> Result<Self, IoError>;
    pub fn write(&mut self, ts: Duration, packet: &[u8]) -> Result<(), IoError>;
}
```

---

## 6. Testing Strategy

### 6.1 Unit Tests

| 模块 | 测试数量 | 覆盖重点 |
|------|----------|----------|
| DNS parser | 6+ | 标准查询、标准响应、含 CNAME 链、AAAA 记录、压缩指针、格式错误 |
| DNS builder | 3+ | 构造查询、构造响应、构造→解析往返 |
| DHCP parser | 5+ | Discover, Offer, Ack, Nak, Option Overload |
| DHCP builder | 2+ | 构造 Discover、构造→解析往返 |
| NTP parser | 3+ | Client 请求、Server 响应、version 4 |
| HTTP request | 3+ | GET, POST, 含多个 headers |
| HTTP response | 3+ | 200 OK, 404, 301 Redirect |
| pcap reader | 3+ | 读 header、读 0 包、读 5 包往返 |
| pcap writer | 2+ | 写 header、写 5 包往返 |
| pcapng reader | 2+ | 读 SHB+IDB+EPB |
| pcapng writer | 2+ | 写 SHB+IDB+EPB 往返 |

### 6.2 测试样本

每个协议至少 1 个真实二进制样本（Wireshark/tcpdump 捕获），硬编码为 `&[u8]` 常量。

### 6.3 Fuzz Tests

4 个 fuzz target:
```
wireforge-app/fuzz/fuzz_targets/
├── dns.rs       — DnsPacket::new() + 所有 accessor + 消费所有 records
├── dhcp.rs      — DhcpPacket::new() + 所有 accessor + 消费所有 options
├── ntp.rs       — NtpPacket::new() + 所有 accessor
└── http.rs      — HttpRequest::parse() + HttpResponse::parse() + 消费所有 headers
```

### 6.4 Benchmarks

- `dns_parse_bench`: 解析典型 100-byte DNS 响应（A 记录）
- `pcap_read_bench`: 读取含 10k 数据包的 pcap 文件

---

## 7. Implementation Plan

### 7.1 Phase Order (依赖关系)

```
Phase 1: Crate 基础设施
  ├── wireforge-app Cargo.toml + lib.rs
  └── IoError 扩展 (wireforge-io)

Phase 2: DNS (无内部依赖)
  ├── dns/types.rs
  ├── dns/name.rs    (QNAME 压缩)
  ├── dns/parser.rs  (依赖 types + name)
  └── dns/builder.rs (依赖 types + name)

Phase 3: DHCP (无内部依赖)
  ├── dhcp/types.rs
  ├── dhcp/parser.rs
  └── dhcp/builder.rs

Phase 4: NTP (无内部依赖)
  ├── ntp/types.rs
  └── ntp/parser.rs

Phase 5: HTTP (无内部依赖)
  ├── http/headers.rs
  ├── http/request.rs
  └── http/response.rs

Phase 6: pcap (无内部依赖)
  ├── pcap/types.rs
  ├── pcap/reader.rs
  ├── pcap/writer.rs
  ├── pcap/ng_reader.rs
  └── pcap/ng_writer.rs

Phase 7: 质量保障
  ├── Fuzz targets (dns, dhcp, ntp, http)
  ├── Benchmarks (dns_parse, pcap_read)
  └── Docs + examples
```

### 7.2 Issue Mapping

| Issue | Phase | SPEC Sections | Priority | Depends On |
|-------|-------|--------------|----------|------------|
| #1 workspace + error | 1 | 2.4, 2.5, 4.1 | high | — |
| #2 DNS types + name | 2 | 3.1, 3.3 | high | #1 |
| #3 DNS parser + builder | 2 | 3.2, 3.4, 3.5 | high | #2 |
| #4 DHCP types + parser | 3 | 3.6, 3.7, 3.8 | high | #1 |
| #5 DHCP builder | 3 | 3.6, 3.7 | high | #4 |
| #6 NTP types + parser | 4 | 3.9, 3.10 | medium | #1 |
| #7 HTTP request + response | 5 | 3.11 | medium | #1 |
| #8 pcap types + reader/writer | 6 | 3.12, 3.13, 3.14 | high | #1 |
| #9 pcapng reader/writer | 6 | 3.15, 3.16 | medium | #8 |
| #10 Fuzz + bench + docs | 7 | 6.3, 6.4 | low | #2–#9 |
| #11 Integration examples | 7 | — | low | all |

### 7.3 Incremental Delivery

每个 Phase 独立可发布:
- Phase 1-2 完成后即可发布 pre-release 供 DNS 使用
- Phase 3-6 逐步添加协议，不破坏已有 API
- Phase 7 不影响功能，可延后

---

## 8. Open Questions & Risks

### 8.1 Unresolved Questions

- DHCPv6 是否作为 v2 添加？PRD 定义为 Non-Goal
- pcapng 是否需要支持 Name Resolution Block (NRB)？v1 不需要
- 是否需要支持 DNS EDNS0 (RFC 6891)？v1 作为 Unknown record 处理

### 8.2 Technical Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| DNS name 压缩解析复杂度 | P0: 核心功能错误 | 参考 `dns-parser` crate 实现，充分测试压缩指针 |
| DHCP Option Overload 遗漏 options | P2: 部分消息解析不完整 | 按 RFC 2132 精确实现，测试含 option 52 的样本 |
| NTP 时间戳 epoch 转换错误 | P3: 时间显示不准 | 使用已知 NTP 时间戳的独立验证（ntpdate 输出） |
| pcapng 格式变体 | P2: 不同 Wireshark 版本兼容性 | 仅支持 SHB+IDB+EPB，跳过未知 Block 类型 |

### 8.3 Assumptions

- `wireforge-core::BuildError` 可直接复用，无需扩展
- `wireforge_io::IoError` 可直接扩展而无需 break 现有 API
- DNS 域名总是有效的 ASCII，不需要 IDN/Punycode 处理
- pcap 文件大小适中（< 2GB），无需处理 > 2GB 的 pcap 格式变体
