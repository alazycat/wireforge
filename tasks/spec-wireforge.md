# SPEC: WireForge — Rust 网络数据包处理库

> 技术规格说明基于: [tasks/prd-wireforge.md](prd-wireforge.md)
> 生成: 2026-06-13 | 项目: greenfield | 目标分支: main

## 1. Summary

### 1.1 What This SPEC Covers

WireForge 是一个纯 Rust 网络数据包处理库，完整替代 libpnet。本 SPEC 定义三层 crate 架构（core / packet / io）、零拷贝解析器 API、Builder 构造器 API、Linux 原始套接字 I/O 接口，以及协议模块的完整拆分方案。覆盖 User Stories US-001 至 US-013，及 Functional Requirements FR-1 至 FR-14。

### 1.2 PRD Reference

- Source: `tasks/prd-wireforge.md`
- User Stories: US-001 ~ US-013
- Functional Requirements: FR-1 ~ FR-14

### 1.3 Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| 解析器实现 | 手写偏移 + 内部宏 | 零依赖、最大控制、编译器友好优化 |
| Crate 拆分 | 三层: core / packet / io | 关注点分离, core 保持 no_std, io 隔离 Linux 依赖 |
| 解析错误风格 | `Option<T>` 返回 | 热路径性能优先, 无需分配错误对象 |
| 构造错误风格 | `Result<T, BuildError>` | 构造不是热路径, 提供字段级诊断信息 |
| 套接字依赖 | `socket2` crate | 比 libc 安全, 比直接 syscall 可移植 |
| 校验和算法 | RFC 1071 标准实现 + 内联 | 正确且性能可预测 |
| PRD Open Questions | 全部 v2 | v1 聚焦最小可用 — 解析 + 构造 + 收发 |

---

## 2. Architecture

### 2.1 System Context

```
┌──────────────────────────────────────────────────┐
│                   应用层 (用户代码)                 │
│         抓包工具 / 扫描器 / ping / 监控             │
└──────────────┬──────────────────────┬────────────┘
               │                      │
     ┌─────────▼────────┐  ┌─────────▼─────────┐
     │ wireforge-packet  │  │  wireforge-io     │
     │ 协议分发 & 枚举    │  │ 套接字封装 & 收发  │
     └─────────┬────────┘  └─────────┬─────────┘
               │                      │
     ┌─────────▼──────────────────────▼─────────┐
     │              wireforge-core               │
     │  解析器 / 构造器 / 类型 / 校验和 / 宏      │
     │  (no_std + alloc)                         │
     └───────────────────────────────────────────┘
```

三层自上而下依赖: `io` → `packet` → `core`。`core` 零依赖（除 `alloc`）。

### 2.2 Component Design

#### wireforge-core

- **职责:** 协议头类型、零拷贝解析器、Builder 构造器、校验和工具、内部宏
- **依赖:** 仅 `core` + `alloc`（no_std 兼容）
- **不负责:** 套接字 I/O、协议分发逻辑

#### wireforge-packet

- **职责:** `Packet` 统一枚举、从 L2/L3 字节流自动分发到具体协议、payload 解析辅助
- **依赖:** `wireforge-core`
- **不负责:** 套接字 I/O

#### wireforge-io

- **职责:** AF_PACKET L2 收发、raw socket L3 收发、`PacketReceiver` trait、超时控制
- **依赖:** `wireforge-packet` + `socket2`
- **平台:** Linux only

### 2.3 Module Interactions

```
接收流程:
  L2Receiver::recv()
    → socket2 recvfrom → 缓冲区
    → EthernetPacket::new(&buf) → Option<EthernetPacket>
    → 用户自行解析上层协议

发送流程:
  Ipv4PacketBuilder::new()
    → .source(...).destination(...).protocol(...).payload(...)
    → .build() → Result<Vec<u8>, BuildError>
    → L3Sender::send(&packet_bytes) → Result<usize, IoError>
```

### 2.4 File Structure

```
wireforge/
├── Cargo.toml              # workspace
├── README.md
├── examples/
│   ├── packet_dump.rs      # 抓包示例
│   ├── packet_build.rs     # 构造与发送示例
│   └── simple_ping.rs      # ping 实现
│
├── wireforge-core/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs           # crate docs, re-export 所有协议模块
│       ├── util.rs          # checksum, byte read helpers, internal macros
│       ├── ether.rs         # EthernetPacket + EthernetPacketBuilder
│       ├── vlan.rs          # VlanPacket (802.1Q / 802.1ad)
│       ├── arp.rs           # ArpPacket + ArpPacketBuilder
│       ├── ipv4.rs          # Ipv4Packet + Ipv4PacketBuilder
│       ├── ipv6.rs          # Ipv6Packet + ext headers + Ipv6PacketBuilder
│       ├── icmp.rs          # IcmpPacket (v4) + Icmpv6Packet + NDP types
│       ├── tcp.rs           # TcpPacket + TcpOption + TcpPacketBuilder
│       ├── udp.rs           # UdpPacket + UdpPacketBuilder
│       └── types.rs         # EtherType, IpProtocol, common enums/consts
│
├── wireforge-packet/
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs           # Packet enum, dispatch helpers
│
└── wireforge-io/
    ├── Cargo.toml
    └── src/
        ├── lib.rs           # crate docs, re-exports
        ├── l2.rs            # L2Receiver, L2Sender (AF_PACKET)
        ├── l3.rs            # L3Receiver, L3Sender (raw socket)
        ├── receiver.rs      # PacketReceiver trait
        └── error.rs         # IoError enum
```

---

## 3. Data Model

### 3.1 Schema-less Design

本项目不涉及数据库。数据结构均为内存中的网络数据包表示。

### 3.2 Core Type Definitions

```rust
// wireforge-core/src/types.rs

/// Ethernet 帧类型 (ethertype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86DD,
    Vlan = 0x8100,
    VlanDouble = 0x88A8,
    // ... 其他常见值
    Unknown(u16),
}

impl From<u16> for EtherType { /* ... */ }
impl From<EtherType> for u16 { /* ... */ }

/// IP 协议号
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
    // ...
    Unknown(u8),
}

impl From<u8> for IpProtocol { /* ... */ }
impl From<IpProtocol> for u8 { /* ... */ }

/// ARP 操作码
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArpOperation {
    Request = 1,
    Reply = 2,
    // RARP ...
    Unknown(u16),
}

/// ARP 硬件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArpHardwareType {
    Ethernet = 1,
    Unknown(u16),
}
```

### 3.3 Parser Types (零拷贝)

通用模式 — 每种协议解析器遵循此约定：

```rust
/// 零拷贝协议解析器。持有底层字节切片的不可变引用。
pub struct XxxPacket<'a> {
    buf: &'a [u8],
}

impl<'a> XxxPacket<'a> {
    /// 尝试从字节切片解析。返回 None 如果数据不足以构成合法协议头。
    /// 注意: 仅做长度检查，不做语义校验（如未知字段值仍返回 Some）。
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < MIN_HEADER_LEN { return None; }
        Some(Self { buf })
    }

    // 字段访问器: 内联的偏移读取
    pub fn payload(&self) -> &'a [u8] { &self.buf[header_len..] }
}
```

### 3.4 Builder Types (拥有缓冲区)

```rust
/// 协议数据包构造器。内部持有 Vec<u8> 缓冲区。
pub struct XxxPacketBuilder {
    buf: Vec<u8>,
    payload: Option<Vec<u8>>,
}

impl XxxPacketBuilder {
    pub fn new() -> Self { /* 预分配默认头部 */ }

    // 链式 setter, 返回 Self
    pub fn field_name(mut self, value: FieldType) -> Self { ... }

    /// 设置 payload
    pub fn payload(mut self, data: &[u8]) -> Result<Self, BuildError> { ... }

    /// 完成构造, 计算校验和, 返回完整数据包字节
    pub fn build(mut self) -> Result<Vec<u8>, BuildError> { ... }
}
```

### 3.5 Error Types

```rust
// wireforge-core
// 解析器 — 无错误类型, 使用 Option<T>

/// 构造器错误
#[derive(Debug, Clone)]
pub enum BuildError {
    /// Payload 超出协议允许的最大长度
    PayloadTooLarge { max: usize, actual: usize },
    /// 字段值无效（参数超出合法范围）
    InvalidField { field: &'static str, reason: &'static str },
}

// wireforge-io
#[derive(Debug)]
pub enum IoError {
    /// 底层套接字错误
    Socket(std::io::Error),
    /// 接收到的数据无法解析
    Parse(&'static str),
    /// 操作超时
    Timeout,
}
```

### 3.6 Protocol Header Constants

```rust
// 每个协议模块内部定义的常量
pub(crate) const ETHER_HEADER_LEN: usize = 14;
pub(crate) const VLAN_HEADER_LEN: usize = 4;
pub(crate) const IPV4_MIN_HEADER_LEN: usize = 20;
pub(crate) const IPV6_HEADER_LEN: usize = 40;
pub(crate) const TCP_MIN_HEADER_LEN: usize = 20;
pub(crate) const UDP_HEADER_LEN: usize = 8;
pub(crate) const ARP_HEADER_LEN: usize = 28; // for Ethernet/IPv4
pub(crate) const ICMP_HEADER_LEN: usize = 8;
```

---

## 4. API Design

### 4.1 Parser API — 每种协议

```rust
// wireforge-core/src/ether.rs

pub struct EthernetPacket<'a> { buf: &'a [u8] }

impl<'a> EthernetPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> { /* len >= 14 */ }

    pub fn dst_mac(&self) -> [u8; 6] { /* buf[0..6] */ }
    pub fn src_mac(&self) -> [u8; 6] { /* buf[6..12] */ }
    pub fn ethertype(&self) -> EtherType { /* buf[12..14] -> u16 */ }
    pub fn payload(&self) -> &'a [u8] { &self.buf[14..] }
}
```

```rust
// wireforge-core/src/ipv4.rs

pub struct Ipv4Packet<'a> { buf: &'a [u8] }

impl<'a> Ipv4Packet<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 20 { return None; }
        let ihl = (buf[0] & 0x0F) as usize * 4;
        if buf.len() < ihl { return None; }
        Some(Self { buf })
    }

    pub fn version(&self) -> u8 { self.buf[0] >> 4 }
    pub fn ihl(&self) -> u8 { self.buf[0] & 0x0F }
    pub fn dscp(&self) -> u8 { self.buf[1] >> 2 }
    pub fn ecn(&self) -> u8 { self.buf[1] & 0x03 }
    pub fn total_length(&self) -> u16 { read_u16be(&self.buf[2..]) }
    pub fn identification(&self) -> u16 { read_u16be(&self.buf[4..]) }
    pub fn flags(&self) -> u8 { self.buf[6] >> 5 }
    pub fn fragment_offset(&self) -> u16 { read_u16be(&self.buf[6..]) & 0x1FFF }
    pub fn ttl(&self) -> u8 { self.buf[8] }
    pub fn protocol(&self) -> IpProtocol { IpProtocol::from(self.buf[9]) }
    pub fn checksum(&self) -> u16 { read_u16be(&self.buf[10..]) }
    pub fn source(&self) -> Ipv4Addr { Ipv4Addr::from(read_u32be(&self.buf[12..])) }
    pub fn destination(&self) -> Ipv4Addr { Ipv4Addr::from(read_u32be(&self.buf[16..])) }
    pub fn options(&self) -> &'a [u8] {
        let opt_len = self.ihl() as usize * 4 - 20;
        &self.buf[20..20 + opt_len]
    }
    pub fn payload(&self) -> &'a [u8] { &self.buf[self.ihl() as usize * 4..] }

    pub fn header_length(&self) -> usize { self.ihl() as usize * 4 }
    pub fn verify_checksum(&self) -> bool {
        internet_checksum(&self.buf[..self.header_length()]) == 0
    }
}
```

```rust
// wireforge-core/src/tcp.rs

pub struct TcpPacket<'a> { buf: &'a [u8] }

impl<'a> TcpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 20 { return None; }
        let data_offset = ((buf[12] >> 4) * 4) as usize;
        if buf.len() < data_offset { return None; }
        Some(Self { buf })
    }

    pub fn source_port(&self) -> u16 { read_u16be(&self.buf[0..]) }
    pub fn destination_port(&self) -> u16 { read_u16be(&self.buf[2..]) }
    pub fn sequence(&self) -> u32 { read_u32be(&self.buf[4..]) }
    pub fn ack_number(&self) -> u32 { read_u32be(&self.buf[8..]) }
    pub fn data_offset(&self) -> u8 { self.buf[12] >> 4 }
    pub fn flags(&self) -> u8 { self.buf[13] }  // NS | CWR | ECE | URG | ACK | PSH | RST | SYN | FIN
    pub fn window(&self) -> u16 { read_u16be(&self.buf[14..]) }
    pub fn checksum(&self) -> u16 { read_u16be(&self.buf[16..]) }
    pub fn urgent_pointer(&self) -> u16 { read_u16be(&self.buf[18..]) }
    pub fn options(&self) -> TcpOptionsIter<'a> { ... }
    pub fn payload(&self) -> &'a [u8] { &self.buf[self.data_offset() as usize * 4..] }

    pub fn syn(&self) -> bool { self.flags() & 0x02 != 0 }
    pub fn ack(&self) -> bool { self.flags() & 0x10 != 0 }
    pub fn fin(&self) -> bool { self.flags() & 0x01 != 0 }
    pub fn rst(&self) -> bool { self.flags() & 0x04 != 0 }
    pub fn psh(&self) -> bool { self.flags() & 0x08 != 0 }
    pub fn urg(&self) -> bool { self.flags() & 0x20 != 0 }

    pub fn header_length(&self) -> usize { self.data_offset() as usize * 4 }

    /// 验证 TCP 校验和 (需提供 IP 伪头信息)
    pub fn verify_checksum(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool { ... }
}
```

### 4.2 Builder API

```rust
// wireforge-core/src/tcp.rs

pub struct TcpPacketBuilder {
    buf: Vec<u8>,     // 20 字节默认 TCP 头
    options_buf: Vec<u8>,
    payload: Option<Vec<u8>>,
}

impl TcpPacketBuilder {
    pub fn new() -> Self {
        let mut buf = vec![0u8; 20];
        buf[12] = 0x50; // data_offset = 5 (20 bytes header)
        Self { buf, options_buf: Vec::new(), payload: None }
    }

    pub fn source_port(mut self, port: u16) -> Self {
        self.buf[0..2].copy_from_slice(&port.to_be_bytes());
        self
    }
    pub fn destination_port(mut self, port: u16) -> Self {
        self.buf[2..4].copy_from_slice(&port.to_be_bytes());
        self
    }
    pub fn sequence(mut self, seq: u32) -> Self {
        self.buf[4..8].copy_from_slice(&seq.to_be_bytes());
        self
    }
    pub fn ack_number(mut self, ack: u32) -> Self {
        self.buf[8..12].copy_from_slice(&ack.to_be_bytes());
        self
    }
    pub fn window(mut self, window: u16) -> Self {
        self.buf[14..16].copy_from_slice(&window.to_be_bytes());
        self
    }
    // flags
    pub fn syn(mut self) -> Self { self.buf[13] |= 0x02; self }
    pub fn ack(mut self) -> Self { self.buf[13] |= 0x10; self }
    pub fn fin(mut self) -> Self { self.buf[13] |= 0x01; self }
    pub fn rst(mut self) -> Self { self.buf[13] |= 0x04; self }
    pub fn psh(mut self) -> Self { self.buf[13] |= 0x08; self }
    // options
    pub fn add_option(mut self, option: TcpOption) -> Result<Self, BuildError> { ... }
    // payload
    pub fn payload(mut self, data: &[u8]) -> Result<Self, BuildError> { ... }

    pub fn build(mut self) -> Result<Vec<u8>, BuildError> { ... }
}
```

### 4.3 I/O API

```rust
// wireforge-io/src/l2.rs

use socket2::{Socket, Domain, Type, Protocol};

pub struct L2Receiver {
    socket: Socket,
    buffer: Vec<u8>,
}

impl L2Receiver {
    /// 打开 AF_PACKET 套接字, 绑定到指定接口
    pub fn new(ifname: &str) -> Result<Self, IoError> { ... }
    /// 启用混杂模式
    pub fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError> { ... }
    /// 接收一个 L2 帧, 阻塞
    pub fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> { ... }
    /// 设置接收超时
    pub fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> { ... }
}
```

```rust
// wireforge-io/src/l3.rs

pub struct L3Receiver {
    socket: Socket,
    buffer: Vec<u8>,
}

impl L3Receiver {
    /// 打开 AF_INET SOCK_RAW 套接字
    pub fn new(protocol: IpProtocol) -> Result<Self, IoError> { ... }
    /// 接收一个 IPv4 数据包
    pub fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError> { ... }
    /// 设置 IP_HDRINCL (发送时)
    pub fn set_header_included(&mut self, on: bool) -> Result<(), IoError> { ... }
    pub fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> { ... }
}
```

```rust
// wireforge-io/src/l2.rs

pub struct L2Sender {
    socket: Socket,
}

impl L2Sender {
    pub fn new(ifname: &str) -> Result<Self, IoError> { ... }
    /// 发送原始 L2 帧字节
    pub fn send(&self, packet: &[u8]) -> Result<usize, IoError> { ... }
}
```

```rust
// wireforge-io/src/l3.rs

pub struct L3Sender {
    socket: Socket,
}

impl L3Sender {
    pub fn new() -> Result<Self, IoError> { ... }
    /// 发送 IPv4 数据包（需手动构造 IP 头）
    pub fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError> { ... }
}
```

---

## 5. Business Logic

### 5.1 内部工具函数

```rust
// wireforge-core/src/util.rs

/// 大端序读取 u16, 调用方负责边界检查
#[inline]
pub(crate) fn read_u16be(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

/// 大端序读取 u32
#[inline]
pub(crate) fn read_u32be(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// 大端序写入 u16
#[inline]
pub(crate) fn write_u16be(buf: &mut [u8], val: u16) {
    buf[0..2].copy_from_slice(&val.to_be_bytes());
}

/// 大端序写入 u32
#[inline]
pub(crate) fn write_u32be(buf: &mut [u8], val: u32) {
    buf[0..4].copy_from_slice(&val.to_be_bytes());
}

/// RFC 1071 Internet Checksum
///
/// 对任意长度的字节切片计算 16 位 ones' complement 校验和。
/// 返回网络字节序的校验和值（已取反，可直接写入数据包）。
pub fn internet_checksum(mut data: &[u8]) -> u16 {
    let mut sum = 0u32;
    while data.len() >= 2 {
        sum += read_u16be(data) as u32;
        data = &data[2..];
    }
    if !data.is_empty() {
        sum += (data[0] as u32) << 8;
    }
    // 折叠进位
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP/UDP 伪头校验和
pub fn pseudo_header_checksum(
    src: &[u8],       // IPv4: 4 bytes, IPv6: 16 bytes
    dst: &[u8],       // 同上
    protocol: u8,     // IP 协议号
    transport_data: &[u8],  // TCP/UDP 头 + payload
) -> u16 {
    let mut sum = 0u32;
    // 源地址
    let mut i = 0;
    while i < src.len() {
        sum += read_u16be(&src[i..]) as u32;
        i += 2;
    }
    // 目的地址
    i = 0;
    while i < dst.len() {
        sum += read_u16be(&dst[i..]) as u32;
        i += 2;
    }
    sum += protocol as u32;
    sum += transport_data.len() as u32;
    // 传输层数据
    let mut data = transport_data;
    while data.len() >= 2 {
        sum += read_u16be(data) as u32;
        data = &data[2..];
    }
    if !data.is_empty() {
        sum += (data[0] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
```

### 5.2 TCP 选项解析

```rust
// wireforge-core/src/tcp.rs

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption<'a> {
    EndOfList,
    NoOp,
    MaxSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack { blocks: &'a [u8] },  // variable length
    Timestamp { ts_val: u32, ts_ecr: u32 },
    Unknown { kind: u8, data: &'a [u8] },
}

pub struct TcpOptionsIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = TcpOption<'a>;
    fn next(&mut self) -> Option<Self::Item> { ... }
}
```

### 5.3 IPv6 扩展头解析

```rust
// wireforge-core/src/ipv6.rs

#[derive(Debug, Clone)]
pub enum Ipv6ExtensionHeader<'a> {
    HopByHop { next_header: IpProtocol, data: &'a [u8] },
    Routing { next_header: IpProtocol, routing_type: u8, segments_left: u8, data: &'a [u8] },
    Fragment { next_header: IpProtocol, fragment_offset: u16, more_fragments: bool, id: u32 },
    Destination { next_header: IpProtocol, data: &'a [u8] },
}

pub struct Ipv6ExtensionHeadersIter<'a> {
    next_header: IpProtocol,
    data: &'a [u8],
}

impl<'a> Iterator for Ipv6ExtensionHeadersIter<'a> {
    type Item = Ipv6ExtensionHeader<'a>;
    fn next(&mut self) -> Option<Self::Item> { ... }
}

impl<'a> Ipv6Packet<'a> {
    pub fn extension_headers(&self) -> Ipv6ExtensionHeadersIter<'a> { ... }
    /// 跳过扩展头后最终的上层协议
    pub fn final_protocol(&self) -> IpProtocol { ... }
    /// 跳过扩展头后最终的有效载荷
    pub fn payload(&self) -> &'a [u8] { ... }
}
```

### 5.4 ICMP / ICMPv6 消息类型

```rust
// wireforge-core/src/icmp.rs

#[derive(Debug, Clone)]
pub enum IcmpMessage<'a> {
    EchoRequest { id: u16, seq: u16, data: &'a [u8] },
    EchoReply { id: u16, seq: u16, data: &'a [u8] },
    DestinationUnreachable { code: u8, data: &'a [u8] },
    TimeExceeded { code: u8, data: &'a [u8] },
    // ... 其他类型
    Unknown { typ: u8, code: u8, data: &'a [u8] },
}

#[derive(Debug, Clone)]
pub enum Icmpv6Message<'a> {
    // NDP
    NeighborSolicitation { target: Ipv6Addr, options: &'a [u8] },
    NeighborAdvertisement { flags: u8, target: Ipv6Addr, options: &'a [u8] },
    RouterSolicitation { options: &'a [u8] },
    RouterAdvertisement { hop_limit: u8, flags: u8, router_lifetime: u16, options: &'a [u8] },
    // ... 其他
    Unknown { typ: u8, code: u8, data: &'a [u8] },
}
```

### 5.5 VLAN 解析

```rust
// wireforge-core/src/vlan.rs

pub struct VlanPacket<'a> {
    buf: &'a [u8],       // 指向 VLAN 标签起始位置
    inner_offset: usize, // 内层协议起始偏移（通常是 4）
}

impl<'a> VlanPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 4 { return None; }
        Some(Self { buf, inner_offset: 4 })
    }

    pub fn pcp(&self) -> u8 { (self.buf[0] >> 5) & 0x07 }
    pub fn dei(&self) -> bool { self.buf[0] & 0x10 != 0 }
    pub fn vid(&self) -> u16 { read_u16be(&self.buf[..]) & 0x0FFF }
    pub fn ethertype(&self) -> EtherType { EtherType::from(read_u16be(&self.buf[2..])) }

    /// 内层数据（可能是另一个 VLAN 标签或实际 payload）
    pub fn inner(&self) -> &'a [u8] { &self.buf[4..] }
}

/// 解析 802.1Q 标签链, 返回所有 VLAN 层级和最终的 EtherType + payload
pub fn parse_vlan_chain(buf: &[u8]) -> Option<(Vec<VlanPacket<'_>>, EtherType, &[u8])> { ... }
```

### 5.6 协议分发 (wireforge-packet)

```rust
// wireforge-packet/src/lib.rs

pub enum Packet<'a> {
    Ethernet(EthernetPacket<'a>),
    Arp(ArpPacket<'a>),
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Icmp(IcmpPacket<'a>),
    Icmpv6(Icmpv6Packet<'a>),
}

/// 从 Ethernet 帧开始逐层解析
pub fn parse_ethernet_frame(buf: &[u8]) -> Option<(EthernetPacket<'_>, Option<Packet<'_>>)> { ... }

/// 从 IPv4 数据报继续解析上层协议
pub fn parse_ipv4_payload<'a>(ip: &Ipv4Packet<'a>) -> Option<Packet<'a>> { ... }
```

### 5.7 Edge Cases

| 场景 | 处理方式 |
|------|----------|
| 数据包长度 < 最小协议头 | `new()` 返回 `None` |
| IP 头 IHL 声明长度 > 实际数据长度 | `new()` 返回 `None` |
| TCP data_offset < 5 | `new()` 返回 `None` |
| 未知 EtherType / IpProtocol | 返回 `EtherType::Unknown(u16)` / `IpProtocol::Unknown(u8)`, payload 仍可访问 |
| 校验和不匹配 | 解析成功，`verify_checksum()` 返回 `false` |
| VLAN 双重标签 (802.1ad + 802.1Q) | `parse_vlan_chain()` 返回多个层级的 Vec |
| IPv6 扩展头链异常 (循环引用) | 设置最大迭代次数（如 8 层），超限返回 `None` |
| TCP 选项不完整 (kind 声明长度 > 剩余数据) | 迭代器提前返回 `None`，已解析的选项仍有效 |
| L2 接收填充不足 60 字节的短帧 | `EthernetPacket::new()` 正常解析，仅检查 14 字节最小头 |
| AF_PACKET 接收超大帧 (jumbo frame) | 接收缓冲区预分配足够大小（如 65536 字节） |

---

## 6. Error Handling

### 6.1 Error Taxonomy

| 组件 | 错误返回 | 描述 |
|------|----------|------|
| 所有 Parser `::new()` | `Option<T>` | 仅长度不足时返回 `None`，不分配错误详情 |
| `verify_checksum()` | `bool` | 校验结果，不是错误 |
| `Builder::payload()` | `Result<Self, BuildError>` | PayloadTooLarge |
| `Builder::build()` | `Result<Vec<u8>, BuildError>` | 构造最终验证 |
| `Builder::add_option()` | `Result<Self, BuildError>` | 选项构造失败 |
| `L2Receiver::new()` | `Result<Self, IoError>` | Socket 打开失败 |
| `L2Receiver::recv()` | `Result<Packet, IoError>` | Socket / Timeout / Parse |
| `L2Sender::send()` | `Result<usize, IoError>` | Socket |
| `L3Sender::send_to()` | `Result<usize, IoError>` | Socket |

### 6.2 No-Panic Guarantee

所有公开 API 对于任意字节输入不得 panic：

- 内部偏移访问前必须通过长度检查
- 字节到整数转换使用 `from_be_bytes`（infallible）
- 不使用 `.unwrap()` / `.expect()` 在公开 API 路径上
- 模糊测试验证 no-panic 属性

### 6.3 Failure Modes

| 场景 | 行为 |
|------|------|
| 网络接口不可用 | `L2Receiver::new()` 返回 `IoError::Socket` |
| 套接字读取超时 | `recv()` 返回 `IoError::Timeout` |
| 内核缓冲区满 (丢包) | 静默丢弃，无错误返回（内核对 SOCK_RAW 行为） |
| 发送时目标不可达 | 异步 ICMP 错误，不阻塞 `send()` |
| 权限不足 (raw socket 需 CAP_NET_RAW) | `new()` 返回 `IoError::Socket` |

---

## 7. Security

### 7.1 Threat Model

本库处理来自网络的不可信数据包字节。攻击面包括：

- 恶意构造的数据包（短头、不一致长度、畸形选项）
- 模糊测试生成的随机字节
- 超大 payload / 循环扩展头
- 整数溢出（校验和累加、长度计算）

### 7.2 Input Validation

所有解析入口点 `::new(&[u8])` 必须验证：

- 缓冲区长度 ≥ 最小协议头
- 变长字段（IHL, data_offset）声明的长度 ≤ 实际缓冲区长度
- TCP 选项/IPv6 扩展头迭代器有上限

内部读取函数 (`read_u16be`, `read_u32be`) 假设调用方已完成边界检查，本身不 panic（使用 `from_be_bytes`, 输入恰好是 2/4 字节）。

### 7.3 Unsafe Code Policy

`unsafe` 仅允许出现在以下场景：

- `wireforge-core/src/util.rs` 中的零拷贝类型转换原语（如 `&[u8]` → `&[u16]` 用于 SIMD 优化校验和，仅在未来性能优化时引入）
- 每个 `unsafe` 块必须附带 `// SAFETY:` 注释，说明前置条件和满足理由
- v1 版本目标: core 层 **零 unsafe 块**

### 7.4 Socket Security

- 套接字绑定仅使用有效接口名（无命令注入风险）
- `set_promiscuous()` 仅在调用方有 CAP_NET_ADMIN 时成功，库不尝试提权
- 不提供 `setsockopt` 的任意透传接口，仅暴露预定义的安全选项

---

## 8. Performance

### 8.1 Expected Load

| 场景 | 预期吞吐量 |
|------|-----------|
| Ethernet 解析 (单帧) | < 10ns |
| IPv4 解析 (单包, 无选项) | < 20ns |
| TCP 解析 (单段, 无选项) | < 30ns |
| 校验和计算 (1500 字节) | < 200ns |
| 数据包构造 (TCP SYN, 含选项) | < 500ns |
| AF_PACKET 接收吞吐 | 受内核/硬件限制，库本身不引入瓶颈 |

### 8.2 Optimization Strategy

- **零拷贝:** 所有 Parser 持有 `&[u8]`，字段通过内联偏移访问 — 编译后为直接内存读取
- **无分配解析:** `new()` 路径无 heap allocation
- **内联:** 所有字段访问器标记 `#[inline]`
- **校验和:** 当前采用逐 16-bit 累加（标准 RFC 1071），未来可升级为 SIMD 加速（`_mm_sad_epu8` 或 carry-less 加法）
- **无虚函数:** 不使用 `dyn Trait` 在热路径上，协议分发使用 enum match（编译器可优化为跳转表）

### 8.3 Compiler Guidance

```rust
// Cargo.toml (wireforge-core)
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
```

---

## 9. Testing Strategy

### 9.1 Unit Tests

每种协议解析器必须包含：

- **正常数据包:** 用 Wireshark 导出的已知正确字节验证字段提取
- **最小长度数据包:** 刚好等于最小头长度
- **长度不足:** 1 字节、2 字节、...、MIN_HEADER_LEN-1 字节均返回 `None`
- **变长头边界:** IHL=5 (最小), IHL=15 (最大) 的 IPv4; data_offset 边界值
- **Payload 访问:** payload 切片长度 = 总长 - 头长
- **往返测试:** 构造后解析再验证字段一致

### 9.2 Integration Tests

- **L2 收发往返:** 在 lo 接口发送自定义 Ethernet 帧并接收验证
- **L3 收发往返:** 发送 ICMP Echo Request 并接收 Echo Reply
- **ARP 请求/应答:** 构造 ARP Request 发送，等待应答并解析

### 9.3 Edge Case Tests

见 Section 5.7 表格。

### 9.4 Fuzz Testing

每个协议模块配置独立的 fuzz target:

```toml
# wireforge-core/fuzz/Cargo.toml 或 .cargo/config.toml
```

```rust
// wireforge-core/fuzz/fuzz_targets/ether.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 任何输入都不能 panic
    if let Some(pkt) = wireforge_core::EthernetPacket::new(data) {
        let _ = pkt.dst_mac();
        let _ = pkt.src_mac();
        let _ = pkt.ethertype();
        let _ = pkt.payload();
    }
});
```

Fuzz targets: `ether`, `vlan`, `arp`, `ipv4`, `ipv6`, `tcp`, `udp`, `icmp`, `icmpv6`

### 9.5 Benchmarks

```rust
// wireforge-core/benches/parse_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_ipv4_parse(c: &mut Criterion) {
    let pkt = include_bytes!("../tests/data/ipv4_tcp.bin");
    c.bench_function("ipv4_parse", |b| {
        b.iter(|| Ipv4Packet::new(black_box(pkt)))
    });
}

criterion_group!(benches, bench_ipv4_parse);
criterion_main!(benches);
```

### 9.6 Acceptance Criteria Mapping

| US | Test Type | Description |
|----|-----------|-------------|
| US-001 | unit + fuzz | Ethernet/VLAN 解析测试 |
| US-002 | unit + fuzz | ARP 解析与构造往返测试 |
| US-003 | unit + fuzz | IPv4 解析/构造/校验和测试 |
| US-004 | unit + fuzz | IPv6 解析/构造/扩展头链测试 |
| US-005 | unit + fuzz | ICMP/ICMPv6 消息类型测试 |
| US-006 | unit + fuzz | TCP 解析/构造/选项/校验和测试 |
| US-007 | unit + fuzz | UDP 解析/构造/校验和测试 |
| US-008 | integration | lo 接口 L2 收发往返 |
| US-009 | integration | lo 接口 ICMP Echo 往返 |
| US-010 | unit | PacketReceiver trait 实现测试 |
| US-011 | fuzz | 全部 9 个 fuzz target, 30s 无 crash |
| US-012 | bench | criterion 基准测试 vs libpnet |
| US-013 | — | rustdoc + examples 编译通过 |

---

## 10. Implementation Plan

### 10.1 Phases

```
Phase 1: Foundation (US-001)
  ├── Cargo workspace + wireforge-core crate 搭建
  ├── util.rs (checksum, read helpers, macros)
  ├── types.rs (EtherType, IpProtocol, 公共枚举)
  ├── ether.rs (EthernetPacket + Builder)
  ├── vlan.rs (VlanPacket, parse_vlan_chain)
  └── 单元测试 + fuzz target

Phase 2: L3 Protocols (US-002~005)
  ├── arp.rs (ArpPacket + Builder)
  ├── ipv4.rs (Ipv4Packet + Builder)
  ├── ipv6.rs (Ipv6Packet + Extension Headers + Builder)
  ├── icmp.rs (IcmpPacket + Icmpv6Packet + NDP)
  └── 单元测试 + fuzz targets

Phase 3: L4 Protocols (US-006~007)
  ├── tcp.rs (TcpPacket + Options + Builder)
  ├── udp.rs (UdpPacket + Builder)
  └── 单元测试 + fuzz targets

Phase 4: Packet Dispatch (US-010)
  ├── wireforge-packet crate 搭建
  ├── Packet enum + 分发逻辑
  └── 集成测试

Phase 5: Socket I/O (US-008~009)
  ├── wireforge-io crate 搭建
  ├── l2.rs (L2Receiver + L2Sender)
  ├── l3.rs (L3Receiver + L3Sender)
  ├── receiver.rs (PacketReceiver trait)
  ├── error.rs (IoError)
  └── 集成测试

Phase 6: Quality Assurance (US-011~013)
  ├── cargo fuzz setup + CI
  ├── criterion benchmarks
  ├── examples/ (packet_dump, packet_build, simple_ping)
  ├── README + rustdoc 完善
  └── 最终 review
```

### 10.2 Dependencies Between Phases

```
Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4 ──→ Phase 5 ──→ Phase 6
                                        │            │
                                        └── depends on core (Phase 1-3)
                                                     │
                                                     └── depends on packet (Phase 4)
```

### 10.3 Issue Mapping

| Issue | SPEC Sections | Phase | Depends On |
|-------|--------------|-------|------------|
| project-setup | 2.4, Cargo workspace | 1 | — |
| core-util-types | 3.2, 5.1, 3.6 | 1 | project-setup |
| ethernet-parser | 4.1, 5.5 | 1 | core-util-types |
| arp-parser | 4.1 | 2 | core-util-types |
| ipv4-parser | 4.1 | 2 | core-util-types |
| ipv6-parser | 4.1, 5.3 | 2 | core-util-types |
| icmp-parser | 4.1, 5.4 | 2 | ipv4-parser, ipv6-parser |
| tcp-parser | 4.1, 4.2, 5.2 | 3 | ipv4-parser, ipv6-parser |
| udp-parser | 4.1, 4.2 | 3 | ipv4-parser, ipv6-parser |
| packet-dispatch | 5.6 | 4 | tcp-parser, udp-parser |
| io-l2-sockets | 4.3 | 5 | packet-dispatch |
| io-l3-sockets | 4.3 | 5 | packet-dispatch |
| fuzz-testing | 9.4 | 6 | all parser issues |
| benchmarks | 9.5 | 6 | all parser issues |
| docs-examples | — | 6 | io-l2-sockets, io-l3-sockets |

---

## 11. Open Questions & Risks

### 11.1 Unresolved Questions (from PRD, deferred to v2)

- IPv4 分片重组
- Transport 层抽象（自动分发 IP payload 到 TCP/UDP/ICMP）
- `to_builder()` 从解析包生成 Builder
- 数据包过滤器 DSL

### 11.2 Technical Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| AF_PACKET 接口在不同内核版本的行为差异 | I/O 集成测试不稳定 | 使用固定内核版本的 CI 容器 |
| TCP 校验和需要伪头 — 不正确使用会静默失败 | 校验错误 | `verify_checksum()` 明确要求 src/dst 参数, rustdoc 示例 |
| IPv6 扩展头链可能无限循环 | 解析 panic | 设置最大迭代深度, fuzz 覆盖循环路径 |
| `socket2` 可能在特定 Linux 版本有 bug | I/O 失败 | 锁定已知兼容版本, 集成测试覆盖目标内核 |

### 11.3 Assumptions

- 运行环境 Linux 内核 ≥ 4.0（AF_PACKET 支持成熟）
- 调用方拥有 CAP_NET_RAW 权限
- 目标处理器为 little-endian（x86_64 / ARM64），大端序读取使用 `from_be_bytes` 保证可移植
- Rust 工具链版本 ≥ 1.75（`no_std` + `alloc` 稳定）
