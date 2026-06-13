# SPEC: WireForge 跨平台 I/O 支持

> Technical specification derived from: [tasks/prd-wireforge-cross-platform-io.md](prd-wireforge-cross-platform-io.md)
> Generated: 2026-06-13 | Target branch: main | Project: wireforge

## 1. Summary

### 1.1 What This SPEC Covers

本 SPEC 定义 `wireforge-io` crate 从 Linux-only 到 Linux/macOS/Windows 三平台的重构方案。核心变更是引入 4 个核心 trait（`L2Reader`、`L2Writer`、`L3Reader`、`L3Writer`），每个平台提供各自的 struct 实现，通过 `#[cfg(target_os)]` 条件编译。

### 1.2 PRD Reference

- Source: `tasks/prd-wireforge-cross-platform-io.md`
- User Stories covered: US-001 ~ US-010
- Functional Requirements covered: FR-1 ~ FR-10

### 1.3 Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| 缓冲区管理 | Trait 内部管理 `[u8; 65536]` | 简单、零拷贝引用返回、与现有 API 一致 |
| NPcap 依赖 | `#[cfg(feature = "npcap")]` feature flag | Windows 用户按需引入，不强制 Linux/macOS 编译 |
| 代码组织 | `src/linux/` `src/macos/` `src/windows/` 按平台目录 | 清晰、单一 crate、无 workspace 膨胀 |
| Trait 设计 | 4 个独立 trait，非关联类型 | 简单直接，用户可独立 mock/替换每个方向 |
| `set_timeout` | 放在每个 trait 中 | 每个 trait 都可以独立设置超时 |
| L3 收发 type | 固定 `Ipv4Packet` 和 `SocketAddrV4` | v1 只支持 IPv4，IPv6 是后续扩展 |
| Breaking change | 允许 | 从 struct 改为 trait，类型别名保持 `L2Receiver` 等名称可用 |

---

## 2. Architecture

### 2.1 System Context

```
┌──────────────────────────────────────────────────┐
│                   应用层 (用户代码)                 │
│         抓包工具 / 扫描器 / 网络监控 / 诊断         │
└──────────────┬──────────────────────┬────────────┘
               │                      │
     ┌─────────▼────────┐  ┌─────────▼─────────┐
     │  wireforge-app   │  │  wireforge-io     │
     │ DNS/DHCP/NTP/    │  │ ┌─────────────────┐│
     │ HTTP/pcap I/O    │  │ │ traits (公共)    ││
     └──────────────────┘  │ ├─────────────────┤│
                           │ │ linux/  (AF_PKT) ││
                           │ │ macos/  (BPF)    ││
                           │ │ windows/(NPcap)  ││
                           │ │ interface.rs     ││
                           │ └─────────────────┘│
                           └───────────────────┘
```

### 2.2 Component Design

#### 核心 trait (`src/traits.rs`)

4 个独立 trait，无继承关系：

```rust
/// L2 帧接收器（Ethernet 帧）。
pub trait L2Reader {
    fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError>;
    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError>;
    fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError>;
}

/// L2 帧发送器（Ethernet 帧）。
pub trait L2Writer {
    fn send(&self, packet: &[u8]) -> Result<usize, IoError>;
}

/// L3 IPv4 数据包接收器。
pub trait L3Reader {
    fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError>;
    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError>;
    fn set_header_included(&mut self, on: bool) -> Result<(), IoError>;
}

/// L3 IPv4 数据包发送器。
pub trait L3Writer {
    fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError>;
}
```

#### 平台实现

| 平台 | L2Reader | L2Writer | L3Reader | L3Writer |
|------|----------|----------|----------|----------|
| Linux | `L2Receiver` | `L2Sender` | `L3Receiver` | `L3Sender` |
| macOS | `BpfReader` | `BpfWriter` | `BsdL3Receiver` | `BsdL3Sender` |
| Windows | `NpcapReader` | `NpcapWriter` | `WinL3Receiver` | `WinL3Sender` |

#### 类型别名 (`src/lib.rs`)

```rust
#[cfg(target_os = "linux")]
pub type DefaultL2Reader = linux::L2Receiver;
#[cfg(target_os = "macos")]
pub type DefaultL2Reader = macos::BpfReader;
#[cfg(target_os = "windows")]
pub type DefaultL2Reader = windows::NpcapReader;

// 同理: DefaultL2Writer, DefaultL3Reader, DefaultL3Writer
```

### 2.3 Module Interactions

```
Linux 收包流程:
  let mut rx: L2Receiver = L2Reader::new("eth0")?;
  rx.set_promiscuous(true)?;
  let eth: EthernetPacket = rx.recv()?;  // trait 方法
  // → socket2 recvfrom → 解析 → EthernetPacket

macOS 收包流程:
  let mut rx: BpfReader = BpfReader::new("en0")?;
  let eth: EthernetPacket = rx.recv()?;
  // → /dev/bpf read → 剥离 BPF header → EthernetPacket

Windows 收包流程:
  let mut rx: NpcapReader = NpcapReader::new("Ethernet0")?;
  let eth: EthernetPacket = rx.recv()?;
  // → npcap pcap_next_ex → EthernetPacket
```

### 2.4 File Structure

```
wireforge-io/
├── Cargo.toml                    # [MODIFY] 添加 npcap feature + 平台依赖
├── src/
│   ├── lib.rs                    # [MODIFY] trait 导出 + 类型别名 + 平台模块
│   ├── error.rs                  # [MODIFY] 扩展 IoError 变体
│   ├── traits.rs                 # [NEW] L2Reader/L2Writer/L3Reader/L3Writer
│   ├── interface.rs              # [NEW] Interface struct + list_interfaces()
│   ├── linux/
│   │   ├── mod.rs                # [MODIFY] 将现有 l2.rs/l3.rs 移入
│   │   ├── l2.rs                 # [MOVED] L2Receiver + L2Sender + trait impl
│   │   └── l3.rs                 # [MOVED] L3Receiver + L3Sender + trait impl
│   ├── macos/
│   │   ├── mod.rs                # [NEW]
│   │   ├── bpf.rs                # [NEW] BpfReader + BpfWriter
│   │   └── l3.rs                 # [NEW] BsdL3Receiver + BsdL3Sender
│   ├── windows/
│   │   ├── mod.rs                # [NEW]
│   │   ├── npcap.rs              # [NEW] NpcapReader + NpcapWriter
│   │   └── l3.rs                 # [NEW] WinL3Receiver + WinL3Sender
│   └── common/
│       └── mod.rs                # [NEW] 跨平台共享工具（如 timeout 设置）
└── examples/
    ├── cross_platform_dump.rs    # [NEW]
    ├── cross_platform_send.rs    # [NEW]
    └── list_interfaces.rs        # [NEW]
```

### 2.5 Feature Flags

```toml
# wireforge-io/Cargo.toml

[features]
default = []
npcap = ["dep:npcap"]  # Windows NPcap 支持

[target.'cfg(windows)'.dependencies]
npcap = { version = "0.1", optional = true }

[target.'cfg(any(target_os = "linux", target_os = "macos"))'.dependencies]
libc = "0.2"

[dependencies]
socket2 = "0.5"
wireforge-packet = { path = "../wireforge-packet" }
```

---

## 3. API Design

### 3.1 Trait 完整签名

```rust
use std::time::Duration;
use std::net::SocketAddrV4;
use wireforge_core::ether::EthernetPacket;
use wireforge_core::ipv4::Ipv4Packet;
use crate::error::IoError;

pub trait L2Reader {
    fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError>;
    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError>;
    fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError>;
}

pub trait L2Writer {
    fn send(&self, packet: &[u8]) -> Result<usize, IoError>;
}

pub trait L3Reader {
    fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError>;
    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError>;
    fn set_header_included(&mut self, on: bool) -> Result<(), IoError>;
}

pub trait L3Writer {
    fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError>;
}
```

### 3.2 平台构造函数

所有平台 struct 提供统一的构造函数签名：

```rust
// Linux
impl L2Receiver {
    pub fn new(ifname: &str) -> Result<Self, IoError>;
}

// macOS
impl BpfReader {
    pub fn new(ifname: &str) -> Result<Self, IoError>;
    pub fn with_buffer_size(ifname: &str, buf_size: usize) -> Result<Self, IoError>;
}

// Windows
impl NpcapReader {
    pub fn new(ifname: &str) -> Result<Self, IoError>;
    pub fn open_all() -> Result<Self, IoError>;  // 捕获所有适配器
}
```

### 3.3 Interface 类型

```rust
#[derive(Debug, Clone)]
pub struct Interface {
    /// 操作系统内部名称（如 "eth0", "en0", "Ethernet0"）
    pub name: String,
    /// 人类可读名称（Windows: "Realtek PCIe GbE", macOS: "Built-in Ethernet"）
    pub friendly_name: Option<String>,
    /// MAC 地址
    pub mac_address: Option<[u8; 6]>,
    /// 绑定的 IP 地址列表
    pub ips: Vec<std::net::IpAddr>,
    /// 是否 loopback
    pub is_loopback: bool,
    /// 接口是否 up
    pub is_up: bool,
}

/// 列出本机所有可用网络接口。
pub fn list_interfaces() -> Result<Vec<Interface>, IoError>;
```

### 3.4 平台实现细节

#### Linux (`src/linux/l2.rs`, `src/linux/l3.rs`)

- **L2**: 现有代码直接适配 — `L2Receiver`/`L2Sender` struct 不变，增加 `impl L2Reader for L2Receiver` 和 `impl L2Writer for L2Sender`
- **L3**: 同上，`impl L3Reader for L3Receiver` 和 `impl L3Writer for L3Sender`
- **系统调用**: `socket2` + `libc::setsockopt`（不变）
- **接口枚举**: `SIOCGIFCONF` ioctl + 逐接口 `SIOCGIFFLAGS`/`SIOCGIFHWADDR`

#### macOS (`src/macos/bpf.rs`, `src/macos/l3.rs`)

- **BPF 流程**:
  1. 遍历 `/dev/bpfN`（0..256），找到第一个未使用的设备
  2. `open("/dev/bpfN")` 获取 fd
  3. `ioctl(fd, BIOCSETIF, &ifreq)` 绑定接口
  4. `ioctl(fd, BIOCIMMEDIATE, &1)` 启用立即模式
  5. `ioctl(fd, BIOCSBLEN, &bufsize)` 设置缓冲区大小（默认 64KB）
  6. `ioctl(fd, BIOCPROMISC, NULL)` 可选混杂模式
  7. `read(fd, buf)` 读取数据包

- **BPF 数据包格式**:
  ```
  [bpf_hdr: 18/26 bytes][Ethernet frame]
  ```
  bpf_hdr 包含 `bh_caplen` (实际捕获长度) 和 `bh_datalen` (原始长度)。解析时需要跳过 bpf_hdr。

- **BPF Writer**: 通过 BPF 设备 `write(fd, frame)` 发送 L2 帧

- **L3**: 与 Linux 共用 90% 代码（raw socket 逻辑相同），差异仅在 `IP_HDRINCL` 常量名
- **接口枚举**: `getifaddrs()` POSIX 函数

#### Windows (`src/windows/npcap.rs`, `src/windows/l3.rs`)

- **NPcap 流程**:
  1. `npcap::Adapter::open(ifname)` 打开适配器
  2. `adapter.set_promiscuous(true)` 设置混杂模式
  3. `adapter.set_timeout(timeout)` 设置超时
  4. `adapter.next_packet()` 获取下一个数据包 `(timestamp, data)`
  5. 解析 `data` 为 `EthernetPacket`

- **NPcap Writer**: `adapter.send(packet)` 发送 L2 帧

- **L3**: Windows raw socket 使用 `socket2::Socket::new(Domain::IPV4, Type::RAW, ...)`。
  Windows 上 `IP_HDRINCL` 行为不同于 Linux，需要设置 socket option `IP_HDRINCL`。

- **接口枚举**: 通过 `npcap::Adapter::list()` 获取适配器列表

### 3.5 IoError 扩展

```rust
#[derive(Debug)]
pub enum IoError {
    // 现有变体（保留）
    Socket(std::io::Error),
    Parse(&'static str),
    Timeout,
    InvalidMagic(u32),
    UnsupportedVersion { major: u16, minor: u16 },
    TruncatedRecord { expected: u32, got: usize },
    NameTooLong(usize),
    CompressionLoop,

    // 新增变体
    /// 指定接口不存在
    InterfaceNotFound(String),
    /// 权限不足（需要 root / Administrator）
    PermissionDenied,
    /// BPF 特定错误
    Bpf(&'static str),
    /// NPcap 特定错误
    #[cfg(feature = "npcap")]
    Npcap(String),
    /// 当前平台不支持的操作
    UnsupportedPlatform,
}
```

---

## 4. Error Handling

### 4.1 Error Taxonomy

| 错误 | 触发条件 | 平台 | 用户操作建议 |
|------|----------|------|--------------|
| `InterfaceNotFound` | 接口名不存在 | All | 运行 `list_interfaces()` 确认可用接口 |
| `PermissionDenied` | 非 root/Administrator | All | 使用 `sudo` 或以管理员运行 |
| `Bpf` | /dev/bpf 不可用或无空闲设备 | macOS | 检查是否有其他抓包程序占用 BPF |
| `Npcap` | NPcap 未安装或驱动加载失败 | Windows | 安装 NPcap（https://npcap.com） |
| `UnsupportedPlatform` | 当前平台无实现 | All | 检查代码是否 gated 了平台 |
| `Timeout` | 接收超时 | All | 增加超时时间或循环重试 |

### 4.2 平台降级策略

- **Windows L2 send**: 若 NPcap 不支持 L2 发送（部分驱动限制），`NpcapWriter::send()` 返回 `IoError::UnsupportedPlatform`
- **L3 IPv6**: v1 不支持 IPv6 L3 收发，调用 `L3Reader::recv()` 遇 IPv6 包返回 `IoError::Parse("IPv6 not supported in L3Reader")`

---

## 5. Testing Strategy

### 5.1 单元测试（跨平台，不依赖 root）

| 测试 | 内容 | 平台 |
|------|------|------|
| `test_io_error_display` | 所有 IoError 变体的 Display 输出可读 | All |
| `test_io_error_from_io` | `From<std::io::Error>` 转换 | All |
| `test_interface_debug` | Interface Debug 输出 | All |
| `test_type_aliases_exist` | DefaultL2Reader 等类型别名可编译 | All |

### 5.2 集成测试（需要权限，可在 CI 中 skip）

| 测试 | 内容 | 条件 |
|------|------|------|
| `test_linux_loopback_l2` | lo 接口 L2 收发往返 | Linux, root |
| `test_linux_loopback_l3` | lo 接口 ICMP Echo 往返 | Linux, root |
| `test_macos_loopback_l2` | lo0 接口 BPF 捕获 | macOS, root |
| `test_macos_loopback_l3` | lo0 ICMP Echo 往返 | macOS, root |
| `test_windows_loopback_l2` | NPcap loopback 捕获 | Windows, Admin |
| `test_windows_loopback_l3` | raw socket ICMP Echo | Windows, Admin |
| `test_list_interfaces` | 返回非空列表，包含 loopback | All |

### 5.3 权限检测

```rust
/// 集成测试入口：检查是否有权限运行网络测试
fn has_network_permission() -> bool {
    // Linux/macOS: 检查 uid == 0
    // Windows: 检查是否 Administrator
}

#[test]
#[ignore] // 需要 root，CI 中 skip
fn test_linux_loopback_l2() {
    if !has_network_permission() { return; }
    // ... 实际测试
}
```

---

## 6. Implementation Plan

### 6.1 Phase Order

```
Phase 1: Trait 定义 + IoError 扩展
  ├── traits.rs (新文件)
  ├── error.rs (扩展)
  └── lib.rs (导出重排)

Phase 2: Linux 适配（最小改动）
  ├── 移动 l2.rs → linux/l2.rs + impl trait
  ├── 移动 l3.rs → linux/l3.rs + impl trait
  └── 保持 struct 名称不变

Phase 3: macOS BPF + L3
  ├── macos/bpf.rs (BpfReader + BpfWriter)
  ├── macos/l3.rs (BsdL3Receiver + BsdL3Sender)
  └── macos 集成测试

Phase 4: Windows NPcap + L3
  ├── windows/npcap.rs (NpcapReader + NpcapWriter)
  ├── windows/l3.rs (WinL3Receiver + WinL3Sender)
  └── windows 集成测试

Phase 5: 跨平台工具
  ├── interface.rs (list_interfaces + 三平台实现)
  ├── common/mod.rs (共享 timeout 设置等)
  ├── 类型别名 DefaultL2Reader 等
  └── 跨平台示例

Phase 6: 文档 + CI
  ├── module docstrings
  ├── examples/
  └── CI 矩阵配置（ubuntu/macos/windows）
```

### 6.2 Issue Mapping

| Issue | Phase | SPEC Sections | Priority | Depends On |
|-------|-------|--------------|----------|------------|
| #1 trait + error | 1 | 2.2, 3.1, 3.5 | high | — |
| #2 linux adapter | 2 | 3.4, 5.2 | high | #1 |
| #3 macOS BPF | 3 | 3.4 | high | #1 |
| #4 macOS L3 | 3 | 3.4 | medium | #1 |
| #5 Windows NPcap | 4 | 3.4 | high | #1 |
| #6 Windows L3 | 4 | 3.4 | medium | #1 |
| #7 interface enumeration | 5 | 3.3 | medium | #2 |
| #8 type aliases + common | 5 | 2.2, 3.4 | low | #2, #3, #5 |
| #9 examples + docs | 6 | 2.4 | low | all |
| #10 CI matrix | 6 | 5.3 | low | all |

### 6.3 Incremental Delivery

- Phase 1+2 完成后即可在 Linux 上使用新 trait API（向后兼容旧 struct 名称）
- Phase 3 完成后可发布 macOS 预览版
- Phase 4 完成后三平台完整可用
- 每个 Phase 独立可发布，不阻塞其他平台

---

## 7. Open Questions & Risks

### 7.1 Unresolved Questions

- Windows L2 send 的可行性？NPcap `pcap_sendpacket` 在某些 WiFi 适配器上不支持。是否降级为 `L2Reader-only`？
- BPF 设备数量限制（macOS 默认 4 个 `/dev/bpf`）是否需要在文档中明确说明？
- `list_interfaces()` 的 `friendly_name` 在 Linux 上通常为空，是否需要提供一个 fallback（如接口名本身）？

### 7.2 Technical Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| NPcap crate 不成熟或 API 不稳定 | Windows L2 无法实现 | 评估 `npcap` crate 的成熟度；必要时直接 FFI 调用 NPcap DLL |
| macOS BPF 在 Apple Silicon 上的兼容性 | P1: macOS 用户不可用 | 在 CI 中加入 macos-14 (ARM) runner |
| BPF 缓冲区过大导致丢包 | P2: 高吞吐场景丢帧 | 提供 `with_buffer_size()` API，默认 64KB，最大可配置到 1MB |
| Windows raw socket 受限于 OS 版本 | P3: Win7 vs Win11 行为差异 | 文档说明最低 Windows 10，测试在 Windows Server 2022 上验证 |

### 7.3 Assumptions

- 用户具有 root/Administrator 权限来运行 L2 捕获
- NPcap/WinPcap 已安装（Windows 用户）
- macOS 上 `/dev/bpf` 设备可用且用户有读写权限
- `socket2` crate 在三平台上均可正常编译
- L3 只支持 IPv4（IPv6 是后续版本的范围）
