# PRD: WireForge 跨平台 I/O 支持

## Introduction

WireForge 当前 `wireforge-io` crate 仅支持 Linux（AF_PACKET L2 + raw socket L3），这限制了库在 macOS 抓包工具、Windows 网络诊断工具等场景的使用。本 PRD 将 `wireforge-io` 重构为跨平台 trait 架构，统一 Linux/macOS/Windows 三平台的 L2/L3 收发能力，同时对现有 API 做 breaking change 以换取更清晰的设计。

## Goals

- 定义平台无关的 L2/L3 收发 trait（`L2Reader`、`L2Writer`、`L3Reader`、`L3Writer`）
- Linux 实现：保留 AF_PACKET + raw socket，适配新 trait
- macOS/BSD 实现：BPF 设备 L2 捕获，raw socket L3 收发
- Windows 实现：NPcap/WinPcap L2 捕获，raw socket L3 收发
- 统一 `IoError` 错误类型，覆盖三平台
- 接口枚举功能（`list_interfaces()`），返回本机可用网络接口
- 每个平台实现通过单元测试和集成测试（至少本地 loopback 收发验证）
- 完整文档 + 跨平台示例

## User Stories

### US-001: 定义平台无关的 I/O trait 体系
**Description:** 作为库用户，我需要一套统一的 trait 来操作 L2/L3 收发，无论底层平台是 Linux AF_PACKET、macOS BPF 还是 Windows NPcap。

**Acceptance Criteria:**
- [ ] `L2Reader` trait: `fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError>`
- [ ] `L2Writer` trait: `fn send(&self, packet: &[u8]) -> Result<usize, IoError>`
- [ ] `L3Reader` trait: `fn recv(&mut self) -> Result<Ipv4Packet<'_>, IoError>`
- [ ] `L3Writer` trait: `fn send_to(&self, packet: &[u8], dst: SocketAddrV4) -> Result<usize, IoError>`
- [ ] 每个 trait 有 `set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError>`
- [ ] `L2Reader` 额外: `set_promiscuous(&mut self, on: bool) -> Result<(), IoError>`
- [ ] `cargo build --workspace` 成功
- [ ] `cargo clippy` 无警告

### US-002: Linux AF_PACKET + raw socket 实现适配
**Description:** 作为 Linux 用户，现有的 L2/L3 功能不能丢失。将现有实现适配到新 trait 接口，同时保留 `L2Receiver`/`L2Sender`/`L3Receiver`/`L3Sender` 作为 trait 的具体实现类型（struct 名称不变，impl 新 trait）。

**Acceptance Criteria:**
- [ ] `L2Receiver` struct 实现 `L2Reader` trait
- [ ] `L2Sender` struct 实现 `L2Writer` trait
- [ ] `L3Receiver` struct 实现 `L3Reader` trait
- [ ] `L3Sender` struct 实现 `L3Writer` trait
- [ ] 现有 Linux 集成测试（lo 接口收发）全部通过
- [ ] `cargo test` (Linux) 全部通过
- [ ] `cargo clippy` 无警告

### US-003: macOS/BSD BPF 设备 L2 捕获实现
**Description:** 作为 macOS 用户，我需要通过 BPF 设备捕获 Ethernet 帧，并支持混杂模式和超时设置。

**Acceptance Criteria:**
- [ ] `BpfReader` struct 实现 `L2Reader` trait
- [ ] `BpfWriter` struct 实现 `L2Writer` trait
- [ ] `BpfReader::new(ifname: &str) -> Result<Self, IoError>` — 打开 /dev/bpf 设备，关联指定接口
- [ ] 支持 `set_promiscuous()` — 通过 BIOCPROMISC ioctl
- [ ] 支持 `set_timeout()` — 通过 BIOCSRTIMEOUT ioctl
- [ ] 支持立即模式（BIOCIMMEDIATE），减少延迟
- [ ] 缓冲区大小可配置（默认 64KB，通过 BIOCSBLEN）
- [ ] 集成测试: lo0 接口发送→接收验证
- [ ] `cargo test` (macOS) 全部通过

### US-004: macOS/BSD raw socket L3 收发适配
**Description:** 作为 macOS 用户，我需要通过 raw socket 收发 IPv4 数据包，支持 IP_HDRINCL。

**Acceptance Criteria:**
- [ ] `BsdL3Receiver` struct 实现 `L3Reader` trait（复用 raw socket 逻辑，与 Linux 共用大部分代码）
- [ ] `BsdL3Sender` struct 实现 `L3Writer` trait
- [ ] 支持 `set_header_included()` — IP_HDRINCL
- [ ] 集成测试: lo0 ICMP Echo 往返
- [ ] `cargo test` (macOS) 全部通过

### US-005: Windows NPcap L2 捕获实现
**Description:** 作为 Windows 用户，我需要通过 NPcap SDK 捕获 Ethernet 帧并发送原始 L2 帧。

**Acceptance Criteria:**
- [ ] `NpcapReader` struct 实现 `L2Reader` trait
- [ ] `NpcapWriter` struct 实现 `L2Writer` trait
- [ ] `NpcapReader::new(ifname: &str) -> Result<Self, IoError>` — 通过 `npcap` crate 打开适配器
- [ ] 支持 `set_promiscuous()` — 设置 NPcap 混杂模式
- [ ] 支持 `set_timeout()` — 设置读超时
- [ ] 集成测试: loopback 接口发送→接收验证
- [ ] `cargo test` (Windows) 全部通过

### US-006: Windows raw socket L3 收发实现
**Description:** 作为 Windows 用户，我需要通过 raw socket 收发 IPv4 数据包。

**Acceptance Criteria:**
- [ ] `WinL3Receiver` struct 实现 `L3Reader` trait
- [ ] `WinL3Sender` struct 实现 `L3Writer` trait
- [ ] 支持 `set_header_included()` — IP_HDRINCL (Windows 等效)
- [ ] 集成测试: loopback ICMP Echo 往返
- [ ] `cargo test` (Windows) 全部通过

### US-007: 统一 IoError + 平台错误映射
**Description:** 作为库用户，我需要一个统一的错误类型，包含所有平台可能的错误场景，且能清晰地判断错误原因。

**Acceptance Criteria:**
- [ ] `IoError` 枚举包含所有平台的错误变体:
  - `Socket(std::io::Error)` — 通用 socket 错误
  - `Parse(&'static str)` — 解析错误
  - `Timeout` — 超时
  - `InvalidMagic(u32)` — pcap magic 不匹配 (已有)
  - `NameTooLong(usize)` — DNS 标签过长 (已有)
  - `CompressionLoop` — DNS 压缩循环 (已有)
  - `InterfaceNotFound(String)` — 接口不存在
  - `PermissionDenied` — 权限不足（sudo / admin）
  - `BpfError(&'static str)` — BPF 特定错误
  - `NpcapError(String)` — NPcap 特定错误
  - `UnsupportedPlatform` — 当前平台不支持的操作
- [ ] `std::error::Error` + `Display` + `From<std::io::Error>` 全实现
- [ ] `cargo clippy` 无警告

### US-008: 网络接口枚举
**Description:** 作为库用户，我需要列出本机可用的网络接口及其属性，以便选择正确的接口进行抓包/发送。

**Acceptance Criteria:**
- [ ] `Interface` struct: `name: String`, `friendly_name: Option<String>`, `mac_address: Option<[u8; 6]>`, `ips: Vec<IpAddr>`, `is_loopback: bool`, `is_up: bool`
- [ ] `list_interfaces() -> Result<Vec<Interface>, IoError>` — 跨平台接口枚举
- [ ] Linux 实现: 通过 `SIOCGIFCONF` + `SIOCGIFHWADDR` + `SIOCGIFFLAGS` 获取
- [ ] macOS 实现: 通过 `getifaddrs()` 获取
- [ ] Windows 实现: 通过 NPcap `pcap_findalldevs` 或 Win32 API 获取
- [ ] 单元测试: 至少验证 lo/lo0/Loopback 接口存在
- [ ] `cargo clippy` 无警告

### US-009: 跨平台示例
**Description:** 作为新用户，我需要看到在 Linux/macOS/Windows 上都能工作的示例代码，快速上手。

**Acceptance Criteria:**
- [ ] `examples/cross_platform_dump.rs` — 从命令行参数指定接口，抓包并打印（三平台通用）
- [ ] `examples/cross_platform_send.rs` — 构造并发送 Ethernet 帧（三平台通用）
- [ ] `examples/list_interfaces.rs` — 列出本机所有接口
- [ ] 每个示例顶部有平台说明和权限提示（sudo / admin）
- [ ] 所有示例 `cargo run --example` 可编译通过

### US-010: trait 对象的类型别名与文档
**Description:** 作为库用户，我需要知道在当前编译平台上 `DefaultL2Reader` / `DefaultL3Reader` 等类型别名指向哪个具体实现。

**Acceptance Criteria:**
- [ ] `pub type DefaultL2Reader = ...` — 根据 `cfg(target_os)` 自动选择
- [ ] `pub type DefaultL2Writer = ...`
- [ ] `pub type DefaultL3Reader = ...`
- [ ] `pub type DefaultL3Writer = ...`
- [ ] `wireforge-io/src/lib.rs` crate-level docstring 说明各平台使用的实现
- [ ] `cargo doc --no-deps` 无警告

## Functional Requirements

- FR-1: 定义 `L2Reader` / `L2Writer` / `L3Reader` / `L3Writer` 四个核心 trait
- FR-2: Linux 实现 (`L2Receiver`, `L2Sender`, `L3Receiver`, `L3Sender`) 适配新 trait
- FR-3: macOS 实现 (`BpfReader`, `BpfWriter`, `BsdL3Receiver`, `BsdL3Sender`) 提供完整 L2/L3 支持
- FR-4: Windows 实现 (`NpcapReader`, `NpcapWriter`, `WinL3Receiver`, `WinL3Sender`) 提供完整 L2/L3 支持
- FR-5: 统一 `IoError` 涵盖三平台所有错误场景
- FR-6: `list_interfaces()` 跨平台接口枚举
- FR-7: 提供 `DefaultL2Reader` 等平台自适应类型别名
- FR-8: 三平台各有至少 1 个集成测试用例
- FR-9: 所有平台 `cargo build --workspace` 可编译
- FR-10: BPF/NPcap 依赖通过 feature flag 按需引入，避免在无关平台上编译不必要的依赖

## Non-Goals

- ❌ 不做 DPDK / netmap / PF_RING 等高性能数据包框架集成 — 这是完全不同的性能层级，适合单独的 crate
- ❌ 不做 Android/iOS 移动端平台支持 — sockfd 在移动端受限
- ❌ 不做 L2 注入在 Windows 上的完整替代方案 — WinPcap/NPcap 对 L2 发送支持有限，文档中注明
- ❌ 不做 BPF filter expression 编译 — 只做数据包捕获，过滤留给上层
- ❌ 不做异步 I/O（tokio/async-std）— 这属于 US-006 的扩展，可在未来添加 `AsyncL2Reader` trait
- ❌ 不做 `wireforge-core` 或 `wireforge-packet` 的跨平台改动 — 这两个 crate 已经是纯 Rust，天然跨平台

## Design Considerations

- **trait 优先，struct 次之** — 所有公开 API 接受 `&mut dyn L2Reader` 而非具体类型，方便用户 mock 和替换
- **平台 feature flag** — 每个平台实现用 `#[cfg(target_os = "linux")]` 等条件编译控制，不引入不必要的依赖
- **NPcap 依赖处理** — Windows 上 `npcap` crate 是可选依赖，用户可通过 feature flag `npcap` 控制是否引入
- **BPF 缓冲区管理** — BPF 设备读到的是完整帧（含 BPF header），需要剥离 BPF header 后返回干净的 Ethernet 帧
- **权限提示** — 在文档和示例中明确标注哪些操作需要 root/Administrator 权限
- **错误信息质量** — 每个平台错误包含足够的上下文信息（接口名、操作类型），方便调试

## Technical Considerations

- **BPF 设备限制** — macOS 上 /dev/bpf 设备数量有限（默认 4 个），需要在文档中说明
- **Windows raw socket 限制** — Windows 7+ 对 raw socket 有限制（不能发送 TCP/UDP），但 IPPROTO_RAW 仍可用于 L3
- **NPcap API 与 WinPcap 兼容** — NPcap 是 WinPcap 的现代替代，API 兼容但提供更多功能（loopback 捕获等）
- **loopback 测试** — lo/lo0 接口不需要物理网卡，可以在 CI 中自动测试
- **依赖版本** — 建议 `socket2` 保持 `0.5`，`npcap` 使用最新稳定版，`libc` 已经是依赖

## Success Metrics

- 三平台 `cargo build` 均通过（CI 矩阵: ubuntu-latest, macos-latest, windows-latest）
- 三平台 `cargo test` 均通过
- 每个平台的集成测试能完成 loopback 收发往返
- `list_interfaces()` 在三平台上均返回至少 1 个接口（loopback）

## Open Questions

- Windows L2 发送是否完全可行？NPcap 支持 L2 发送但需要管理员权限，且部分驱动可能不支持。是否降级为 `L2Reader-only` 的 Windows L2 支持？
- BPF 缓冲区大小默认值是否需要可配置？macOS 默认 4096 字节，可能不足以捕获大型数据包
- `list_interfaces()` 返回的 `friendly_name` 在 Linux 上通常为空（只有 macOS 的 "Built-in Ethernet" 和 Windows 的友好名称），是否需要统一？
- 是否需要支持 Wi-Fi 监控模式（monitor mode）？这在三平台上的 API 差异极大，建议标记为 v2
- Windows 上是否需要支持 WinPcap（旧版）还是只支持 NPcap？NPcap 是 WinPcap 的继任者，建议只支持 NPcap
