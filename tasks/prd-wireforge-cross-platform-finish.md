# PRD: WireForge 跨平台 I/O 收尾 — 生产就绪

## Introduction

WireForge `wireforge-io` 的跨平台 trait 架构已就位（#27），Linux 适配和 Windows L3 已完成（#28/#32），但以下模块仍是空壳或占位符：macOS BPF L2（#29）、macOS L3（#30）、Windows NPcap L2（#31）、`list_interfaces()`（#33）、类型别名和共享工具（#34）、跨平台示例（#35）、CI 矩阵（#36）。

本 PRD 将这些收尾工作打包为完整交付，达到"三平台均可编译、各平台通过集成测试、文档齐全"的生产就绪标准。

## Goals

- macOS BPF L2 收发完整实现并通过 lo0 集成测试
- macOS L3 raw socket 完整实现并通过 lo0 集成测试
- Windows NPcap L2 捕获实现（至少 L2Reader，L2Writer 标记平台限制）
- `list_interfaces()` 三平台完整实现
- `DefaultL2Reader` 等类型别名 + 共享工具 `common/mod.rs` 完善
- 3 个跨平台示例程序
- CI 矩阵覆盖 ubuntu/macos/windows
- 所有模块 rustdoc 完整

## User Stories

### US-001: macOS BPF L2 完整实现
**Description:** 作为 macOS 用户，我需要 BPF 设备捕获 Ethernet 帧并发送 L2 帧，支持混杂模式和超时。

**Acceptance Criteria:**
- [ ] `BpfReader` 完整实现：打开 `/dev/bpfN`、`BIOCSETIF` 绑定接口、`BIOCIMMEDIATE` 立即模式、`BIOCSBLEN` 缓冲区（默认 64KB，可配置）
- [ ] `BpfReader::recv()` — `read(fd, buf)` → 剥离 BPF header（`bpf_hdr` 18/26 bytes） → `EthernetPacket`
- [ ] `set_promiscuous()` — `BIOCPROMISC` ioctl
- [ ] `set_timeout()` — `BIOCSRTIMEOUT` ioctl
- [ ] `BpfWriter` 完整实现：`write(fd, frame)` 通过 BPF 设备发送
- [ ] `BpfReader::with_buffer_size(ifname, buf_size)` — 自定义缓冲区
- [ ] BPF 设备耗尽时返回 `IoError::Bpf("no free bpf devices")`
- [ ] 集成测试: lo0 接口发送→接收往返验证
- [ ] 单元测试: BPF header 剥离正确性（模拟 bpf_hdr + Ethernet 帧）
- [ ] `cargo test` (macOS) 全部通过

### US-002: macOS L3 raw socket 完整实现
**Description:** 作为 macOS 用户，我需要 raw socket 收发 IPv4 数据包，支持 IP_HDRINCL。

**Acceptance Criteria:**
- [ ] `BsdL3Receiver` 完整实现：`Socket::new(Domain::IPV4, Type::RAW, proto)`
- [ ] `recv()` — `sock.recv(&mut buf)` → `Ipv4Packet`
- [ ] `set_header_included()` — `IP_HDRINCL` setsockopt
- [ ] `set_timeout()` — `SO_RCVTIMEO` setsockopt
- [ ] `BsdL3Sender` 完整实现 + `send_to()`
- [ ] 集成测试: lo0 ICMP Echo 往返
- [ ] `cargo test` (macOS) 全部通过

### US-003: Windows NPcap L2 实现
**Description:** 作为 Windows 用户，我需要 NPcap 捕获 Ethernet 帧。L2 发送标记为平台限制。

**Acceptance Criteria:**
- [ ] `NpcapReader` 通过 FFI 调用 `npcap.dll` 的 `pcap_open_live` / `pcap_next_ex` / `pcap_close`
- [ ] 不依赖外部 crate — 纯 `extern "system"` FFI 绑定到 npcap.dll
- [ ] `NpcapReader::new(ifname)` — 打开适配器，设置 snaplen=65535, promisc=1, timeout
- [ ] `recv()` — `pcap_next_ex` → 返回 `(timestamp, packet_data)` → `EthernetPacket`
- [ ] `set_promiscuous()` — 重新打开适配器（或关闭当前再打开）
- [ ] `set_timeout()` — 通过 `pcap_set_timeout` 或重建适配器
- [ ] Windows 上 L2 send 返回 `IoError::UnsupportedPlatform`（NPcap L2 send 需要特殊驱动支持）
- [ ] 单元测试: NPcap DLL 未安装时的错误处理（不 panic）
- [ ] 集成测试: Npcap loopback 捕获（如 NPcap 已安装）
- [ ] `cargo test` (Windows) 全部通过

### US-004: list_interfaces() 三平台完整实现
**Description:** 作为库用户，我需要列出本机所有网络接口及其属性。

**Acceptance Criteria:**
- [ ] Linux: `SIOCGIFCONF` ioctl 获取接口列表 → 逐个 `SIOCGIFFLAGS` / `SIOCGIFHWADDR` / `SIOCGIFADDR` 获取属性
- [ ] macOS: `getifaddrs()` POSIX 函数 → 聚合 AF_LINK（MAC）和 AF_INET/AF_INET6（IP）信息
- [ ] Windows: `GetAdaptersInfo` (iphlpapi.dll) 或 `GetAdaptersAddresses` FFI → 提取名称/MAC/IP/状态
- [ ] `Interface` struct 所有字段正确填充
- [ ] 至少返回 loopback 接口
- [ ] 无权限要求（三平台均可非 root 运行）
- [ ] `cargo test` 各平台通过

### US-005: 类型别名 + 共享工具完善
**Description:** 作为库用户，我需要 `DefaultL2Reader` 等类型别名在文档中可查，且跨平台共享代码不重复。

**Acceptance Criteria:**
- [ ] 确认 `DefaultL2Reader` / `DefaultL2Writer` / `DefaultL3Reader` / `DefaultL3Writer` 四别名正确指向各平台实现
- [ ] `common/mod.rs` 补充: `set_promiscuous_linux()` 等共享辅助（如有）
- [ ] 类型别名有 rustdoc 说明
- [ ] `cargo doc --no-deps -p wireforge-io` 无警告

### US-006: 跨平台示例
**Description:** 作为新用户，我需要看到可在当前平台直接运行的示例代码。

**Acceptance Criteria:**
- [ ] `examples/cross_platform_dump.rs` — 接口名从命令行参数或 `list_interfaces()` 获取，捕获并打印 10 个 Ethernet 帧（含 EtherType + MAC 地址 + 长度）
- [ ] `examples/cross_platform_send.rs` — 构造 Ethernet + IPv4 + ICMP Echo Request 并发送到指定目标
- [ ] `examples/list_interfaces.rs` — 调用 `list_interfaces()` 并表格化打印所有接口属性
- [ ] 每个示例使用 `DefaultL2Reader` 等类型别名
- [ ] 顶部有平台说明和权限提示（`sudo` / `Administrator`）
- [ ] `cargo build --example` 三平台均通过
- [ ] `cargo clippy` 无警告

### US-007: CI 矩阵 + 文档
**Description:** 作为库维护者，我需要 CI 在三平台上自动运行，且文档覆盖所有公开 API。

**Acceptance Criteria:**
- [ ] `.github/workflows/ci.yml` — 3 平台矩阵（ubuntu-latest, macos-latest, windows-latest）
- [ ] 每个 job: `cargo build --workspace` + `cargo test --workspace` + `cargo clippy --workspace`
- [ ] Linux job 以 root 运行集成测试
- [ ] macOS job 以 root 运行 BPF 集成测试
- [ ] Windows job 测试 NPcap 存在性检测（不 panic）
- [ ] `wireforge-io/src/lib.rs` crate 级 docstring 完整
- [ ] 每个平台模块 (`linux/mod.rs`, `macos/mod.rs`, `windows/mod.rs`) 有模块级 docstring
- [ ] 每个公开方法/struct 有 rustdoc
- [ ] `cargo doc --no-deps --workspace` 无警告
- [ ] README 更新为反映三平台状态

## Functional Requirements

- FR-1: macOS BPF L2 收发必须通过 `/dev/bpf` 设备实现，不使用 libpcap
- FR-2: macOS L3 收发必须使用 raw socket（与 Linux 共用 >90% 代码）
- FR-3: Windows NPcap L2 必须使用纯 FFI（`extern "system"`），不依赖外部 Rust crate
- FR-4: `list_interfaces()` 在非 root 下可运行
- FR-5: 所有平台实现的错误必须映射到统一的 `IoError` 变体
- FR-6: CI 矩阵必须覆盖三平台
- FR-7: 每个平台至少 1 个集成测试用例
- FR-8: 类型别名必须在文档中可见

## Non-Goals

- ❌ 不做 macOS DLT (Data Link Type) 自动检测 — 默认假设 Ethernet
- ❌ 不做 BPF filter expression 编译（BPF bytecode）
- ❌ 不做 Windows L2 send 的 NPcap 驱动适配（仅 L2Reader）
- ❌ 不做 Wi-Fi 监控模式（monitor mode）
- ❌ 不做 macOS NetworkExtension API（现代替代 BPF 的框架，需要特殊的 entitlement）
- ❌ 不做 pcap/pcapng 在 `wireforge-io` 中的集成（已在 wireforge-app 中）

## Technical Considerations

- **NPcap FFI 绑定范围**: 只需 4 个函数 — `pcap_findalldevs`, `pcap_open_live`, `pcap_next_ex`, `pcap_close`, `pcap_freealldevs`, `pcap_set_timeout`
- **BPF header 结构**: macOS 64-bit 上 `bpf_hdr` 为 18 字节（`bh_tstamp(8) + bh_caplen(4) + bh_datalen(4) + bh_hdrlen(2)`），需按实际平台调整
- **macOS `/dev/bpf` 权限**: 需要 root 或 `readwrite` 权限组。文档中注明可使用 `sudo chmod` 或配置 `devfs` 规则
- **Windows raw socket 限制**: Windows 10+ raw socket 可收发 IPPROTO_RAW 数据包，但不能在 TCP/UDP 协议上接收
- **CI 权限**: Linux `sudo`, macOS `sudo`（或使用 `pfctl` 配置），Windows 无需特殊权限（NPcap 已安装）

## Success Metrics

- `cargo build --workspace` 在 ubuntu-latest, macos-latest, windows-latest 均通过
- `cargo test` 在 Linux 和 macOS 上集成测试通过（含 lo/lo0 收发往返）
- `list_interfaces()` 在三平台上均返回 ≥1 个接口
- `cargo doc --no-deps --workspace` 零警告
- 96+ 测试全部通过（现有测试无回归）

## Open Questions

- NPcap DLL 是否总是安装在 `C:\Windows\System32\Npcap\`？是否需要 fallback 搜索路径？
- macOS BPF 设备数量限制（默认 4 个）是否需要在文档中明确说明？
- `list_interfaces()` 在 Windows 上是否需要 fallback 到 `GetAdaptersAddresses`（如果 NPcap 未安装）？
- 是否需要支持 macOS 上的 BPF `BIOCGBLEN` 读取默认缓冲区大小？
- Windows 集成测试是否需要 mock NPcap 或检查 NPcap 是否已安装后 skip？
