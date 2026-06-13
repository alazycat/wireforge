# SPEC: WireForge 跨平台 I/O 收尾 — 生产就绪

> Technical specification derived from: [tasks/prd-wireforge-cross-platform-finish.md](prd-wireforge-cross-platform-finish.md)
> Generated: 2026-06-13 | Target branch: main | Project: wireforge

## 1. Summary

### 1.1 What This SPEC Covers

本 SPEC 定义 `wireforge-io` 三平台完整实现的剩余部分：macOS BPF L2、macOS L3 raw socket、Windows NPcap L2 FFI、三平台 `list_interfaces()`、类型别名完善、跨平台示例、CI 矩阵配置。这是跨平台 I/O 系列 SPEC 的第二部分（第一部分 `spec-wireforge-cross-platform-io.md` 已实现 trait 架构 + Linux 适配 + Windows L3）。

### 1.2 PRD Reference

- Source: `tasks/prd-wireforge-cross-platform-finish.md`
- User Stories covered: US-001 ~ US-007
- Functional Requirements covered: FR-1 ~ FR-8

### 1.3 Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| NPcap FFI | `extern "system"` 手动声明 wpcap.dll 函数 | 零外部 Rust crate 依赖，仅 6 个函数签名 |
| Windows 接口枚举 | IP Helper API (`GetAdaptersAddresses`) | 系统自带，无需 NPcap |
| macOS BPF | 直接 `/dev/bpf` ioctl，不依赖 libpcap | 轻量、与 Linux AF_PACKET 模式一致 |
| macOS L3 | 与 Linux 共享 >90% 代码，仅常量名差异 | BSD/Linux socket API 几乎一致 |
| L2 send on Windows | 返回 `UnsupportedPlatform` | NPcap `pcap_sendpacket` 在 WiFi 适配器上常不可用 |
| `list_interfaces()` 权限 | 非 root 可运行 | 三平台均可非特权用户获取接口列表 |

---

## 2. Architecture

### 2.1 Module Completion Status

```
wireforge-io/src/
├── traits.rs              ✅ 已完成 (#27)
├── error.rs               ✅ 已完成 (#27)
├── lib.rs                 ✅ 已完成 (#27)
├── interface.rs           ⚠️ 占位符 — 本 SPEC 完成
├── common/mod.rs          ⚠️ 部分 — 本 SPEC 完善
├── linux/
│   ├── mod.rs             ✅ 已完成 (#28)
│   ├── l2.rs              ✅ 已完成 (#28)
│   └── l3.rs              ✅ 已完成 (#28)
├── macos/
│   ├── mod.rs             ✅ 骨架
│   ├── bpf.rs             ❌ 空壳 — 本 SPEC 完成 (US-001)
│   └── l3.rs              ❌ 空壳 — 本 SPEC 完成 (US-002)
├── windows/
│   ├── mod.rs             ✅ 骨架
│   ├── npcap.rs           ❌ 空壳 — 本 SPEC 完成 (US-003)
│   └── l3.rs              ✅ 已完成 (#32)
```

### 2.2 New files

```
.github/workflows/ci.yml                     [NEW] — 三平台 CI 矩阵
wireforge-io/examples/
├── cross_platform_dump.rs                   [NEW]
├── cross_platform_send.rs                   [NEW]
└── list_interfaces.rs                       [NEW]
```

---

## 3. macOS BPF Implementation (US-001)

### 3.1 BPF Device Lifecycle

```
open("/dev/bpfN")  →  BIOCSETIF  →  BIOCIMMEDIATE  →  BIOCSBLEN  →  [可选: BIOCPROMISC]
       │                  │               │                │
   遍历 0..256       绑定接口        立即模式          缓冲区大小
   找到首个可用       (en0, etc.)    (不等待满缓冲)     (默认 64KB)
```

### 3.2 BPF ioctl Constants

```rust
// macOS/BSD BPF ioctl commands
const BIOCSETIF: libc::c_ulong = 0x8020426c;   // bind to interface
const BIOCIMMEDIATE: libc::c_ulong = 0x80044270; // immediate mode
const BIOCSBLEN: libc::c_ulong = 0x80204270;    // set buffer length
const BIOCPROMISC: libc::c_ulong = 0;           // set promiscuous (no arg)
const BIOCSRTIMEOUT: libc::c_ulong = 0x8008426d; // set read timeout
const BIOCGBLEN: libc::c_ulong = 0x40044266;    // get buffer length (read-only)
```

### 3.3 BPF Header Structure

macOS 64-bit `bpf_hdr`:
```rust
#[repr(C)]
struct BpfHeader {
    bh_tstamp: libc::timeval,  // 16 bytes on 64-bit
    bh_caplen: u32,            // 4 bytes — bytes actually captured
    bh_datalen: u32,           // 4 bytes — original packet length
    bh_hdrlen: u16,            // 2 bytes — header length (18 or 26)
    // possible padding
}
// Total: 26 bytes on 64-bit macOS
```

**bpfilter_hdr** 处理逻辑:
```rust
fn strip_bpf_header(buf: &[u8]) -> (&[u8], u32) {
    // Read bh_hdrlen from last 2 bytes of header area
    let hdrlen_offset = 16; // offset of bh_hdrlen in BpfHeader
    if buf.len() < 18 { return (&[], 0); }
    let hdrlen = u16::from_be_bytes([buf[hdrlen_offset], buf[hdrlen_offset + 1]]) as usize;
    let caplen_offset = 16; // offset of bh_caplen
    let caplen = u32::from_be_bytes([buf[caplen_offset], buf[caplen_offset+1], buf[caplen_offset+2], buf[caplen_offset+3]]);
    if buf.len() < hdrlen + caplen as usize { return (&[], 0); }
    (&buf[hdrlen..hdrlen + caplen as usize], caplen)
}
```

### 3.4 BpfReader Implementation

```rust
pub struct BpfReader {
    fd: std::fs::File,      // /dev/bpfN
    ifname: String,
    buf_size: usize,        // default 65536
}
```

**Constructor sequence:**
1. `for n in 0..256 { File::open(format!("/dev/bpf{n}")) }` — 找到第一个可用设备
2. 构造 `ifreq`，写入接口名，调用 `ioctl(fd, BIOCSETIF, &ifreq)`
3. `ioctl(fd, BIOCIMMEDIATE, &1u32)`
4. `ioctl(fd, BIOCSBLEN, &buf_size)`
5. 返回 `BpfReader`

**`recv()` 流程:**
1. `fd.read(&mut buf)` — buf 大小为 `buf_size`
2. 剥离 BPF header → 得到 Ethernet 帧数据起始指针和长度
3. `EthernetPacket::new(frame_data)?` — 零拷贝解析

### 3.5 BpfWriter Implementation

```rust
pub struct BpfWriter {
    fd: std::fs::File,
}
```

`send(packet)` → `fd.write_all(packet)` — BPF 设备直接写入 L2 帧即可发送。

---

## 4. macOS L3 Implementation (US-002)

### 4.1 Shared Code Strategy

macOS raw socket API 与 Linux 几乎一致。主要差异：
- `libc::IP_HDRINCL` 常量名和类型略有不同
- `setsockopt` 的参数类型在 macOS 上是 `c_int`，Linux 上也是 `c_int`

**实现方案：** 将 Linux `l3.rs` 拷贝到 macOS，调整 import 路径。无需共享通用代码（差异太小，不值得抽象）。

### 4.2 BsdL3Receiver / BsdL3Sender

与 Linux `L3Receiver` / `L3Sender` 完全同构。`set_timeout` 共享 `common::set_socket_timeout`（Unix 分支）。

---

## 5. Windows NPcap L2 Implementation (US-003)

### 5.1 FFI Bindings

绑定 `wpcap.dll` 的 6 个函数：

```rust
extern "system" {
    fn pcap_findalldevs(alldevsp: *mut *mut pcap_if_t, errbuf: *mut u8) -> i32;
    fn pcap_freealldevs(alldevs: *mut pcap_if_t);
    fn pcap_open_live(device: *const u8, snaplen: i32, promisc: i32, to_ms: i32, errbuf: *mut u8) -> *mut pcap_t;
    fn pcap_close(p: *mut pcap_t);
    fn pcap_next_ex(p: *mut pcap_t, pkt_header: *mut *mut pcap_pkthdr, pkt_data: *mut *const u8) -> i32;
    fn pcap_set_timeout(p: *mut pcap_t, timeout_ms: i32) -> i32;
}
```

### 5.2 C 类型映射

```rust
#[repr(C)]
struct pcap_if_t {
    next: *mut pcap_if_t,
    name: *const u8,          // C string
    description: *const u8,   // C string (nullable)
    addresses: *mut pcap_addr_t,
    flags: u32,
}

#[repr(C)]
struct pcap_pkthdr {
    ts: libc::timeval,    // timestamp
    caplen: u32,          // captured length
    len: u32,             // original length
}

type pcap_t = std::ffi::c_void;  // opaque handle
```

### 5.3 NpcapReader Implementation

```rust
pub struct NpcapReader {
    handle: *mut pcap_t,
    _ifname: String,
}
```

**Constructor:**
1. 将 `ifname` 转为 CString
2. 调用 `pcap_open_live(ifname_cstr, 65535, 0, 1000, errbuf)` — snaplen=65535, no promisc, 1s timeout
3. 如果返回 null → 读取 errbuf → `IoError::Npcap(errbuf_string)`
4. 如果不为 null → `NpcapReader { handle, ... }`

**`recv()`:**
1. 声明 `*mut pcap_pkthdr` 和 `*const u8` 指针
2. `pcap_next_ex(handle, &mut header_ptr, &mut data_ptr)`
3. 返回值 = 1 → 成功，用 `header.caplen` 切片 data_ptr → `EthernetPacket::new(data)`
4. 返回值 = 0 → timeout
5. 返回值 < 0 → 错误

**Drop:**
```rust
impl Drop for NpcapReader {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { pcap_close(self.handle); }
        }
    }
}
```

### 5.4 NPcap 未安装处理

构造函数失败时返回 `IoError::Npcap("wpcap.dll not found or failed to open adapter")`。DLL 加载由 Windows loader 自动处理（函数声明为 `extern "system"` 时，首次调用时动态链接）。

**重要：** `extern "system"` 函数在程序启动时解析，如果 `wpcap.dll` 不存在，进程启动即失败。解决方案：使用 `libloading` crate 或 `LoadLibrary` + `GetProcAddress` 动态加载。

更稳妥的方案 — 使用 `LoadLibraryA` / `GetProcAddress`:

```rust
// 在 NpcapReader::new() 中：
let dll = LoadLibraryA("wpcap.dll\0".as_ptr());
if dll.is_null() {
    return Err(IoError::Npcap("wpcap.dll not found. Install NPcap from https://npcap.com".into()));
}
let pcap_open_live: unsafe extern "system" fn(...) -> *mut pcap_t =
    std::mem::transmute(GetProcAddress(dll, "pcap_open_live\0".as_ptr()));
// ... 缓存函数指针或使用 once_cell::Lazy
```

推荐使用 `libloading` crate（已在 `socket2` 的依赖树中可能已经编译过），或者用手动 `LoadLibrary` 方案。

---

## 6. list_interfaces() Implementation (US-004)

### 6.1 Linux Implementation

```
SIOCGIFCONF → 获取所有接口的 ifreq 数组
  └── 对每个接口:
      ├── SIOCGIFFLAGS → 提取 IFF_UP, IFF_LOOPBACK
      ├── SIOCGIFHWADDR → 提取 MAC 地址
      └── SIOCGIFADDR → 提取 IPv4 地址
```

使用 `socket2::Socket::new(Domain::IPV4, Type::DGRAM, None)` 获取临时 socket 用于 ioctl。

### 6.2 macOS Implementation

```
getifaddrs(&mut ifap)
  └── 遍历链表:
      ├── AF_LINK (sockaddr_dl) → MAC 地址 + 接口名
      ├── AF_INET → IPv4 地址
      └── AF_INET6 → IPv6 地址
  └── freeifaddrs(ifap)
```

聚合策略：按接口名分组，合并 AF_LINK 的 MAC 和 AF_INET/AF_INET6 的 IP 列表。`IFF_LOOPBACK` 和 `IFF_UP` 通过 `ifa_flags` 字段获取。

### 6.3 Windows Implementation

使用 IP Helper API (`iphlpapi.dll`) 的 `GetAdaptersAddresses`：

```rust
extern "system" {
    fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: *const c_void,
        addresses: *mut IP_ADAPTER_ADDRESSES,
        size: *mut u32,
    ) -> u32;
}
```

- `family = AF_UNSPEC(0)` — 获取所有地址族
- `flags = GAA_FLAG_INCLUDE_PREFIX(0x0010)` — 包含前缀信息
- 两次调用：第一次获取 size，第二次获取数据

从 `IP_ADAPTER_ADDRESSES` 链表中提取：
- `AdapterName` → `name`
- `FriendlyName` → `friendly_name`
- `PhysicalAddress` → `mac_address`
- `IfType == IF_TYPE_SOFTWARE_LOOPBACK(24)` → `is_loopback`
- `OperStatus == IfOperStatusUp(1)` → `is_up`

---

## 7. Type Aliases + Common Utilities (US-005)

### 7.1 Type Alias Verification

当前 `lib.rs` 已有 4 个类型别名（`DefaultL2Reader` 等）。本 SPEC 确保：
- 每个 alias 有 rustdoc: `/// The default L2 reader for the current platform.`
- `cargo doc` 中可见

### 7.2 common/mod.rs Enhancement

```rust
// 为 Unix 平台统一 timeval 到 Duration 的转换
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn duration_to_timeval(dur: Duration) -> libc::timeval { ... }

// 跨平台 sleep (Duration → timeval / DWORD)
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn set_socket_timeout_unix(fd: c_int, dur: Option<Duration>) -> Result<(), IoError> { ... }
```

---

## 8. Examples (US-006)

### 8.1 cross_platform_dump.rs

```rust
//! Cross-platform packet dumper.
//! Usage: sudo ./cross_platform_dump [interface]
//! If no interface specified, uses list_interfaces() to pick the first non-loopback.

fn main() -> Result<(), Box<dyn Error>> {
    let ifname = std::env::args().nth(1)
        .or_else(|| {
            let ifaces = list_interfaces().ok()?;
            ifaces.iter().find(|i| !i.is_loopback).map(|i| i.name.clone())
        })
        .unwrap_or_else(|| "lo".into());

    let mut rx = DefaultL2Reader::new(&ifname)?;
    rx.set_promiscuous(true)?;
    rx.set_timeout(Some(Duration::from_secs(1)))?;

    println!("Listening on {}...", ifname);
    for _ in 0..10 {
        match rx.recv() {
            Ok(eth) => println!("{} -> {}  EtherType={:?}  len={}",
                mac_hex(&eth.src_mac()), mac_hex(&eth.dst_mac()),
                eth.ethertype(), eth.payload().len() + 14),
            Err(IoError::Timeout) => continue,
            Err(e) => { eprintln!("Error: {e}"); break; }
        }
    }
    Ok(())
}
```

### 8.2 cross_platform_send.rs

构造 Ethernet + IPv4 + ICMP Echo Request → 通过 `DefaultL2Writer` 发送。

### 8.3 list_interfaces.rs

调用 `list_interfaces()` → 表格化打印。

---

## 9. CI Configuration (US-007)

### 9.1 GitHub Actions Matrix

```yaml
name: CI
on: [push, pull_request]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --workspace
      - run: cargo test --workspace
      - run: cargo clippy --workspace -- -D warnings
      - run: cargo doc --no-deps --workspace

  test-linux-root:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo cargo test --workspace -- --ignored  # 运行需 root 的集成测试
```

### 9.2 Platform-Specific CI Notes

- **Linux**: `sudo cargo test` 运行 lo 接口集成测试（已标记 `#[ignore]`）
- **macOS**: `sudo cargo test` 运行 BPF 集成测试
- **Windows**: 标准 `cargo test`（NPcap 集成测试检查 NPcap 是否存在）

### 9.3 Module Documentation

- 每个平台 `mod.rs` 有模块级 docstring，说明后端和限制
- `Interface` struct 各字段有 rustdoc
- `list_interfaces()` 有使用示例 docstring

---

## 10. Testing Strategy

### 10.1 Unit Tests (can run without root)

| Test | Module | Platform | Description |
|------|--------|----------|-------------|
| `test_bpf_header_strip` | macos/bpf | macOS | 模拟 bpf_hdr + frame → strip 正确 |
| `test_npcap_not_installed` | windows/npcap | Windows | DLL 不存在时返回 Npcap 错误，不 panic |
| `test_interface_loopback_present` | interface | All | list_interfaces() 包含 loopback |
| `test_type_alias_compiles` | lib | All | DefaultL2Reader::new("eth0") 可编译 |
| `test_io_error_display_new` | error | All | 新增 IoError 变体 Display 正确 |

### 10.2 Integration Tests (need root, marked `#[ignore]`)

| Test | Content | Platform |
|------|---------|----------|
| `test_macos_bpf_loopback` | lo0 发送→接收往返 | macOS |
| `test_macos_l3_loopback` | lo0 ICMP Echo 往返 | macOS |
| `test_windows_npcap_loopback` | NPcap loopback 捕获 | Windows |
| `test_linux_l2_loopback` | lo 接口 L2 收发 | Linux |

---

## 11. Implementation Plan

### 11.1 Issue Mapping

| Issue | SPEC Sections | Priority | Platform | Depends On |
|-------|--------------|----------|----------|------------|
| #1  | 3.1–3.5 macOS BPF | high | macOS | — |
| #2  | 4.1–4.2 macOS L3 | high | macOS | — |
| #3  | 5.1–5.4 Windows NPcap | high | Windows | — |
| #4  | 6.1–6.3 list_interfaces() | high | All | — |
| #5  | 7.1–7.2 type aliases + common | medium | All | #1, #2, #3 |
| #6  | 8.1–8.3 examples | medium | All | #5 |
| #7  | 9.1–9.3 CI + docs | medium | All | #1–#6 |

### 11.2 Ordering

```
#1 (macOS BPF) ────┐
#2 (macOS L3)  ────┤
                    ├── #5 (type aliases) ── #6 (examples) ── #7 (CI)
#3 (Win NPcap)  ───┤
#4 (list_ifaces) ──┘ (顺序无关，可在 #1/#2/#3 前后)
```

---

## 12. Open Questions & Risks

### 12.1 Unresolved Questions

- NPcap DLL 动态加载方案: `libloading` vs 手动 `LoadLibrary`。建议用 `LoadLibrary` + `GetProcAddress` 因为只加载一个 DLL，无需 `libloading` 依赖。
- macOS BPF `bpf_hdr` 在 ARM64 (Apple Silicon) 上的确切大小？文档说 18 字节但在实践中可能为 26 字节（含 padding 对齐到 8 字节边界）。需在 CI 上和真机上验证。

### 12.2 Technical Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| macOS BPF buffer 大小不足导致丢帧 | P2: 高吞吐时丢包 | `with_buffer_size()` API，默认 64KB 但用户可调至 1MB |
| wpcap.dll 动态加载失败 | P1: Windows L2 不可用 | 优雅降级为 `UnsupportedPlatform` 错误，不 panic |
| `getifaddrs` 在旧版 macOS 上不可用 | P3: macOS 10.5- 不可用 | 文档声明支持 macOS 10.12+ |

### 12.3 Assumptions

- macOS 编译环境已安装 Xcode Command Line Tools（含 libc headers）
- NPcap 用户已手动安装（https://npcap.com）
- CI macOS runner (macos-latest) 有 `/dev/bpf` 设备可用
