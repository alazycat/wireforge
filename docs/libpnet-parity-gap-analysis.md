# WireForge 与 libpnet 差距分析

**日期：** 2026-11-01
**对比基准：** libpnet v0.35.0（tag `f2ff90c`）+ master `e4fc80a`（2026-05-01）
**WireForge 版本：** 1.1.0（HEAD `9e4ff4d`）
**验证方式：** 逐模块对照上游源码；`cargo test --workspace` 通过（exit 0）

> **状态更新（2026-11-01，Issue #19）**：本文撰写后，以下差距已通过对应 issue
> 修复并合并：IPv4 options 构造（#12）、serde/MacAddr/IANA 常量（#15）、
> SLL/SLL2（#16）、VXLAN（#17）、flowcontrol/USBPcap（#18）。
> P1 §1/§2 关于"没有 `MutablePacket` / 公共 `Packet` trait"的结论已过时——
> `wireforge-core::packet` 现提供 `Packet`/`MutablePacket`/`PacketSize`/`FromPacket`。
> 其余结论（macOS 空壳、Windows L2 发送缺失、`pnet_macros`/`pnet_transport`
> 无对应物）仍然有效。

## 结论

WireForge 在协议解析/构造的覆盖面上已经接近甚至部分超过 libpnet，但距离 README 宣称的
"complete replacement" 仍有明显差距。当前更准确的定位是：

> **Linux 上可用的 libpnet 子集，加上更完整的应用层协议与 pcap 文件能力。**

主要差距集中在三块：

1. **跨平台 I/O 完成度**——macOS 全部为空壳，Windows L2 只能收不能发；
2. **libpnet 的核心 API 抽象**——`MutablePacket`、泛型 `Packet` trait、`pnet_macros`、
   `pnet_transport` 均无对应物；
3. **协议与校验和细节**——IPv6 上的 TCP/UDP 校验和、L3 IPv6、SLL/SLL2/VXLAN 等。

---

## 差距总览

| 维度 | libpnet 0.35 | WireForge | 差距 |
|---|---|---|---|
| macOS L2/L3 I/O | 完整 | **全部空壳** | 🔴 严重 |
| Windows L2 发送 | 完整 | **不支持** | 🔴 严重 |
| 可变包 / 泛型 Packet API | `MutablePacket` + `Packet` traits | 无 | 🔴 严重 |
| 自定义协议宏 | `pnet_macros` derive | 无 | 🟠 大 |
| 传输层抽象 | `pnet_transport` | 无 | 🟠 中 |
| IPv6 上的 TCP/UDP 校验和 | 支持 | 不支持 | 🟠 中 |
| 协议模块 | 18 个 packet 模块 | core 12 + app 15 | 🟡 小（各有取舍） |
| 应用层、pcap/pcapng 文件 I/O | 弱/无 | 强 | 🟢 WireForge 领先 |

---

## P0 — 平台 I/O：目前只有 Linux 真正完整

README 的平台表把 macOS BPF 和 Windows NPcap 都标为可用，但实现并非如此。

| 能力 | 实际情况 | 位置 |
|---|---|---|
| macOS BPF L2 收发 | `new`/`recv`/`set_timeout`/`set_promiscuous`/`send` **全部返回 `UnsupportedPlatform`** | `wireforge-io/src/macos/bpf.rs:16-44` |
| macOS L3 raw socket | 同样全部空壳 | `wireforge-io/src/macos/l3.rs:14-39` |
| Windows NPcap 发送 | `NpcapWriter::new` 直接返回 `UnsupportedPlatform` | `wireforge-io/src/windows/npcap.rs:240-250` |
| Windows 混杂模式 | `pcap_open_live` 硬编码 `promisc=0`；`set_promiscuous` 直接报错 | `wireforge-io/src/windows/npcap.rs:169-176,217-221` |
| Windows 超时 | 在 `pcap_open_live`（已激活句柄）之后调用 `pcap_set_timeout`，按 libpcap 语义会返回错误，且返回值被忽略，超时基本不生效 | `wireforge-io/src/windows/npcap.rs:210-215` |
| L3 仅 IPv4 | trait 固定为 `Ipv4Packet` / `SocketAddrV4`，无法收发 IPv6 | `wireforge-io/src/traits.rs:8,40,52` |
| 通用 `Config`/`channel` | 无读写缓冲大小、无写超时、无 Linux `PACKET_FANOUT`、无 `socket_fd`、无 `build_and_send` 批量发送；reader/writer 是两个独立对象，没有 libpnet `datalink::channel()` 的 (tx, rx) 对 | `wireforge-io/src/traits.rs` |
| 接口枚举信息 | 无 `index`、无 netmask/prefix、无 `description`/flags；Linux 只取每接口的第一个 IPv4，没有 IPv6 | `wireforge-io/src/interface.rs:11-25,88-106` |
| 平台广度 | libpnet 还覆盖 Android、FreeBSD/OpenBSD/NetBSD、illumos/Solaris（BPF）、netmap、libpcap、winpkfilter、dummy 测试后端 | — |

**影响：**

- macOS 用户目前完全不能用；
- Windows 用户只能抓、不能发，也不能开混杂模式；
- 从 libpnet 迁移到 Windows 会直接丢失发送和 promiscuous 能力。

这是 "complete replacement" 最大的硬门槛。

---

## P1 — API 抽象：libpnet 的核心能力没有对应物

### 1. 没有 MutablePacket / 原地修改包

libpnet 的所有包都有 `Mutable*Packet` + 字段 setter，可以直接在已有 buffer 上改字段、
重算校验和。WireForge 只有只读 parser + `Builder::build() -> Vec<u8>`
（如 `wireforge-core/src/ipv4.rs:152` 起）。做 TTL 递减、NAT、改 MAC、就地改校验和
这类高性能操作，WireForge 必须重新分配和拷贝。

### 2. 没有公共 `Packet` / `MutablePacket` / `PacketSize` / `FromPacket` trait

libpnet 可以写 `fn handle<T: Packet>(p: T)` 这类泛型代码；WireForge 每个协议只有各自的
固有 `new()`/`payload()`，没有统一抽象。

### 3. 没有 `#[derive(Packet)]`（pnet_macros）

libpnet 用户能定义私有/实验协议并自动生成解析器、setter、迭代器。WireForge 加新协议
必须手写 parser/builder，也无法接入泛型体系。PRD 把它列为 non-goal，但这是与
"drop-in replacement" 定位直接冲突的。

### 4. 没有 `pnet_transport` 等价层

libpnet 提供 `transport_channel`、`tcp_packets()`/`udp_packets()`/`icmp_packets()`
迭代器、TTL/ECN 设置、带超时的 `next_with_timeout()`。WireForge 只有更底层的
L3 raw socket。

### 5. TCP/UDP 校验和只支持 IPv4 伪头

- `TcpPacket::verify_checksum(src: Ipv4Addr, ...)`、`TcpPacketBuilder::build(src: Ipv4Addr, ...)`
  —— `wireforge-core/src/tcp.rs:283,448`
- UDP 同理 —— `wireforge-core/src/udp.rs:54,106`

libpnet 同时提供 `ipv4_checksum`、`ipv6_checksum` 以及用于分段的 `_adv` 变体。
**ICMPv6 已经支持 IPv6 伪头，但 TCP/UDP over IPv6 无法正确构造或校验。**

### 6. 其他细节

- IPv4 options 只能解析、不能构造（builder 没有 `options()`，`ipv4.rs:152-244`）。
- 没有 serde feature；MAC 是 `[u8; 6]`，libpnet 有带 `Display`/`FromStr`/serde 的
  `MacAddr`。
- IANA 常量覆盖少：libpnet `ip.rs` 有 147 个协议号常量，WireForge 的 `IpProtocol`
  只有 6 个命名值 + `Unknown(u8)`；EtherType 同理（23 vs 7）。
- 发送 API 只有 `send(&[u8])`，没有 libpnet 的 `build_and_send` 批量零拷贝接口。

---

## P2 — 协议覆盖：不是单向落后，各有取舍

### libpnet 有、WireForge 没有的 packet 模块

| 模块 | 用途 |
|---|---|
| `sll` / `sll2` | Linux cooked capture；解析 `tcpdump -i any` / `LINKTYPE_LINUX_SLL` 抓包必需 |
| `vxlan` | VXLAN 隧道封装 |
| `flowcontrol` | 以太网 PAUSE / PFC 流控帧 |
| `usbpcap` | USBPcap 抓包头部 |

### 两边都有、但实现方式不同的

- **DNS、DHCP**：libpnet 0.35 已有 `dns.rs`/`dhcp.rs`（底层 packet 字段定义），
  迁移指南写 "Application-layer: None" 不准确；WireForge 的 app 层解析/构造更完整。
- **IPv6 扩展头**：libpnet 也有 HopByHop/Routing/Fragment/Destination 支持，
  迁移指南写 "IPv6 basic" 不准确。WireForge 多了链深度限制和统一迭代器。
- **GRE**：两边都有；PRD 里 "libpnet 有 GRE、WireForge 缺失" 的描述是过时的。
- **IPv4 options / TCP options / ICMPv6 NDP**：两者都有，WireForge 的 TCP options
  迭代器还更完整。

### WireForge 真正领先的地方

- IGMP v1/v2/v3（libpnet 没有 IGMP 模块）；
- pcap/pcapng 文件读写；
- DNS 压缩名/Builder；
- TLS/SSH/MQTT/Modbus/RADIUS/mDNS/LLMNR/NetBIOS/SMB2/RDP 等应用层协议；
- typed ICMP/IGMP 消息；
- Visitor 分发。

---

## P3 — 工程与文档：几处"宣称"和"实际"不一致

### 1. README 与实现不符

README 写 "complete replacement for libpnet"，平台表写 macOS BPF 可用——与
`wireforge-io/src/macos/*.rs` 的空壳实现矛盾。

### 2. 迁移指南的优势表过时/不准确

`docs/migration-from-libpnet.md` 中：

- "Application-layer: None" —— libpnet 0.35 已有 dns/dhcp 模块；
- "Fuzz testing: No" —— libpnet 仓库有 `fuzz/fuzzers/`（6 个 target）；
- "no_std: libpnet No" —— `pnet_packet` 本身就是无条件 `#![no_std] + alloc`；
  WireForge 的真实优势是 **wireforge-core 零依赖**，不是 no_std；
- "IPv6 basic" —— libpnet 有扩展头支持。

### 3. PRD 已过时

`tasks/prd-wireforge-libpnet-parity.md` 说 IGMP 缺失（已实现）、GRE 缺失（已实现）、
Windows NPcap 空壳（reader 已实现）、libpnet 有 IGMP / 无 GRE（实际相反）。

### 4. CI 没有真正验证跨平台 I/O

- 全仓库没有任何 `#[ignore]` 测试，因此 `cargo test -- --ignored` 的 Linux/macOS
  root job **实际跑 0 个测试**；
- macOS job 只证明空壳能编译，从未验证 BPF/L3；
- Windows 的 `npcap.rs` 测试没有 `#[ignore]` 保护，而 workflow 没有安装 Npcap 的步骤，
  干净 runner 上很可能直接失败；
- 没有 `wireforge-io/tests/` 集成测试；libpnet 有 `dummy` 后端可用于注入式测试，
  WireForge 没有等价物。

---

## 补齐优先级建议

1. **macOS BPF L2 + L3**（或先修 README/CI，明确标记为未实现）
2. **Windows Npcap：发送、promisc、正确的超时设置**
3. **`Packet`/`MutablePacket` trait + 原地修改 API**（架构级差距，决定能否真正替代 libpnet）
4. **IPv6：L3 收发 + TCP/UDP 伪头校验和**
5. **SLL/SLL2、VXLAN**
6. **统一 `Config`/`channel`、`build_and_send`、Linux fanout**
7. **pnet_macros / pnet_transport**：若目标真的是 "complete replacement" 就必须补；
   若只覆盖常见抓包/发包场景，可以明确写进 non-goals，避免文档误导。

---

## 对应 GitHub Issues

以上差距已拆分为 GitHub Issues（2026-11-01 创建），使用 `P0`/`P1`/`P2`/`P3` 标签：

| 优先级 | Issue | 主题 |
|---|---|---|
| P0 | [#3](https://github.com/alazycat/wireforge/issues/3) | macOS BPF L2 抓包与注入实现 |
| P0 | [#4](https://github.com/alazycat/wireforge/issues/4) | macOS L3 raw socket 收发实现 |
| P0 | [#5](https://github.com/alazycat/wireforge/issues/5) | Windows Npcap：发送、混杂模式、超时 |
| P0 | [#6](https://github.com/alazycat/wireforge/issues/6) | L3 I/O 支持 IPv6 |
| P0 | [#7](https://github.com/alazycat/wireforge/issues/7) | datalink Config/channel、fanout、批量发送 |
| P0 | [#8](https://github.com/alazycat/wireforge/issues/8) | Interface 枚举信息补齐 |
| P1 | [#9](https://github.com/alazycat/wireforge/issues/9) | 公共 Packet trait 家族 |
| P1 | [#10](https://github.com/alazycat/wireforge/issues/10) | Mutable*Packet 原地修改 API |
| P1 | [#11](https://github.com/alazycat/wireforge/issues/11) | TCP/UDP IPv6 校验和 |
| P1 | [#12](https://github.com/alazycat/wireforge/issues/12) | IPv4 options 构造 |
| P1 | [#13](https://github.com/alazycat/wireforge/issues/13) | pnet_macros 等价派生宏（需确认范围） |
| P1 | [#14](https://github.com/alazycat/wireforge/issues/14) | pnet_transport 等价传输层（需确认范围） |
| P1 | [#15](https://github.com/alazycat/wireforge/issues/15) | serde、MacAddr、IANA 常量 |
| P2 | [#16](https://github.com/alazycat/wireforge/issues/16) | SLL/SLL2（Linux cooked capture） |
| P2 | [#17](https://github.com/alazycat/wireforge/issues/17) | VXLAN |
| P2 | [#18](https://github.com/alazycat/wireforge/issues/18) | Ethernet flow control 与 USBPcap |
| P3 | [#19](https://github.com/alazycat/wireforge/issues/19) | README/迁移指南/PRD 修正 |
| P3 | [#20](https://github.com/alazycat/wireforge/issues/20) | CI 与测试基础设施 |

---

## 附录 A：libpnet 0.35.0 packet 模块清单

```
arp, dhcp, dns, ethernet, flowcontrol, gre, icmp, icmpv6, ip,
ipv4, ipv6, sll, sll2, tcp, udp, usbpcap, vlan, vxlan, util
```

其中 WireForge 缺失：`sll`、`sll2`、`vxlan`、`flowcontrol`、`usbpcap`。
libpnet 没有 `igmp` 模块（WireForge 已实现 IGMP，属于领先项）。

## 附录 B：本次核对的关键源码位置

| 主题 | WireForge 位置 |
|---|---|
| macOS BPF 空壳 | `wireforge-io/src/macos/bpf.rs:16-44` |
| macOS L3 空壳 | `wireforge-io/src/macos/l3.rs:14-39` |
| Windows L2 发送空壳 | `wireforge-io/src/windows/npcap.rs:240-250` |
| Windows promisc/超时 | `wireforge-io/src/windows/npcap.rs:169-176,210-221` |
| IPv4-only L3 trait | `wireforge-io/src/traits.rs:8,40,52` |
| 接口信息结构 | `wireforge-io/src/interface.rs:11-25` |
| Linux 接口仅首个 IPv4 | `wireforge-io/src/interface.rs:88-106` |
| TCP IPv4 校验和 | `wireforge-core/src/tcp.rs:283,448` |
| UDP IPv4 校验和 | `wireforge-core/src/udp.rs:54,106` |
| IPv4 builder（无 options） | `wireforge-core/src/ipv4.rs:152-244` |
| CI workflow | `.github/workflows/ci.yml` |

---

## 参考

- libpnet 仓库：<https://github.com/libpnet/libpnet>
- libpnet v0.35.0：tag `f2ff90c`（2024-05-30）
- 迁移指南：`docs/migration-from-libpnet.md`
- 对标 PRD：`tasks/prd-wireforge-libpnet-parity.md`（部分内容已过时）
