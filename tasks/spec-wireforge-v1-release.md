# SPEC: WireForge v1.0 正式发布

> Technical specification derived from: [tasks/prd-wireforge-v1-release.md](prd-wireforge-v1-release.md)
> Generated: 2026-06-13 | Target branch: main | Project: wireforge

## 1. Summary

### 1.1 What This SPEC Covers

本 SPEC 定义 WireForge v1.0 正式发布的完整流程：API 审计清单、安全审计模板、crates.io 发布步骤、CHANGELOG 格式、贡献指南模板。不含新协议实现（已在之前 SPEC 中覆盖）。

### 1.2 PRD Reference

- Source: `tasks/prd-wireforge-v1-release.md`
- User Stories covered: US-001 ~ US-008

### 1.3 Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| API 标注方案 | 文档标注 `#[doc = "Stability: stable"]` | 不引入 feature gate 复杂度，简单可读 |
| MSRV | Rust 1.75 | 2023-12 稳定版，覆盖大多数发行版和 CI |
| Unsafe 审计标准 | 每个 unsafe 块必须有 `// SAFETY:` 注释 | Rust 社区标准 |
| crates.io 发布顺序 | core → packet → io + app (并行) | 依赖拓扑决定 |
| CHANGELOG 格式 | Keep a Changelog 标准 | 社区广泛使用 |
| Semver | 4 crate 同步 v1.0.0，后续独立版本 | v1.0 后各 crate 可独立演进 |

---

## 2. API Audit Checklist (US-001)

### 2.1 wireforge-core (`pub` 导出)

| Item | Type | Stability | Action |
|------|------|-----------|--------|
| `types::EtherType` | enum | Stable | 保持 |
| `types::IpProtocol` | enum | Stable | 考虑添加 `Igmp` 和 `Gre` 变体 |
| `types::ArpOperation` | enum | Stable | 保持 |
| `types::ArpHardwareType` | enum | Stable | 保持 |
| `util::internet_checksum()` | fn | Stable | 保持 |
| `util::pseudo_header_checksum()` | fn | Stable | 保持 |
| `util::read_u16be/u32be` | fn (pub(crate)) | Internal | 已经是 crate-internal |
| `util::BuildError` | enum | Stable | 保持 |
| `ether::EthernetPacket` | struct | Stable | 保持 |
| `ether::EthernetPacketBuilder` | struct | Stable | 保持 |
| `vlan::VlanPacket` | struct | Stable | 保持 |
| `vlan::parse_vlan_chain()` | fn | Stable | 保持 |
| `arp::ArpPacket` | struct | Stable | 保持 |
| `arp::ArpPacketBuilder` | struct | Stable | 保持 |
| `ipv4::Ipv4Packet` | struct | Stable | 保持 |
| `ipv4::Ipv4PacketBuilder` | struct | Stable | 保持 |
| `ipv6::Ipv6Packet` | struct | Stable | 保持 |
| `ipv6::Ipv6ExtensionHeader` | enum | Stable | 保持 |
| `ipv6::Ipv6PacketBuilder` | struct | Stable | 保持 |
| `icmp::IcmpPacket` | struct | Stable | 保持 |
| `icmp::IcmpMessage` | enum | Stable | 保持 |
| `icmp::Icmpv6Packet` | struct | Stable | 保持 |
| `icmp::Icmpv6Message` | enum | Stable | 保持 |
| `tcp::TcpPacket` | struct | Stable | 保持 |
| `tcp::TcpOption` | enum | Stable | 保持 |
| `tcp::TcpOptionsIter` | struct | Stable | 保持 |
| `tcp::TcpPacketBuilder` | struct | Stable | 保持 |
| `udp::UdpPacket` | struct | Stable | 保持 |
| `udp::UdpPacketBuilder` | struct | Stable | 保持 |
| `igmp::IgmpPacket` | struct | Stable | 保持 |
| `igmp::IgmpMessage` | enum | Stable | 保持 |
| `gre::GrePacket` | struct | Stable | 保持 |
| `gre::GrePacketBuilder` | struct | Stable | 保持 |

**Action Items:**
1. `IpProtocol` 枚举: 已包含 `Igmp` 和 `Gre` 的 `Unknown(u8)` 路径，v1.0 保持现状
2. 所有 `pub const *_LEN` 和 `pub const *_HEADER_LEN` 保持 Stable
3. `BuildError` 变体 `InvalidField` 和 `PayloadTooLarge` 保持 Stable

### 2.2 wireforge-packet

| Item | Type | Stability |
|------|------|-----------|
| `Packet<'a>` | enum | Stable |
| `parse_ethernet_frame()` | fn | Stable |
| `parse_ipv4_payload()` | fn | Stable |
| `parse_ipv6_payload()` | fn | Stable |
| `From<EthernetPacket> for Packet` | impl | Stable |

### 2.3 wireforge-io

| Item | Type | Stability |
|------|------|-----------|
| `traits::L2Reader` | trait | Stable |
| `traits::L2Writer` | trait | Stable |
| `traits::L3Reader` | trait | Stable |
| `traits::L3Writer` | trait | Stable |
| `IoError` | enum | Stable |
| `Interface` | struct | Stable |
| `list_interfaces()` | fn | Stable |
| `DefaultL2Reader` | type alias | Stable |
| `DefaultL2Writer` | type alias | Stable |
| `DefaultL3Reader` | type alias | Stable |
| `DefaultL3Writer` | type alias | Stable |
| `linux::L2Receiver/Sender` | struct | Stable |
| `linux::L3Receiver/Sender` | struct | Stable |
| `macos::BpfReader/BpfWriter` | struct | Unstable (待 macOS 验证) |
| `macos::BsdL3Receiver/Sender` | struct | Unstable |
| `windows::NpcapReader/Writer` | struct | Stable |
| `windows::WinL3Receiver/Sender` | struct | Stable |

### 2.4 wireforge-app

| Item | Type | Stability |
|------|------|-----------|
| `dns::parser::DnsPacket` | struct | Stable |
| `dns::parser::DnsRecord` | enum | Stable |
| `dns::builder::DnsPacketBuilder` | struct | Stable |
| `dns::types::*` | enums | Stable |
| `dhcp::parser::DhcpPacket` | struct | Stable |
| `dhcp::types::DhcpOption` | enum | Stable |
| `dhcp::builder::DhcpPacketBuilder` | struct | Stable |
| `ntp::parser::NtpPacket` | struct | Stable |
| `ntp::types::*` | enums | Stable |
| `http::HttpRequest` | struct | Stable |
| `http::HttpResponse` | struct | Stable |
| `http::Header` | struct | Stable |
| `pcap::PcapReader` | struct | Stable |
| `pcap::PcapWriter` | struct | Stable |
| `pcap::PcapNgReader` | struct | Stable |
| `pcap::PcapNgWriter` | struct | Stable |
| `pcap::LinkType` | enum | Stable |

---

## 3. Security Audit Template (US-003)

### 3.1 Unsafe Code Inventory

| File | Lines | Purpose | Risk | Verified |
|------|-------|---------|------|----------|
| `linux/l2.rs` | L64-70, L88-96 | `libc::ioctl` + `setsockopt` | Low — standard socket ops | ⬜ |
| `linux/l3.rs` | L49-62 | `setsockopt` | Low — standard socket ops | ⬜ |
| `windows/npcap.rs` | L80 | `LoadLibraryA` + `GetProcAddress` | Medium — dynamic FFI | ⬜ |
| `windows/npcap.rs` | L134, L148 | `pcap_open_live`, `pcap_next_ex` → pointer deref | Medium — C pointer handling | ⬜ |
| `windows/l3.rs` | L53-65, L76-88 | `setsockopt` FFI | Low — standard socket ops | ⬜ |
| `macos/bpf.rs` | (stub) | `/dev/bpf` ioctl | ⬜ | ⬜ |
| `wireforge-core` | 0 | No unsafe code | None | ✅ |

**审计标准:**
- 每个 `unsafe` 块前必须有 `// SAFETY:` 注释，说明为何安全
- 所有 FFI 函数签名必须与 C 头文件一致
- 所有裸指针解引用必须有 null check 或长度验证

### 3.2 Dependency Audit

```bash
cargo audit          # 检查已知漏洞 (RUSTSEC advisories)
cargo deny check     # 检查许可证兼容性
```

### 3.3 Fuzz Coverage

| Protocol | Fuzz Target | Status |
|----------|-------------|--------|
| ether | ✅ | wireforge-core/fuzz |
| vlan | ✅ | wireforge-core/fuzz |
| arp | ✅ | wireforge-core/fuzz |
| ipv4 | ✅ | wireforge-core/fuzz |
| ipv6 | ✅ | wireforge-core/fuzz |
| tcp | ✅ | wireforge-core/fuzz |
| udp | ✅ | wireforge-core/fuzz |
| icmp | ✅ | wireforge-core/fuzz |
| icmpv6 | ✅ | wireforge-core/fuzz |
| dns | ✅ | wireforge-app/fuzz |
| dhcp | ✅ | wireforge-app/fuzz |
| ntp | ✅ | wireforge-app/fuzz |
| http | ✅ | wireforge-app/fuzz |

---

## 4. CHANGELOG Structure (US-004)

### 4.1 Format

遵循 [Keep a Changelog](https://keepachangelog.com/) 格式:

```markdown
# Changelog

## [1.0.0] — 2026-06-13

### Added (wireforge-core)
- IGMPv1/v2/v3 parser and builder
- GRE (RFC 2784 + RFC 2890) parser and builder with Key/Seq/Checksum

### Added (wireforge-app)
- DNS message parser and builder with QNAME compression
- DHCPv4 parser and builder with Option Overload
- NTPv4 packet parser
- HTTP/1.1 request/response line parser
- pcap reader/writer (pcap + pcapng)

### Added (wireforge-io)
- Cross-platform L2Reader/L2Writer/L3Reader/L3Writer traits
- Windows NPcap L2 capture via dynamic FFI
- Windows raw socket L3
- Linux AF_PACKET L2 + raw socket L3
- macOS BPF L2 + raw socket L3 (stubs)
- list_interfaces() — Linux, macOS, Windows
- IoError with platform-specific variants

### Added (wireforge-packet)
- Packet enum with From impls for all protocols
- parse_ethernet_frame(), parse_ipv4_payload(), parse_ipv6_payload()

### Added (infra)
- 13 protocol fuzz targets
- Criterion benchmarks (parse, build, checksum)
- Cross-platform examples (dump, send, list_interfaces)
- CI matrix (ubuntu, macos, windows)
- libpnet → WireForge migration guide

### Changed
- IoError: added InterfaceNotFound, PermissionDenied, Bpf, Npcap, UnsupportedPlatform variants
- Output: from concrete structs to trait-based L2Reader/L2Writer/L3Reader/L3Writer

### Fixed
- Various clippy fixes across all crates
```

### 4.2 Pre-v1.0 Changelog

从 commit `a9ae730` (bootstrap) 到 v1.0.0-rc1 的所有变更按版本分组列出。

---

## 5. Contributing Guide Structure (US-005)

### 5.1 CONTRIBUTING.md

```markdown
# Contributing to WireForge

## Development Setup
git clone ... && cd wireforge && cargo build --workspace

## Code Style
- cargo fmt (standard Rust formatting)
- cargo clippy --workspace -- -D warnings (must pass)
- All pub items must have rustdoc
- unsafe blocks must have // SAFETY: comments

## Testing
- cargo test --workspace (unit + doc tests)
- sudo cargo test --workspace -- --ignored (integration, requires root)
- cargo +nightly fuzz run <target> (fuzz testing)

## Pull Request Process
1. Create a branch: feat/issue-N-short-desc or fix/issue-N-short-desc
2. Write tests
3. Run cargo fmt + cargo clippy
4. Update CHANGELOG.md if applicable
5. Open PR against main

## Commit Style
- feat: new feature
- fix: bug fix
- docs: documentation
- chore: maintenance
```

### 5.2 GitHub Templates

`.github/ISSUE_TEMPLATE/bug_report.md`:
```markdown
---
name: Bug Report
about: Report a bug in WireForge
---

**Crate**: wireforge-core / packet / io / app
**Version**: 
**Platform**: Linux / macOS / Windows
**Description**:
**Reproduction**:
\```rust
// minimal code to reproduce
\```
**Expected**:
**Actual**:
```

`.github/PULL_REQUEST_TEMPLATE.md`:
```markdown
## Summary
## Test Plan
## Checklist
- [ ] cargo fmt
- [ ] cargo clippy --workspace
- [ ] cargo test --workspace
- [ ] CHANGELOG updated (if applicable)
```

---

## 6. crates.io Publication Steps (US-008)

### 6.1 Pre-publish Checklist

| Step | Command | Expected |
|------|---------|----------|
| 1. Verify metadata | `cargo metadata --no-deps` | No warnings |
| 2. Dry-run package | `cargo package -p wireforge-core --dry-run` | Success |
| 3. Dry-run all | `for p in core packet io app; do cargo package -p wireforge-$p; done` | All success |
| 4. Verify doc | `cargo doc --no-deps --workspace` | Zero warnings |
| 5. Verify test | `cargo test --workspace` | All pass |
| 6. Verify clippy | `cargo clippy --workspace -- -D warnings` | All pass |

### 6.2 Publish Order

```
1. cargo publish -p wireforge-core     (zero deps)
2. cargo publish -p wireforge-packet   (depends on core)
3. cargo publish -p wireforge-io       (depends on core + packet)
4. cargo publish -p wireforge-app      (depends on packet)
```

### 6.3 Post-publish Verification

```bash
cargo add wireforge-core wireforge-packet wireforge-io wireforge-app
cargo build
```

---

## 7. Cargo.toml v1.0 Changes (US-002)

### 7.1 Workspace Root

```toml
[workspace.package]
version = "1.0.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/wireforge/wireforge"
documentation = "https://docs.rs/wireforge-core"
rust-version = "1.75"
```

### 7.2 Per-crate metadata additions

```toml
# Each crate adds:
keywords = ["networking", "packet", "parsing", "pcap"]
categories = ["network-programming", "parsing"]
```

---

## 8. Testing Strategy

### 8.1 Unit Tests (existing)

- 84 wireforge-core tests ✅
- 24 wireforge-app tests ✅
- 5 wireforge-io tests ✅
- 1 wireforge-packet test ✅
- Total: **114 tests**

### 8.2 Release Validation Tests

| Test | Command | Platform |
|------|---------|----------|
| Package integrity | `cargo package -p wireforge-core` | All |
| Fresh install | `cargo add wireforge-core` in empty project | All |
| Doc generation | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` | All |
| MSRV check | `cargo +1.75 build --workspace` | All |
| Fuzz compile | `cargo +nightly fuzz check` (all targets) | Linux |

---

## 9. Implementation Plan

### 9.1 Issue Mapping

| Issue | SPEC Sections | Priority | Depends On |
|-------|--------------|----------|------------|
| #48 | 2.1–2.4 API audit + stability | high | — |
| #49 | 3.1–3.3 Security audit | high | — |
| #50 | 7.1–7.2 Cargo.toml v1.0 + metadata | high | — |
| #51 | 4.1–4.2 CHANGELOG | medium | — |
| #52 | 5.1–5.2 Contributing guide + templates | medium | — |
| #53 | 6.1–6.3 crates.io publish | high | #48, #49, #50 |
| #54 | macOS BPF + L3 (external SPEC) | high | — |
| #55 | Benchmark baseline | medium | — |
| #56 | Final README + docs polish | medium | all |
