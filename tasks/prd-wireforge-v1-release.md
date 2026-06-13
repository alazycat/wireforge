# PRD: WireForge v1.0 正式发布

## Introduction

WireForge 已完成 47 个 Issues 的开发，覆盖 libpnet 100% 协议、4 个应用层协议、pcap I/O、三平台 trait 架构（Windows 完整、Linux 完整、macOS 待补齐）。当前状态距 crates.io v1.0 发布只差最后冲刺：架构审查、API 稳定性锁定、性能基线、安全审计、发布流程。

本 PRD 定义 WireForge v1.0 正式发布的完整标准。

## Goals

- 完成架构审查，基于 47 个 Issue 的经验教训决定是否调整 API
- 锁定 v1.0 公开 API 稳定性边界
- 建立性能基线（benchmark numbers）
- 完成安全审计（unsafe 代码审查、依赖审计）
- 发布到 crates.io（4 crates）
- 编写 CONTRIBUTING.md、CODE_OF_CONDUCT.md
- 生成完整 CHANGELOG
- macOS BPF L2 + L3 补齐（当前唯一功能缺口）

## User Stories

### US-001: 架构审查与 API 稳定性锁定
**Description:** 作为库维护者，我需要审查所有 `pub` API，决定哪些是 v1.0 stable、哪些标记为 `#[doc(hidden)]` 或 experimental feature gate。

**Acceptance Criteria:**
- [ ] 审计 4 个 crate 的所有 `pub` 导出（types + functions + traits + structs + methods）
- [ ] 生成 API 清单文档 `docs/api-audit-v1.md`，每个 pub item 标记状态: Stable / Unstable / Deprecated
- [ ] 标记为 Unstable 的 API 添加 `#[doc(hidden)]` 或 feature gate
- [ ] 决定是否需要 breaking change（基于 47 个 Issue 的实践经验）
- [ ] 如有 breaking change，编写迁移指南
- [ ] `cargo doc --no-deps --workspace` 零警告

### US-002: Crate 元数据与版本号
**Description:** 作为库维护者，我需要更新所有 crate 的 Cargo.toml 元数据和版本号。

**Acceptance Criteria:**
- [ ] workspace version → `1.0.0`
- [ ] 每个 crate 的 `description`、`keywords`、`categories` 完善
- [ ] `documentation`、`homepage`、`repository` 字段设置正确
- [ ] `license` 字段确认 MIT
- [ ] `readme` 字段指向 README.md
- [ ] `rust-version` 字段设置 MSRV（Minimum Supported Rust Version）
- [ ] 所有 crate `cargo package --dry-run` 成功

### US-003: 安全审计
**Description:** 作为库维护者，我需要审查所有 unsafe 代码、验证依赖安全性、确保无已知漏洞。

**Acceptance Criteria:**
- [ ] 审计所有 `unsafe {}` 块（标注原因、验证安全性）
- [ ] 审计所有 `extern "system"` FFI 声明（参数类型正确性、内存安全性）
- [ ] `cargo audit` 检查依赖树无已知漏洞
- [ ] `cargo deny check` 检查依赖许可证兼容性
- [ ] 审计结果记录在 `docs/security-audit-v1.md`
- [ ] 无 `unsafe` 代码在 `wireforge-core`（保持 no_std 安全性）
- [ ] `wireforge-io` 中的 unsafe（socket/FFI）已验证安全性

### US-004: CHANGELOG 与发布说明
**Description:** 作为库维护者，我需要一份从项目起点到 v1.0 的完整变更日志。

**Acceptance Criteria:**
- [ ] `CHANGELOG.md` 按 crate 分组（core, packet, io, app）
- [ ] 按版本列出所有新增协议/功能
- [ ] 标注 breaking changes（IoError 扩展、trait 体系引入等）
- [ ] 包含 v1.0 发布亮点摘要
- [ ] 链接到 migration guide

### US-005: 贡献指南与社区基础设施
**Description:** 作为库维护者，我需要为外部贡献者准备入门文档。

**Acceptance Criteria:**
- [ ] `CONTRIBUTING.md`: 开发环境搭建、编码规范、测试要求、PR 流程
- [ ] `CODE_OF_CONDUCT.md` (Rust 社区标准)
- [ ] `SECURITY.md` (安全漏洞报告流程)
- [ ] GitHub Issue templates (bug report, feature request)
- [ ] GitHub PR template
- [ ] README 添加 community 相关 section

### US-006: 性能基线
**Description:** 作为库维护者，我需要在 v1.0 建立正式的性能基线数据。

**Acceptance Criteria:**
- [ ] 运行所有 criterion benchmarks 并记录结果
- [ ] 基准: 各协议解析吞吐量 (Mpps)、构造吞吐量、校验和计算速度
- [ ] 在 README 或独立文档中展示 key metrics
- [ ] 与 libpnet 的性能对比数据（如有）
- [ ] `cargo bench` 全部可运行

### US-007: macOS BPF + L3 补齐
**Description:** 作为库维护者，macOS 是唯一缺失的平台实现，必须在 v1.0 前补齐。

**Acceptance Criteria:**
- [ ] `macos/bpf.rs`: BpfReader 完整实现（/dev/bpf ioctl）
- [ ] `macos/l3.rs`: BsdL3Receiver/BsdL3Sender 完整实现
- [ ] lo0 集成测试通过
- [ ] macOS CI job 全部绿色

### US-008: crates.io 发布
**Description:** 作为库维护者，我需要将 4 个 crate 发布到 crates.io。

**Acceptance Criteria:**
- [ ] `cargo publish --dry-run` 全部通过
- [ ] 发布顺序: core → packet → io, app
- [ ] 验证 `cargo add wireforge-core` 可正常安装
- [ ] 验证 `cargo add wireforge-app` 可正常安装（含所有传递依赖）
- [ ] crates.io 页面渲染正常（readme、doc links）

## Functional Requirements

- FR-1: v1.0 后所有 `pub` API 遵循 semver（major.minor.patch）
- FR-2: 4 个 crate 同时升级到 1.0.0
- FR-3: `wireforge-core` 必须保持 `no_std` + `alloc`
- FR-4: 所有 unsafe 代码必须有 `// SAFETY:` 注释说明
- FR-5: 所有 crate 的 `cargo doc` 零警告
- FR-6: 所有 crate 的 `cargo clippy` 零警告
- FR-7: 所有 crate 的 `cargo test` 全部通过
- FR-8: CHANGELOG 覆盖从 commit a9ae730 (bootstrap) 到 v1.0.0
- FR-9: macOS CI 绿色

## Non-Goals

- ❌ 不做 libpnet 之外的协议添加（v1.0 范围已锁定）
- ❌ 不做 async/await I/O 支持（tokio 集成是 v2 特性）
- ❌ 不做 Android/iOS 移动端支持
- ❌ 不做 DPDK/netmap 高性能框架集成
- ❌ 不做 Wireshark dissector 导出
- ❌ 不做 macOS NetworkExtension API（需特殊 entitlement）

## Technical Considerations

- **Semver 承诺**: v1.0 后 breaking change 必须伴随 major version bump
- **MSRV**: 建议设为 Rust 1.75（2024年初稳定版，覆盖绝大多数用户）
- **Unsafe 审计重点**: `wireforge-io/src/linux/l2.rs` (socket ioctl)、`windows/npcap.rs` (FFI)、`windows/l3.rs` (setsockopt)
- **依赖最小化**: `wireforge-core` 目前零外部依赖，v1.0 必须保持
- **crates.io 发布顺序**: core → packet → io, app (io 和 app 无相互依赖，可并行发布)

## Success Metrics

- crates.io 4 个 crate 全部可 `cargo add` 安装
- `cargo doc` 文档完整覆盖所有 pub API
- CI 三平台全部绿色
- 安全审计零高危发现
- CHANGELOG 完整记录所有变更
- macOS lo0 集成测试通过

## Open Questions

- MSRV 设为多少？Rust 1.70 (2023-06) vs 1.75 (2023-12) vs 1.80 (2024-07)
- 是否需要 RFC 流程？小团队可跳过，大改动在 Issue 中讨论即可
- `wireforge-io` 的 `DefaultL2Reader` 等类型别名是否需要 feature gate？当前是自动平台选择，无需 feature
- macOS BPF 实现是否需要支持 Apple Silicon 特定的 64-bit bpf_hdr 对齐？docs 说明 + 运行时检测
