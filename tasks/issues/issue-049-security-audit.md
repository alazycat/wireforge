# 安全审计 (unsafe + dependencies)

## Description

审计所有 `unsafe` 代码块，确保每个都有 `// SAFETY:` 注释说明安全性理由。运行 `cargo audit` 和 `cargo deny check` 检查依赖树中的已知漏洞和许可证问题。输出 `docs/security-audit-v1.md`。

## Acceptance Criteria

- [ ] 审计 6 处 unsafe 代码:
  - `wireforge-io/src/linux/l2.rs`: ioctl + setsockopt
  - `wireforge-io/src/linux/l3.rs`: setsockopt
  - `wireforge-io/src/windows/npcap.rs`: LoadLibraryA + GetProcAddress + pcap_* calls
  - `wireforge-io/src/windows/l3.rs`: setsockopt FFI (2处)
  - `wireforge-io/src/macos/bpf.rs`: (空壳，标注待实现)
- [ ] 每个 unsafe 块前添加 `// SAFETY:` 注释
- [ ] `cargo audit` — 检查已知漏洞 (RUSTSEC advisories)
- [ ] `cargo deny check` — 检查许可证兼容性
- [ ] 验证 `wireforge-core` 无 unsafe 代码
- [ ] 生成 `docs/security-audit-v1.md` 记录审计结果
- [ ] 确认 13 个 fuzz target 均已覆盖各协议解析器

## Dependencies

None

## Type

security

## Priority

high

## SPEC Reference

Section 3 — Security Audit Template; Section 3.1 Unsafe Code Inventory; Section 3.2 Dependency Audit
