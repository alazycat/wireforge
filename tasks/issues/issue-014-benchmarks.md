# Criterion 基准测试

## Description

为每个协议解析器和构造器添加 `criterion` 基准测试。覆盖解析速度、构造速度、校验和计算。记录与 libpnet 的性能对比数据。

## Acceptance Criteria

- [ ] `wireforge-core/Cargo.toml` 添加 `criterion` dev-dependency + `[[bench]]` 配置
- [ ] Bench target: `parse_bench` — 各协议解析吞吐量
- [ ] Bench target: `build_bench` — 各协议构造吞吐量
- [ ] Bench target: `checksum_bench` — IP/TCP/UDP 校验和计算
- [ ] `cargo bench` 可正常运行
- [ ] 基准测试数据记录在文档中（可选 v2 中自动化对比 libpnet）

## Dependencies

Issue #3~#9 (各协议 parser/builder 就绪)

## Type

infra

## Priority

low

## SPEC Reference

Section 9.5 — Benchmarks; PRD US-012
