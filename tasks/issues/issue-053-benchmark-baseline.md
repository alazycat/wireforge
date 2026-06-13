# 性能基线 (Benchmark Baseline)

## Description

运行所有 criterion benchmarks 并记录 v1.0 性能基线数据。可选与 libpnet 对比。在文档中展示关键指标。

## Acceptance Criteria

- [ ] `cargo bench -p wireforge-core` 运行 parse_bench, build_bench, checksum_bench
- [ ] `cargo bench -p wireforge-app` 运行 dns_parse_bench, pcap_read_bench
- [ ] 记录各协议解析吞吐量 (Mpps) 和构造速度
- [ ] 可选: 与 libpnet 的性能对比（在相同环境下运行 libpnet benchmarks）
- [ ] 在 README 或 `docs/benchmarks-v1.md` 中展示 key metrics
- [ ] 确保 benchmarks 可重复运行

## Dependencies

None

## Type

infra

## Priority

medium

## SPEC Reference

PRD US-006 — 性能基线
