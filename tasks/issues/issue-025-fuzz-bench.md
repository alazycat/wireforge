# Fuzz targets + 基准测试

## Description

为新增的应用层协议解析器添加 `cargo fuzz` target 和 `criterion` 基准测试。Fuzz 覆盖 DNS、DHCP、NTP、HTTP 共 4 个模块。Bench 覆盖 DNS 解析和 pcap 读取。

## Acceptance Criteria

- [ ] `wireforge-app/fuzz/Cargo.toml` — cargo-fuzz 配置
- [ ] 4 个 fuzz target: `dns`, `dhcp`, `ntp`, `http`
- [ ] 每个 target: `fuzz_target!(|data: &[u8]| { let _ = XxxPacket::new(data); ... })` + 调用所有访问器
- [ ] `cargo +nightly fuzz check` 每个 target 可编译
- [ ] `wireforge-app/Cargo.toml` 添加 `criterion` dev-dependency + `[[bench]]` 配置
- [ ] Bench: `dns_parse_bench` — DNS 响应解析吞吐量
- [ ] Bench: `pcap_read_bench` — 含数据包文件的读取吞吐量
- [ ] `cargo bench` 可正常运行
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #18 (dns), #21 (ntp), #22 (http), #23 (pcap)

## Type

infra

## Priority

low

## SPEC Reference

Section 6.3 — Fuzz Tests; Section 6.4 — Benchmarks
