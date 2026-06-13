# pcap 类型 + Reader + Writer

## Description

实现 pcap 文件格式（.pcap）的读写。Reader 封装 `std::io::Read` 并实现 `Iterator`，逐个产出 `(timestamp, packet_data)` 对。Writer 封装 `std::io::Write`，支持写入 global header + 数据包记录。

## Acceptance Criteria

- [ ] `pcap/types.rs`: `PcapHeader`（24 bytes, `#[repr(C)]`）, `PcapRecordHeader`（16 bytes）, `Endianness` 枚举, `LinkType` 枚举（Ethernet=1, Raw=101, Unknown）
- [ ] `PcapReader<R: Read>::new(reader) -> Result<Self, IoError>` — 读取并验证 global header（magic 0xa1b2c3d4 或 0xd4c3b2a1）
- [ ] `PcapReader::header() -> &PcapHeader`
- [ ] `PcapReader::link_type() -> LinkType`
- [ ] `impl<R: Read> Iterator for PcapReader<R>` — Item = `Result<(Duration, Vec<u8>), IoError>`
- [ ] `PcapWriter<W: Write>::new(writer, link_type) -> Result<Self, IoError>` — 写入 global header
- [ ] `PcapWriter::write(&mut self, ts: Duration, packet: &[u8]) -> Result<(), IoError>` — 写入 record header + data，立即 flush
- [ ] 支持大小端自动检测（根据 magic number）
- [ ] 单元测试: 写入→回读 5 个数据包 roundtrip、读 0 包文件、无效 magic 错误处理
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #16 (crate 就绪)

## Type

backend

## Priority

high

## SPEC Reference

Section 3.12 — pcap Types; Section 3.13 — pcap Reader API; Section 3.14 — pcap Writer API
