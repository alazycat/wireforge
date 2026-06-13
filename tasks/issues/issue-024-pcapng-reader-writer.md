# pcapng Reader + Writer

## Description

实现 pcapng 文件格式的读写。支持三种核心 Block: Section Header Block (SHB)、Interface Description Block (IDB)、Enhanced Packet Block (EPB)。Reader 实现 Iterator 产出 `PcapNgBlock` 枚举。Writer 支持创建 SHB + IDB + 写入 EPB。

## Acceptance Criteria

- [ ] `pcap/types.rs` 扩展: `PcapNgBlock` 枚举 (SectionHeader, InterfaceDescription, EnhancedPacket, Unknown)
- [ ] `PcapNgReader<R: Read>::new(reader) -> Result<Self, IoError>` — 解析 SHB 确定字节序
- [ ] `PcapNgReader::link_type() -> Option<LinkType>` — 从第一个 IDB 获取
- [ ] `impl<R: Read> Iterator for PcapNgReader<R>` — Item = `Result<PcapNgBlock, IoError>`
- [ ] 跳过未知 Block 类型（不报错，继续解析）
- [ ] `PcapNgWriter<W: Write>::new(writer, link_type) -> Result<Self, IoError>` — 自动写入 SHB + IDB
- [ ] `PcapNgWriter::write_epb(&mut self, ts: Duration, packet: &[u8]) -> Result<(), IoError>`
- [ ] 单元测试: SHB+IDB+EPB 写入→回读往返、未知 block 跳过测试
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #23 (pcap types + reader/writer)

## Type

backend

## Priority

medium

## SPEC Reference

Section 3.15 — pcapng 设计; Section 3.16 — pcapng Block Iterator
