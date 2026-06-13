# Windows NPcap L2 FFI 实现

## Description

实现 Windows 平台上基于 NPcap 的 L2 帧捕获，使用 `LoadLibrary` / `GetProcAddress` 动态加载 `wpcap.dll`。绑定 6 个核心函数：`pcap_findalldevs`、`pcap_freealldevs`、`pcap_open_live`、`pcap_next_ex`、`pcap_close`、`pcap_set_timeout`。L2 发送标记为 `UnsupportedPlatform`。

## Acceptance Criteria

- [ ] FFI: `LoadLibraryA("wpcap.dll")` 动态加载 DLL，`GetProcAddress` 获取 6 个函数指针
- [ ] `pcap_open_live(device, snaplen=65535, promisc=0, to_ms=1000, errbuf)` 打开适配器
- [ ] `NpcapReader::new(ifname)` — 将接口名转为 CString，调用 pcap_open_live
- [ ] `recv()` — `pcap_next_ex` 返回 1 → 读取 pcap_pkthdr + 数据 → EthernetPacket
- [ ] pcap_next_ex 返回 0 → timeout
- [ ] pcap_next_ex 返回 -1 → 错误
- [ ] `set_timeout()` — `pcap_set_timeout` 设置超时 (毫秒)
- [ ] `set_promiscuous()` — 关闭当前 handle 后用 promisc=1 重新打开
- [ ] `impl Drop for NpcapReader` — `pcap_close(handle)`
- [ ] `NpcapWriter::send()` 返回 `IoError::UnsupportedPlatform`
- [ ] wpcap.dll 不存在时返回 `IoError::Npcap("wpcap.dll not found...")`，不 panic
- [ ] DLL 函数指针使用 `OnceLock` 或类似机制缓存（避免每次 new 都 LoadLibrary）
- [ ] 实现 `L2Reader` + `L2Writer` trait
- [ ] 单元测试: DLL 不存在时不 panic
- [ ] 集成测试: NPcap loopback 捕获（如 NPcap 已安装）(标记 `#[ignore]`)
- [ ] `cargo build` (Windows) 成功
- [ ] `cargo test` (Windows) 全部通过

## Dependencies

None (纯 FFI，不依赖外部 Rust crate)

## Type

backend

## Priority

high

## SPEC Reference

Section 5 — Windows NPcap L2 Implementation; Section 5.1 FFI bindings; Section 5.2 C type mappings
