# WireForge v1.0 Security Audit

**Date:** 2026-06-13
**Scope:** All 4 crates (core, packet, io, app)
**Auditor:** Automated + manual review

## Unsafe Code Inventory

### wireforge-core
- **0 unsafe blocks** — no_std + alloc only, all memory access bounds-checked.

### wireforge-io/src/linux/l2.rs
- **set_promiscuous()** (L58-62): `ioctl(fd, SIOCSIFFLAGS, &ifreq)` — SAFETY: ifreq is zeroed, name copied with bounds check; flags set to valid IFF_PROMISC. Standard POSIX socket operation.
- **set_timeout()** (L81-99): `setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))` — SAFETY: timeval struct properly initialized; sizeof matches. Standard POSIX operation.

### wireforge-io/src/linux/l3.rs
- **set_header_included()**: `setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val))` — SAFETY: val is c_int 0 or 1; sizeof matches. Standard POSIX operation.
- **set_timeout()**: Same as l2.rs. Standard POSIX operation.

### wireforge-io/src/windows/npcap.rs
- **LoadLibraryA + GetProcAddress**: Dynamic DLL loading — SAFETY: DLL name is a valid CString. GetProcAddress uses known function names from wpcap.dll API. Function signatures verified against Npcap SDK 1.76 headers.
- **pcap_open_live**: Returns null on error, errbuf is 256 bytes (≥ PCAP_ERRBUF_SIZE). CString interface name is valid UTF-8.
- **pcap_next_ex**: Returns pointer to internal pcap buffer. caplen bounds-checked before creating slice. Packet data is valid for the duration of the next call.
- **pcap_close**: Called in Drop impl. Handle checked for null before closing.

### wireforge-io/src/windows/l3.rs
- **setsockopt FFI**: Windows WinSock setsockopt — SAFETY: function pointer declared with correct calling convention (system). Parameters match Windows SDK. Timeout uses DWORD (u32) as required by Windows SO_RCVTIMEO.

## Fuzz Coverage

All 13 protocol parsers have cargo-fuzz targets:
- ✅ ether, vlan, arp, ipv4, ipv6, tcp, udp, icmp, icmpv6 (wireforge-core/fuzz)
- ✅ dns, dhcp, ntp, http (wireforge-app/fuzz)

## Dependency Audit

No known vulnerabilities in dependencies (verified via `cargo audit`).

Direct dependencies:
- wireforge-core: 0 (no_std) ✅
- wireforge-packet: 1 (wireforge-core) ✅
- wireforge-io: socket2, libc (Linux/macOS) ✅
- wireforge-app: wireforge-packet ✅

## Risk Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 0 | — |
| Info | — | All unsafe blocks are standard OS API calls with proper bounds checking |

## Recommendations

- Consider adding `cargo audit` to CI pipeline
- Run fuzz targets for extended durations before each release (> 30 min each)
- Review NPcap FFI function signatures against latest Npcap SDK before each major release
