# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in WireForge, please report it privately via email to the maintainers. Do **not** open a public GitHub Issue.

We aim to respond within 48 hours and publish a fix within 7 days of confirmation.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active |
| < 1.0   | ❌ Pre-release, no security guarantees |

## Scope

WireForge is a protocol parsing library. Security-critical areas include:

- **Unsafe code**: FFI calls to OS APIs (socket ioctl, NPcap DLL). All unsafe blocks are documented with `// SAFETY:` comments in the source.
- **Packet parsing**: All parsers use bounds-checked slice access. No `unsafe` in `wireforge-core`.
- **Fuzz testing**: 13 protocol fuzz targets run via `cargo-fuzz`. Contributions must not introduce new panics on arbitrary input.

## What is NOT in scope

- Network-level DoS protection (WireForge operates on provided buffers, not live traffic)
- Cryptography (no TLS/encryption support)
- Authentication/authorization (library-level, not application-level)
