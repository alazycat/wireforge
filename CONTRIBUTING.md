# Contributing to WireForge

## Development Setup

```bash
git clone https://github.com/wireforge/wireforge
cd wireforge
cargo build --workspace
cargo test --workspace
```

## Code Style

- `cargo fmt` — standard Rust formatting
- `cargo clippy --workspace -- -D warnings` — must pass with zero warnings
- All `pub` items must have rustdoc comments
- `unsafe` blocks must have `// SAFETY:` comments explaining why they are safe
- New protocol modules follow existing patterns: zero-copy `Packet::new(&[u8]) -> Option<Self>`, `Builder::build() -> Vec<u8>`

## Testing

```bash
cargo test --workspace          # unit + doc tests
cargo test --workspace -- --ignored  # integration tests (requires root on Linux/macOS)
cargo +nightly fuzz run <target>     # fuzz testing
```

## Commit Style

- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation
- `chore:` — maintenance, CI, benchmarks

No AI attribution in commits.

## Pull Request Process

1. Create a feature branch: `feat/issue-N-` or `fix/issue-N-`
2. Write tests for new functionality
3. Run `cargo fmt && cargo clippy --workspace`
4. Run `cargo test --workspace`
5. Update CHANGELOG.md if applicable
6. Open PR against `main`

## Adding a New Protocol

1. Create `wireforge-core/src/<protocol>.rs`
2. Implement `Packet::new(&[u8]) -> Option<Self>` (zero-copy parser)
3. Implement `Builder` with `build() -> Vec<u8>`
4. Add `#[cfg(test)] mod tests` with known sample data
5. Add `pub mod <protocol>;` to `lib.rs`
6. Add fuzz target in `wireforge-core/fuzz/fuzz_targets/`
7. Update docs and CHANGELOG
