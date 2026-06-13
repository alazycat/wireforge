# CI 矩阵配置 + 模块文档

## Description

配置三平台 CI 矩阵（ubuntu-latest, macos-latest, windows-latest），确保每次提交在三平台上均通过编译和测试。为所有新增模块添加 rustdoc 注释和模块级文档。

## Acceptance Criteria

- [ ] CI 配置文件（`.github/workflows/ci.yml` 或等效）包含三平台矩阵
- [ ] 每个平台的 CI job: `cargo build --workspace` + `cargo test --workspace` + `cargo clippy --workspace`
- [ ] Windows CI 安装 NPcap SDK（通过 chocolatey 或手动下载）
- [ ] 集成测试在 CI 中使用 `#[ignore]` 标记（需要权限），仅编译不运行
- [ ] `traits.rs` 有模块级 docstring 和使用示例
- [ ] `interface.rs` 有模块级 docstring
- [ ] `common/mod.rs` 有模块级 docstring
- [ ] `wireforge-io/src/lib.rs` 更新 crate-level docstring（说明三平台支持）
- [ ] Linux 测试在 CI 中以 root 运行（`sudo cargo test`）
- [ ] `cargo doc --no-deps` 无警告
- [ ] `cargo clippy` 无警告

## Dependencies

All previous issues (#27–#35)

## Type

infra

## Priority

low

## SPEC Reference

Section 5 — Testing Strategy; Section 2.5 — Feature Flags
