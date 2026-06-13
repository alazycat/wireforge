# HTTP/1.1 请求 + 响应行解析

## Description

实现 HTTP/1.1 请求行和响应行的纯文本解析器。解析 method + URI + version + headers，body 作为原始 `&[u8]` 透传。不处理 chunked transfer-encoding、body 长度感知、或 obsolete line folding。

## Acceptance Criteria

- [ ] `http/headers.rs`: `Header<'a>` struct (name: &str, value: &[u8])
- [ ] `http/headers.rs`: `HeaderIter<'a>` — 解析 `Name: Value\r\n` 对，遇到空行停止
- [ ] `HttpRequest::parse(&[u8]) -> Option<Self>` — 解析 `METHOD SP URI SP VERSION\r\n`
- [ ] `HttpRequest` 字段: `method() -> &str`, `uri() -> &str`, `version() -> &str`, `headers() -> HeaderIter`, `body() -> &[u8]`
- [ ] `HttpResponse::parse(&[u8]) -> Option<Self>` — 解析 `VERSION SP STATUS SP REASON\r\n`
- [ ] `HttpResponse` 字段: `version() -> &str`, `status_code() -> u16`, `reason() -> &str`, `headers() -> HeaderIter`, `body() -> &[u8]`
- [ ] 行终止符严格 `\r\n`，不做 obsolete line folding
- [ ] 单元测试: GET 请求、POST 请求（含多个 headers）、200 响应、404 响应
- [ ] `cargo test` 全部通过
- [ ] `cargo clippy` 无警告

## Dependencies

Issue #16 (crate 就绪)

## Type

backend

## Priority

medium

## SPEC Reference

Section 3.11 — HTTP Types
