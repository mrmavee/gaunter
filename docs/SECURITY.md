# Security & Fuzzing

## Dependency Advisories
Specific advisories are ignored in `deny.toml` as the vulnerable code paths are unreachable in Gaunter:

| ID | Crate | Reason |
|----|-------|--------|
| **RUSTSEC-2024-0437** | `protobuf` | DoS via stack overflow in `skip_group`. Unreachable as Gaunter does not expose metrics endpoints and the L4 proxy only handles HTTP/1.x, never parsing Protobuf messages. |
| **RUSTSEC-2025-0069** | `daemonize` | Informational (unmaintained). Gaunter runs Pingora in the foreground via `Server::run_forever()` in `src/main.rs`; daemonization is never initialized. |
| **RUSTSEC-2024-0388** | `derivative` | Informational (unmaintained). Procedural macro used by `pingora-core` at compile-time only; no runtime footprint. |
| **RUSTSEC-2024-0436** | `paste` | Informational (unmaintained). Procedural macro used by `imageproc` at compile-time only; no runtime footprint. |

## Fuzzing Status
Core logic is continuously stressed using `cargo-fuzz` (libFuzzer) to ensure memory safety and zero panics.

- **Corpus**: 9567 seeds (38M, minimized)
- **Crashes Found**: 0
- **Last Updated**: 2026-04-02

### Statistics
| Target | Coverage | Features | Corpus |
|--------|----------|----------|--------|
| `form_captcha` | 1123 | 3485 | 544/112Kb |
| `proxy_protocol` | 355 | 541 | 136/6351b |
| `session_security` | 1226 | 3655 | 298/37Kb |
| `waf_engine` | 7298 | 42407 | 7071/1275Kb |
| `detect_mime` | 81 | 120 | 51/1748b |
| `waf_rule_engine` | 1465 | 7133 | 718/131Kb |
| `hs_setconf` | 291 | 1461 | 433/96Kb |

### Target Descriptions
- `form_captcha`: Custom `application/x-www-form-urlencoded` parser (`src/core/proxy/response.rs`) for extracting CAPTCHA tokens and solutions (`s`, `solution`, `c1-c6`).
- `proxy_protocol`: Integration with `proxy-header` (V1/V2) and custom IPv6-based Tor Circuit ID extraction logic (`src/core/proxy/protocol.rs`).
- `session_security`: `CookieCrypto` (XChaCha20-Poly1305 encryption) and `EncryptedSession` deserializer (pipe-delimited string parsing).
- `waf_engine`: `WafEngine::scan` logic including multi-layered decoding (percent, `+`), `libinjection` integration, and custom SSRF/Path Traversal detection.
- `waf_rule_engine`: Deep stress testing of the core `RuleEngine` across path, query, body, and cookie zones.
- `detect_mime`: Validation of file upload magic bytes and MIME signatures to prevent upload filter bypass.
- `hs_setconf`: Validates `torrc` configuration parsing and dynamic Hidden Service (`HS`) setup logic (`src/features/tor/control.rs`).
