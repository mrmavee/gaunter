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

- **Corpus**: 8861 seeds (36M, minimized)
- **Crashes Found**: 0
- **Last Updated**: 2026-03-02

### Statistics
| Target | Coverage | Features | Corpus |
|--------|----------|----------|--------|
| `form_captcha` | 1123 | 3481 | 545/120Kb |
| `proxy_protocol` | 334 | 515 | 131/6221b |
| `session_security` | 1238 | 3667 | 302/38Kb |
| `waf_engine` | 7278 | 41293 | 6939/1186Kb |
| `detect_mime` | 81 | 120 | 51/1748b |
| `waf_rule_engine` | 1401 | 6665 | 648/84Kb |

### Target Descriptions
- `form_captcha`: Custom `application/x-www-form-urlencoded` parser (`src/core/proxy/response.rs`) for extracting CAPTCHA tokens and solutions (`s`, `solution`, `c1-c6`).
- `proxy_protocol`: Integration with `proxy-header` (V1/V2) and custom IPv6-based Tor Circuit ID extraction logic (`src/core/proxy/protocol.rs`).
- `session_security`: `CookieCrypto` (XChaCha20-Poly1305 encryption) and `EncryptedSession` deserializer (pipe-delimited string parsing).
- `waf_engine`: `WafEngine::scan` logic including multi-layered decoding (percent, `+`), `libinjection` integration, and custom SSRF/Path Traversal detection.
- `waf_rule_engine`: Deep stress testing of the core `RuleEngine` across path, query, body, and cookie zones.
- `detect_mime`: Validation of file upload magic bytes and MIME signatures to prevent upload filter bypass.
