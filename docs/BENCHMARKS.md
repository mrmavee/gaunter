# Performance Benchmarks

Internal security logic is designed for minimal latency impact. These benchmarks measure the overhead of security layers built on top of the Pingora framework.

## Benchmark Scope

### WAF & Rule Engine
Measures the cost of security inspections for various traffic patterns.
- **Clean Scan**: Processing overhead for standard requests passing all checks.
- **Attack Scan**: Detection speed for SQLi/XSS payloads via `libinjection` and signatures.
- **Rule Eval**: Efficiency of Aho-Corasick and RegexSet matching logic.
- **Captcha Generator**: Rendering speed for full WebP visual challenges.

### Session & Cryptography
Performance of stateless session management.
- **Encryption/Decryption**: Throughput of `XChaCha20-Poly1305` for session tokens.
- **Serialization**: Speed of custom pipe-delimited format conversion.

### Protocol & Helpers
- **PROXY Protocol**: Decoding latency for binary PROXY v2 headers.
- **MIME Detection**: Magic byte signature matching for file uploads.
- **Form Parsing**: Data extraction speed for CAPTCHA submissions.
- **Tor Control**: Parsing efficiency of `torrc` configuration payloads.

## Results

Metrics collected via [Criterion.rs](https://github.com/bheisler/criterion.rs).

| Component | Operation | Latency (Avg) | Note |
| :--- | :--- | :--- | :--- |
| **WAF Engine** | Clean Request Scan | **~8.02 µs** | Standard request overhead |
| **WAF Engine** | SQLi Payload Scan | **~5.16 µs** | libinjection detection |
| **WAF Engine** | XSS Payload Scan | **~5.58 µs** | Signature matching |
| **Rule Engine** | Clean Evaluation | **~492 ns** | Simple path evaluation |
| **Rule Engine** | Attack Evaluation | **~2.05 µs** | Complex pattern scan |
| **CookieCrypto** | Session Encrypt | **~1.79 µs** | Encryption cost |
| **CookieCrypto** | Session Decrypt | **~1.36 µs** | Decryption and integrity |
| **Session** | `to_bytes` | **~656 ns** | String serialization |
| **Session** | `from_bytes` | **~477 ns** | Zero-allocation parsing |
| **File Upload** | Validate PNG MIME | **~2.19 ns** | Magic byte match |
| **File Upload** | Unknown/Malicious | **~4.91 ns** | Fast rejection |
| **Form Data** | Parse Valid Input | **~370 ns** | CAPTCHA extraction |
| **Form Data** | Parse Invalid Input | **~357 ns** | Rapid data rejection |
| **PROXY v2** | Decode Header | **~29.7 ns** | Binary packet parsing |
| **Tor Control** | Parse `torrc` & Build | **~1.12 µs** | Pre-allocated streaming builder |
| **Captcha** | WebP Rendering (Medium) | **~7.15 ms** | Multi-offset blitting rotation |

## Reproduction

Execute benchmarks locally:

```bash
cargo bench --all-features
```

*Note: Results depend on CPU architecture and system load.*
