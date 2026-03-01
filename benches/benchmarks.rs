use criterion::{Criterion, criterion_group, criterion_main};
use gaunter::test_helpers::{
    CookieCrypto, EncryptedSession, RuleEngine, detect_safe_mime, parse_form, parse_proxy_header,
};
use gaunter::{Config, WafEngine, WebhookNotifier};
use std::hint::black_box;
use std::sync::Arc;

fn bench_waf_engine(c: &mut Criterion) {
    let config = Arc::new(Config::default());
    let webhook = Arc::new(WebhookNotifier::new(&config));
    let engine = WafEngine::try_new(webhook, vec![]).expect("ok");

    c.bench_function("waf_scan_clean", |b| {
        b.iter(|| engine.scan(black_box("/api/v1/data?page=1"), black_box("URI")));
    });

    c.bench_function("waf_scan_sqli", |b| {
        b.iter(|| engine.scan(black_box("/search?q=' OR 1=1--"), black_box("URI")));
    });

    c.bench_function("waf_scan_xss", |b| {
        b.iter(|| {
            engine.scan(
                black_box("/page?x=<script>alert(1)</script>"),
                black_box("URI"),
            );
        });
    });
}

fn bench_rule_engine(c: &mut Criterion) {
    let engine = RuleEngine::try_new().expect("ok");

    c.bench_function("rule_eval_clean", |b| {
        b.iter(|| {
            let _ = engine.eval(
                black_box("/about"),
                black_box("page=2&sort=name"),
                black_box(""),
                black_box("session=abc123"),
            );
        });
    });

    c.bench_function("rule_eval_attack", |b| {
        b.iter(|| {
            let _ = engine.eval(
                black_box("/"),
                black_box("id=1' OR 1=1-- ; SELECT * FROM users; @@version"),
                black_box("<script>alert(1)</script><img onerror=x onload=y><svg onload=z>"),
                black_box("()()(SELECT 1)"),
            );
        });
    });
}

fn bench_cookie_crypto(c: &mut Criterion) {
    let crypto = CookieCrypto::new("0123456789abcdef0123456789abcdef");
    let payload = b"session_id|circuit_123|1700000000|0|0|0|0|0|0|0|0|0||0|0|0|0";

    c.bench_function("cookie_encrypt", |b| {
        b.iter(|| crypto.try_encrypt(black_box(payload)));
    });

    let encrypted = crypto.try_encrypt(payload).expect("ok");

    c.bench_function("cookie_decrypt", |b| {
        b.iter(|| crypto.decrypt(black_box(&encrypted)));
    });
}

fn bench_session_serialization(c: &mut Criterion) {
    let session = EncryptedSession {
        session_id: "test-sess".to_string(),
        circuit_id: Some("127.0.0.1".to_string()),
        created_at: 1_700_000_000,
        queue_started_at: 0,
        queue_completed: false,
        captcha_failures: 0,
        captcha_gen_count: 1,
        verified: true,
        verified_at: 1_700_000_000,
        last_active_at: 1_700_000_000,
        blocked: false,
        blocked_at: 0,
        block_reason: String::new(),
        waf_violations: 0,
        upload_violations: 0,
        ratelimit_violations: 0,
        karma_total: 0,
    };

    c.bench_function("session_to_bytes", |b| {
        b.iter(|| session.to_bytes());
    });

    let bytes = session.to_bytes();

    c.bench_function("session_from_bytes", |b| {
        b.iter(|| EncryptedSession::from_bytes(black_box(&bytes), black_box(3600)));
    });
}

fn bench_signatures(c: &mut Criterion) {
    let png = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let unknown = b"plain text payload for testing";

    c.bench_function("detect_mime_png", |b| {
        b.iter(|| detect_safe_mime(black_box(png)));
    });

    c.bench_function("detect_mime_unknown", |b| {
        b.iter(|| detect_safe_mime(black_box(unknown)));
    });
}

fn bench_response_parsing(c: &mut Criterion) {
    let valid_form = b"token=abcdef123456&answer=ABCDEF";
    let invalid_form = b"key1=val1&key2=val2";

    c.bench_function("parse_form_valid", |b| {
        b.iter(|| parse_form(black_box(valid_form)));
    });

    c.bench_function("parse_form_invalid", |b| {
        b.iter(|| parse_form(black_box(invalid_form)));
    });
}

fn bench_proxy_protocol(c: &mut Criterion) {
    let v2_header = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C\xC0\xA8\x01\x01\xC0\xA8\x01\x02\x04\xD2\x1B\x39";

    c.bench_function("parse_proxy_v2", |b| {
        b.iter(|| parse_proxy_header(black_box(v2_header), black_box("")));
    });
}

criterion_group!(
    benches,
    bench_waf_engine,
    bench_rule_engine,
    bench_cookie_crypto,
    bench_session_serialization,
    bench_signatures,
    bench_response_parsing,
    bench_proxy_protocol,
);
criterion_main!(benches);
