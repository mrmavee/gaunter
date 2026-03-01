mod common;
use common::{base_waf, default_restricted_paths};

#[tokio::test]
async fn block_sqli() {
    let waf = base_waf();

    let payloads = [
        "/search?q=' OR 1=1--",
        "/search?q=' OR ''='",
        "/login?user=admin'--",
        "/api?id=1' AND 1=CONVERT(int,@@version)--",
    ];

    for payload in payloads {
        let result = waf.scan(payload, "URI");
        assert!(result.blocked);
    }
}

#[tokio::test]
async fn block_xss() {
    let waf = base_waf();

    let payloads = [
        "/page?x=<script>alert(1)</script>",
        "/page?x=<img onerror=alert(1)>",
        "/page?x=<svg onload=alert(1)>",
        "/page?x=<body onload=alert(1)>",
    ];

    for payload in payloads {
        let result = waf.scan(payload, "URI");
        assert!(result.blocked);
    }
}

#[tokio::test]
async fn block_lfi() {
    let waf = base_waf();

    let payloads = [
        "/../../etc/passwd",
        "/..\\..\\windows\\system32\\config\\sam",
        "/path%00.html",
        "/static/../../etc/shadow",
        "/%2e%2e/%2e%2e/etc/passwd",
    ];

    for payload in payloads {
        let result = waf.scan(payload, "URI");
        assert!(result.blocked,);
    }
}

#[tokio::test]
async fn block_ssrf() {
    let waf = base_waf();

    let payloads = [
        "/proxy?url=file:///etc/shadow",
        "/proxy?url=gopher://127.0.0.1:25/",
        "/proxy?url=http://127.0.0.1/admin",
        "/proxy?url=http://localhost/admin",
        "/proxy?url=http://169.254.169.254/latest/meta-data/",
        "/proxy?url=http://10.0.0.1/internal",
        "/proxy?url=http://192.168.1.1/secret",
        "/proxy?url=http://[::1]/admin",
        "/proxy?url=dict://localhost:6379/",
        "/proxy?url=ftp://internal-server/data",
    ];

    for payload in payloads {
        let result = waf.scan(payload, "URI");
        assert!(result.blocked);
    }
}

#[tokio::test]
async fn detect_restricted_paths() {
    let restricted_paths = default_restricted_paths();

    for path in &restricted_paths {
        assert!(restricted_paths.contains(path.as_str()),);
    }

    let critical_paths = ["/.env", "/.git/HEAD", "/.aws/credentials", "/wp-admin"];
    for path in critical_paths {
        assert!(restricted_paths.contains(path),);
    }

    assert!(!restricted_paths.contains("/"),);
    assert!(!restricted_paths.contains("/about"),);
}

#[tokio::test]
async fn allow_safe() {
    let waf = base_waf();

    let safe_inputs = [
        "/",
        "/about",
        "/search?q=hello+world",
        "/api/v1/data?page=2&limit=50",
        "/products?category=electronics&sort=price",
        "/user/profile?tab=settings",
    ];

    for input in safe_inputs {
        let result = waf.scan(input, "URI");
        assert!(!result.blocked,);
    }
}
