mod common;
use common::{base_config, spawn_mock_backend, spawn_stack};
use reqwest::StatusCode;

#[tokio::test]
async fn block_sqli() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy, _) = spawn_stack(&backend);
    let client = reqwest::Client::new();

    let res = client
        .get(format!("http://{proxy}/?id=%27%20OR%201%3D1--"))
        .header("X-Circuit-ID", "tor:0001")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn block_lfi() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy, _) = spawn_stack(&backend);
    let client = reqwest::Client::new();

    let res = client
        .get(format!("http://{proxy}/%252e%252e%252fetc/passwd"))
        .header("X-Circuit-ID", "tor:0002")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn block_ssrf() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy, _) = spawn_stack(&backend);
    let client = reqwest::Client::new();

    let res = client
        .get(format!("http://{proxy}/?url=http://[::1]/admin"))
        .header("X-Circuit-ID", "tor:0003")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn block_restricted_path() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy, _) = spawn_stack(&backend);
    let client = reqwest::Client::new();

    let res = client
        .get(format!("http://{proxy}/.env"))
        .header("X-Circuit-ID", "tor:0004")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res_silent = client
        .get(format!("http://{proxy}/server-status"))
        .header("X-Circuit-ID", "tor:0005")
        .send()
        .await
        .unwrap();
    assert_eq!(res_silent.status(), StatusCode::BAD_REQUEST);

    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let res = client
        .get(format!("http://{proxy}/valid"))
        .header("X-Circuit-ID", "tor:0004")
        .header("Cookie", cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn block_waf_persistent() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy, _) = spawn_stack(&backend);
    let client = reqwest::Client::new();
    let cid = "tor:0006";

    let res = client
        .get(format!("http://{proxy}/api"))
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let mut permanently_blocked = false;

    for _ in 0..25 {
        let mut req = client
            .get(format!("http://{proxy}/?id=%27%20OR%201%3D1--"))
            .header("X-Circuit-ID", cid);

        if !cookie.is_empty() {
            req = req.header("Cookie", &cookie);
        }

        let res = req.send().await.unwrap();

        let nc = res
            .headers()
            .get("set-cookie")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_string();

        if !nc.is_empty() {
            cookie = nc;
        }

        let status = res.status();
        if status == StatusCode::BAD_REQUEST {
            let body = res.text().await.unwrap_or_default();
            if body.contains("Session ID")
                || body.contains("Security Check")
                || body.contains("Incident ID")
            {
                permanently_blocked = true;
                break;
            }
        }
    }

    assert!(
        permanently_blocked,
        "Attacker should be permanently blocked after repeated WAF violations"
    );
}

#[tokio::test]
async fn block_no_id() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy, _) = spawn_stack(&backend);
    let client = reqwest::Client::new();

    let res = client.get(format!("http://{proxy}/")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn block_sqli_body() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy, _) = spawn_stack(&backend);
    let client = reqwest::Client::new();

    let res = client
        .post(format!("http://{proxy}/login"))
        .header("X-Circuit-ID", "tor:0007")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("username=admin' OR 1=1--&password=credential_secret")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
