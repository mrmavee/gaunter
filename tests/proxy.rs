mod common;
use common::{base_config, spawn_mock_backend, spawn_proxy_server};
use reqwest::StatusCode;

#[tokio::test]
async fn forward_valid() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = reqwest::Client::new();

    let res = client
        .get(format!("http://{proxy}/"))
        .header("X-Circuit-ID", "tor:0001")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_check() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = reqwest::Client::new();

    let res = client
        .get(format!("http://{proxy}/health"))
        .send()
        .await
        .unwrap();

    assert!(res.status() == StatusCode::OK || res.status() == StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn missing_circuit_id() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = reqwest::Client::new();

    let res = client.get(format!("http://{proxy}/")).send().await.unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn limit_body() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = reqwest::Client::new();

    let b = vec![0u8; 11 * 1024 * 1024];
    let res = client
        .post(format!("http://{proxy}/"))
        .header("X-Circuit-ID", "tor:0002")
        .body(b)
        .send()
        .await;

    match res {
        Ok(r) => assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE),
        Err(e) => assert!(e.is_connect() || e.is_body() || e.is_request()),
    }
}

#[tokio::test]
async fn limit_body_persistent() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = reqwest::Client::new();
    let cid = "tor:0003";

    let res = client
        .get(format!("http://{proxy}/api"))
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = common::get_cookie(&res);
    let mut permanently_blocked = false;

    for _ in 0..25 {
        let b = vec![0u8; 11 * 1024 * 1024];
        let mut req = client
            .post(format!("http://{proxy}/upload"))
            .header("X-Circuit-ID", cid);

        if !cookie.is_empty() {
            req = req.header("Cookie", &cookie);
        }

        let res = req.body(b).send().await;

        if let Ok(res) = res {
            let nc = common::get_cookie(&res);
            if !nc.is_empty() {
                cookie = nc;
            }

            if res.status() == StatusCode::PAYLOAD_TOO_LARGE
                || res.status() == StatusCode::BAD_REQUEST
            {
                let body = res.text().await.unwrap_or_default();
                if body.contains("Request Too Large") || body.contains("Access Denied") {
                    permanently_blocked = true;
                    break;
                }
            }
        }
    }

    assert!(
        permanently_blocked,
        "Attacker should be permanently blocked after repeated upload limit violations"
    );
}

#[tokio::test]
async fn throttle_rate() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = reqwest::Client::new();
    let cid = "tor:0004";

    let mut blocked = false;
    for _ in 0..100 {
        if let Ok(res) = client
            .get(format!("http://{proxy}/"))
            .header("X-Circuit-ID", cid)
            .send()
            .await
        {
            let s = res.status();
            if s == StatusCode::TOO_MANY_REQUESTS {
                blocked = true;
                break;
            }

            if s == StatusCode::OK || s == StatusCode::BAD_REQUEST {
                let b = res.text().await.unwrap_or_default();
                if b.contains("Please Wait")
                    || b.contains("Access Denied")
                    || b.contains("Protected by Gaunter")
                {
                    blocked = true;
                    break;
                }
            }
        } else {
            blocked = true;
            break;
        }
    }

    assert!(blocked);
}

#[tokio::test]
async fn throttle_session() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = common::spawn_proxy_limited(&backend);
    let client = reqwest::Client::new();
    let cid = "tor:0005";
    let url = format!("http://{proxy}/api");

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = common::get_cookie(&res);
    let mut session_blocked = false;

    for _ in 0..150 {
        let mut req = client.get(&url).header("X-Circuit-ID", cid);
        if !cookie.is_empty() {
            req = req.header("Cookie", &cookie);
        }

        if let Ok(res) = req.send().await {
            let nc = common::get_cookie(&res);
            if !nc.is_empty() {
                cookie = nc;
            }

            let status = res.status();
            let b = res.text().await.unwrap_or_default();

            if status == StatusCode::BAD_REQUEST
                && (b.contains("permanently blocked due to excessive rate limit violations")
                    || b.contains("permanently blocked due to extreme flooding"))
            {
                session_blocked = true;
                break;
            }
        }
    }

    assert!(
        session_blocked,
        "Session should be permanently blocked due to rate limit karma"
    );
}

#[tokio::test]
async fn handle_fail() {
    let _config = base_config();
    let proxy = spawn_proxy_server("127.0.0.1:1");
    let client = reqwest::Client::new();

    let res = client
        .get(format!("http://{proxy}/"))
        .header("X-Circuit-ID", "tor:0006")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn skip_multipart() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = reqwest::Client::new();

    let b = "--boundary\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n' OR 1=1--\r\n--boundary--\r\n";
    let res = client
        .post(format!("http://{proxy}/upload"))
        .header("X-Circuit-ID", "tor:0007")
        .header("Content-Type", "multipart/form-data; boundary=boundary")
        .body(b)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn bypass_static_assets() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = reqwest::Client::new();

    let res = client
        .get(format!("http://{proxy}/style.css"))
        .header("X-I2P-DestB64", "base64_i2p_destination_identity")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}
