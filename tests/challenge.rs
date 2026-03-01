mod common;
use common::{base_config, get_cookie, spawn_mock_backend, spawn_proxy_mode};
use reqwest::{StatusCode, redirect::Policy};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn block_bypass() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_mode(&backend, Some("DEFENSE"));
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();

    let res = client
        .get(format!("http://{proxy}/captcha"))
        .header("X-Circuit-ID", "tor:0001")
        .send()
        .await
        .unwrap();

    let b = res.text().await.unwrap();
    assert!(b.contains("Please Wait"));
}

#[tokio::test]
async fn hold_queue() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_mode(&backend, Some("DEFENSE"));
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let url = format!("http://{proxy}/");
    let cid = "tor:0002";

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = get_cookie(&res);
    let b = res.text().await.unwrap();
    assert!(b.contains("Please Wait"));

    sleep(Duration::from_secs(1)).await;
    let res = client
        .get(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let nc = get_cookie(&res);
    if !nc.is_empty() {
        cookie = nc;
    }

    let b = res.text().await.unwrap();
    assert!(b.contains("Please Wait"));

    sleep(Duration::from_secs(6)).await;
    let res = client
        .get(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let b = res.text().await.unwrap();
    assert!(b.contains("Security Check") || b.contains("captcha"));
}

#[tokio::test]
async fn lock_refresh() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_mode(&backend, Some("DEFENSE"));
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let url = format!("http://{proxy}/");
    let cid = "tor:0003";

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = get_cookie(&res);
    sleep(Duration::from_secs(6)).await;

    let mut blocked = false;
    for _ in 0..30 {
        let res = client
            .get(&url)
            .header("Cookie", &cookie)
            .header("X-Circuit-ID", cid)
            .send()
            .await
            .unwrap();

        let status = res.status();
        let nc = get_cookie(&res);
        if !nc.is_empty() {
            cookie = nc;
        }

        let b = res.text().await.unwrap().to_lowercase();
        if status == StatusCode::BAD_REQUEST && (b.contains("violation") || b.contains("blocked")) {
            blocked = true;
            break;
        }
    }
    assert!(blocked);
}

#[tokio::test]
async fn fail_verify() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_mode(&backend, Some("DEFENSE"));
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let url = format!("http://{proxy}/");
    let cid = "tor:0004";

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let cookie = get_cookie(&res);
    sleep(Duration::from_secs(6)).await;

    let res = client
        .post(format!("http://{proxy}/captcha"))
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("s=invalid_token&solution=mismatch_solution")
        .send()
        .await
        .unwrap();

    let status = res.status();
    assert!(
        status == StatusCode::SEE_OTHER
            || status == StatusCode::FOUND
            || status == StatusCode::OK
            || status.is_redirection()
            || status == StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn redirect_on_verify() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_mode(&backend, Some("DEFENSE"));
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let url = format!("http://{proxy}/");
    let cid = "tor:0005";

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = get_cookie(&res);
    sleep(Duration::from_secs(6)).await;

    let res = client
        .get(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let nc = get_cookie(&res);
    if !nc.is_empty() {
        cookie = nc;
    }

    let res = client
        .post(format!("http://{proxy}/captcha"))
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("s=invalid_token&solution=mismatch_solution")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn enter_flow() {
    use common::spawn_no_captcha;
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_no_captcha(&backend);
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let url = format!("http://{proxy}/");
    let cid = "tor:0006";

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = get_cookie(&res);
    sleep(Duration::from_secs(6)).await;

    let res = client
        .get(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let nc = get_cookie(&res);
    if !nc.is_empty() {
        cookie = nc;
    }

    let b = res.text().await.unwrap();
    let token = extract_token(&b);

    let res = client
        .post(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("s={token}&solution=validation_passcode"))
        .send()
        .await
        .unwrap();

    assert!(res.status().is_redirection());
}

#[tokio::test]
async fn captcha_limit_exceeded() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_mode(&backend, Some("DEFENSE"));
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let url = format!("http://{proxy}/");
    let cid = "tor:0007";

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = get_cookie(&res);
    sleep(Duration::from_secs(6)).await;

    let res = client
        .get(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();
    cookie = get_cookie(&res);

    for _ in 0..4 {
        let res = client
            .get(format!("http://{proxy}/captcha"))
            .header("Cookie", &cookie)
            .header("X-Circuit-ID", cid)
            .send()
            .await
            .unwrap();

        let status = res.status();
        if status == StatusCode::BAD_REQUEST {
            return;
        }

        let nc = get_cookie(&res);
        if !nc.is_empty() {
            cookie = nc;
        }
    }

    let res = client
        .get(format!("http://{proxy}/captcha"))
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn captcha_failure_reset() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_mode(&backend, Some("DEFENSE"));
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let url = format!("http://{proxy}/");
    let cid = "tor:0009";

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = get_cookie(&res);
    sleep(Duration::from_secs(6)).await;

    let res = client
        .get(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();
    cookie = get_cookie(&res);

    for _ in 0..3 {
        let res = client
            .post(format!("http://{proxy}/captcha"))
            .header("Cookie", &cookie)
            .header("X-Circuit-ID", cid)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("s=invalid_token&solution=mismatch_solution")
            .send()
            .await
            .unwrap();

        cookie = get_cookie(&res);
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
    }

    let res = client
        .get(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let b = res.text().await.unwrap();
    assert!(b.contains("Please Wait"));
}

fn extract_token(html: &str) -> String {
    if let Some(pos) = html.find("name=\"s\" value=\"") {
        let start = pos + "name=\"s\" value=\"".len();
        if let Some(end) = html[start..].find('"') {
            return html[start..start + end].to_string();
        }
    }
    String::new()
}

#[tokio::test]
async fn verified_redirect() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = common::spawn_no_captcha(&backend);
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();
    let url = format!("http://{proxy}/");
    let cid = "tor:0008";

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let mut cookie = get_cookie(&res);
    sleep(Duration::from_secs(6)).await;

    let res = client
        .get(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let nc = get_cookie(&res);
    if !nc.is_empty() {
        cookie = nc;
    }

    let b = res.text().await.unwrap();
    let token = extract_token(&b);

    let res = client
        .post(&url)
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("s={token}&solution=validation_passcode"))
        .send()
        .await
        .unwrap();

    let nc = get_cookie(&res);
    if !nc.is_empty() {
        cookie = nc;
    }

    let res = client
        .get(format!("http://{proxy}/captcha"))
        .header("Cookie", &cookie)
        .header("X-Circuit-ID", cid)
        .send()
        .await
        .unwrap();

    let status = res.status();
    assert!(status == StatusCode::SEE_OTHER || status == StatusCode::FOUND);
}
