mod common;

use common::{base_config, base_defense, spawn_mock_backend, spawn_proxy_server};
use gaunter::test_helpers::TrackMode;
use reqwest::{Client, StatusCode};
use tokio::time::{Duration, sleep};

#[test]
fn is_karma_exceeded() {
    let (_config, monitor) = base_defense();

    let circuit = "fd87:d87e:eb43::0000:0001";
    monitor.add_karma(circuit, 20);
    assert!(!monitor.is_malicious(circuit));

    monitor.add_karma(circuit, 40);
    assert!(monitor.is_malicious(circuit));
}

#[test]
fn rate_limit_exceeded() {
    let (_config, monitor) = base_defense();

    let circuit = "fd87:d87e:eb43::0000:0bad";

    monitor.add_karma(circuit, 300);
    assert!(monitor.is_circuit_banned(circuit));

    let clean_circuit = "fd87:d87e:eb43::0000:0002";
    assert!(!monitor.is_circuit_banned(clean_circuit));
}

#[test]
fn karma_accumulation_blocks() {
    let (_config, monitor) = base_defense();

    let circuit = "fd87:d87e:eb43::0000:dead";

    monitor.add_karma(circuit, 10);
    assert!(!monitor.is_circuit_banned(circuit));

    monitor.add_karma(circuit, 10);
    assert!(!monitor.is_circuit_banned(circuit));

    monitor.add_karma(circuit, 250);
    assert!(monitor.is_circuit_banned(circuit));
}

#[test]
fn session_blocking() {
    let (_config, monitor) = base_defense();

    let session = "session_identity_active";
    assert!(!monitor.is_session_blocked(session));

    monitor.block_session(session);
    assert!(monitor.is_session_blocked(session));

    assert!(!monitor.is_session_blocked("session_identity_alt"));
}

#[test]
fn attack_score_calculation() {
    let (_config, monitor) = base_defense();

    assert!(monitor.attack_score() < 0.1);

    for i in 0..5 {
        monitor.record_request(Some(&format!("cid_{i}")), false, TrackMode::GlobalAndLocal);
        monitor.record_unverified();
    }

    assert!(monitor.attack_score() < 0.1);

    for i in 5..15 {
        monitor.record_request(Some(&format!("cid_{i}")), false, TrackMode::GlobalAndLocal);
    }

    for _ in 0..100 {
        monitor.record_unverified();
    }

    let raw = monitor.attack_score();
    assert!(raw < 2.0);
}

#[tokio::test]
async fn auto_defense_escalation() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = Client::new();

    for i in 0..15 {
        let _ = client
            .get(format!("http://{proxy}/"))
            .header("X-Circuit-ID", format!("tor:circuit_{i:04x}"))
            .send()
            .await;
    }

    sleep(Duration::from_secs(11)).await;

    let res = client
        .get(format!("http://{proxy}/"))
        .header("X-Circuit-ID", "tor:identity_primary")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let res = client
        .get(format!("http://{proxy}/"))
        .header("X-Circuit-ID", "tor:identity_secondary")
        .send()
        .await
        .unwrap();

    let body = res.text().await.unwrap();
    assert!(
        body.contains("Please Wait")
            || body.contains("Security Check")
            || body.contains("Click to Enter")
    );
}

#[tokio::test]
async fn permanent_blocking_flow() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let proxy = spawn_proxy_server(&backend);
    let client = Client::new();
    let url = format!("http://{proxy}/");
    let cid = "tor:identity_attacker";

    let mut cookie = String::new();

    for _ in 0..30 {
        let mut req = client.get(&url).header("X-Circuit-ID", cid);

        if !cookie.is_empty() {
            req = req.header("Cookie", &cookie);
        }

        let res = req.send().await.unwrap();
        let nc = common::get_cookie(&res);
        if !nc.is_empty() {
            cookie = nc;
        }
    }

    let res = client
        .get(&url)
        .header("X-Circuit-ID", cid)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = res.text().await.unwrap();
    assert!(body.contains("permanently blocked"));
}

#[test]
fn remove_unblocks_circuit() {
    let (_config, monitor) = base_defense();
    let circuit = "fd87:d87e:eb43::0000:0003";

    monitor.add_karma(circuit, 300);
    assert!(monitor.is_circuit_banned(circuit));
    assert!(monitor.is_circuit_blocked(circuit));

    monitor.remove_circuit(circuit);

    assert!(!monitor.is_circuit_banned(circuit));
    assert!(!monitor.is_circuit_blocked(circuit));
    assert_eq!(monitor.karma(circuit), 0);
}

#[test]
fn remove_missing_circuit() {
    let (_config, monitor) = base_defense();
    let circuit = "fd87:d87e:eb43::0000:0004";

    monitor.remove_circuit(circuit);
    monitor.remove_circuit(circuit);

    assert_eq!(monitor.karma(circuit), 0);
    assert!(!monitor.is_circuit_blocked(circuit));
}
