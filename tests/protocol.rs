mod common;
use common::{base_config, spawn_mock_backend, spawn_stack};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[tokio::test]
async fn forward_proxy_v1() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy_addr, _) = spawn_stack(&backend);

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&proxy_addr))
        .await
        .unwrap()
        .unwrap();

    let hdr = "PROXY TCP6 fd87:d87e:eb43::0000:0001 fd87:d87e:eb43::1 12345 80\r\n";
    let req = "GET / HTTP/1.1\r\nHost: gaunter\r\nConnection: close\r\n\r\n";

    stream.write_all(hdr.as_bytes()).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut res = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut res))
        .await
        .unwrap()
        .unwrap();

    let s = String::from_utf8_lossy(&res);
    assert!(s.contains("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn circuit_ban_karma() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy_addr, defense) = spawn_stack(&backend);

    let ipv6_cid = "fd87:d87e:eb43::0000:0bad";
    let unified_cid = "tor:2989";
    defense.add_karma(unified_cid, 300);

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&proxy_addr))
        .await
        .unwrap()
        .unwrap();

    let hdr = format!("PROXY TCP6 {ipv6_cid} fd87:d87e:eb43::1 12345 80\r\n");
    stream.write_all(hdr.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(n, 0);
}

#[tokio::test]
async fn dest_ban_karma() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy_addr, defense) = spawn_stack(&backend);

    let raw_hash = "i2p_destination_hash";
    let unified_cid = gaunter::test_helpers::i2p_destination_id(raw_hash);
    defense.add_karma(&unified_cid, 300);

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&proxy_addr))
        .await
        .unwrap()
        .unwrap();

    let req = format!("GET / HTTP/1.1\r\nHost: gaunter\r\nX-I2P-DestHash: {raw_hash}\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let res = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap();

    match res {
        Ok(n) => assert_eq!(n, 0),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset),
    }
}

#[tokio::test]
async fn compress_gzip() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy_addr, _) = spawn_stack(&backend);

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&proxy_addr))
        .await
        .unwrap()
        .unwrap();

    let hdr = "PROXY TCP6 fd87:d87e:eb43::0000:0002 fd87:d87e:eb43::1 12345 80\r\n";
    let req =
        "GET / HTTP/1.1\r\nHost: gaunter\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n";

    stream.write_all(hdr.as_bytes()).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut res = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut res))
        .await
        .unwrap()
        .unwrap();

    let s = String::from_utf8_lossy(&res);
    assert!(s.contains("Content-Encoding: gzip"));
}

#[tokio::test]
async fn reject_junk() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy_addr, _) = spawn_stack(&backend);

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&proxy_addr))
        .await
        .unwrap()
        .unwrap();

    stream
        .write_all(b"GET / INVALID_PROTOCOL\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 1024];
    let res = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    assert!(res.is_err() || res.unwrap().unwrap() == 0);
}

#[tokio::test]
async fn reject_overflow() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy_addr, _) = spawn_stack(&backend);

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&proxy_addr))
        .await
        .unwrap()
        .unwrap();

    let long_hdr = "X-Header-Overflow: ".to_string() + &"A".repeat(9000) + "\r\n";
    let req = format!("GET / HTTP/1.1\r\nHost: overflow_host\r\n{long_hdr}\r\n");

    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let res = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    assert!(res.is_err() || res.unwrap().unwrap() == 0);
}

#[tokio::test]
async fn reject_dup_cl() {
    let _config = base_config();
    let backend = spawn_mock_backend();
    let (proxy_addr, _) = spawn_stack(&backend);

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&proxy_addr))
        .await
        .unwrap()
        .unwrap();

    let req =
        "POST / HTTP/1.1\r\nHost: gaunter\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n12345";
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let res = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    assert!(res.is_err() || res.unwrap().unwrap() == 0);
}
