//! PROXY protocol parser and forwarder.
//!
//! Handles TCP ingress with PROXY v1 headers and circuit ID extraction.

use async_chunked_transfer::Encoder;
use async_compression::tokio::write::{BrotliEncoder, GzipEncoder};
use proxy_header::{ParseConfig, ProxyHeader};
use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, trace, warn};

use crate::error::{Error, Result};

fn extract_circuit(ip: &std::net::IpAddr, prefix: &str) -> Option<String> {
    match ip {
        std::net::IpAddr::V6(v6) => {
            let ip_str = v6.to_string();
            if !ip_str.starts_with(prefix) {
                return None;
            }
            let octets = v6.octets();
            let global_id = u64::from_be_bytes([
                octets[8], octets[9], octets[10], octets[11], octets[12], octets[13], octets[14],
                octets[15],
            ]);
            Some(format!("tor:{global_id}"))
        }
        std::net::IpAddr::V4(_) => None,
    }
}

/// Parses PROXY v2 header.
#[cfg(any(fuzzing, feature = "fuzzing", feature = "testing"))]
#[must_use]
pub fn parse_proxy_header(buf: &[u8], prefix: &str) -> Option<(usize, SocketAddr, Option<String>)> {
    parse_proxy_inner(buf, prefix)
}

#[cfg(not(any(fuzzing, feature = "fuzzing", feature = "testing")))]
fn parse_proxy_header(buf: &[u8], prefix: &str) -> Option<(usize, SocketAddr, Option<String>)> {
    parse_proxy_inner(buf, prefix)
}

fn parse_proxy_inner(buf: &[u8], prefix: &str) -> Option<(usize, SocketAddr, Option<String>)> {
    let config = ParseConfig::default();

    match ProxyHeader::parse(buf, config) {
        Ok((header, consumed)) => header.proxied_address().map_or_else(
            || {
                trace!("proxy: local");
                None
            },
            |addr| {
                let source = addr.source;
                let circuit_id = extract_circuit(&source.ip(), prefix);
                trace!(circuit = ?circuit_id, "proxy: circuit detected");

                trace!(
                    source = %source,
                    circuit = ?circuit_id,
                    "proxy: header parsed"
                );

                Some((consumed, source, circuit_id))
            },
        ),
        Err(e) => {
            debug!(error = ?e, "proxy: header parse failed");
            None
        }
    }
}

/// PROXY protocol listener configuration.
#[derive(Clone)]
pub struct ProxyProtocolConfig {
    /// External bind address.
    pub listen_addr: SocketAddr,
    /// Internal bind address.
    pub internal_addr: SocketAddr,
    /// Tor circuit ID prefix.
    pub circuit_prefix: String,
    /// Max concurrent connections.
    pub concurrency_limit: usize,
    /// Optional defense monitor.
    pub defense_monitor: Option<Arc<crate::DefenseMonitor>>,
}

/// Runs the PROXY protocol listener.
///
/// # Errors
/// Returns error if the listener fails to bind.
pub async fn run_proxy_listener(config: ProxyProtocolConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen_addr).await.map_err(|e| {
        Error::Proxy(format!(
            "FATAL: Failed to bind PROXY listener to {}: {}",
            config.listen_addr, e
        ))
    })?;

    info!(
        listen_addr = %config.listen_addr,
        "ready on {}", config.listen_addr
    );
    info!(
        internal_addr = %config.internal_addr,
        "forwarding to {}", config.internal_addr
    );

    let connection_limit =
        std::sync::Arc::new(tokio::sync::Semaphore::new(config.concurrency_limit));

    loop {
        let Ok(permit) = Arc::clone(&connection_limit).acquire_owned().await else {
            break;
        };

        match listener.accept().await {
            Ok((mut client, peer_addr)) => {
                let cfg = config.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = Box::pin(handle_connection(&mut client, peer_addr, &cfg)).await
                    {
                        debug!(peer_addr = %peer_addr, error = %e, "connection error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "failed to accept connection");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    Ok(())
}
fn configure_tcp_stream(stream: &TcpStream) {
    let sock = socket2::SockRef::from(&stream);

    let _ = stream.set_nodelay(true);

    let mut ka = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(10));

    #[cfg(not(target_os = "openbsd"))]
    {
        ka = ka.with_retries(3);
    }

    let _ = sock.set_tcp_keepalive(&ka);

    #[cfg(target_os = "linux")]
    {
        let _ = sock.set_tcp_user_timeout(Some(std::time::Duration::from_millis(10000)));
    }
}

async fn handle_connection(
    client: &mut TcpStream,
    _peer_addr: SocketAddr,
    config: &ProxyProtocolConfig,
) -> std::io::Result<()> {
    configure_tcp_stream(client);

    let mut buf = [0u8; 512];
    let n = client.peek(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    let (skip_bytes, circuit_id) = if buf.starts_with(b"PROXY ") {
        buf.get(..n).map_or((0, None), |slice| {
            match parse_proxy_header(slice, &config.circuit_prefix) {
                Some((consumed, _source, cid)) => (consumed, cid),
                None => (0, None),
            }
        })
    } else {
        (0, None)
    };

    if skip_bytes > 0 {
        let mut discard = vec![0u8; skip_bytes];
        client.read_exact(&mut discard).await?;
    }

    if let Some(cid) = circuit_id.as_ref()
        && config
            .defense_monitor
            .as_ref()
            .is_some_and(|m| m.is_circuit_banned(cid))
    {
        warn!(circuit = %cid, action = "circuit_ban", "connection refused: circuit banned");
        return Ok(());
    }

    let mut upstream = TcpStream::connect(config.internal_addr).await?;
    configure_tcp_stream(&upstream);

    let accept_encoding = process_req(client, &mut upstream, circuit_id).await?;
    Box::pin(process_res(client, &mut upstream, accept_encoding)).await?;

    Ok(())
}

fn build_headers(
    req: &httparse::Request,
    circuit_id: Option<&String>,
) -> std::io::Result<(String, Option<usize>, Option<String>)> {
    let mut content_length: Option<usize> = None;
    let mut transfer_encoding = false;
    let mut accept_encoding = None;

    for header in req.headers.iter() {
        let name = header.name.to_lowercase();
        if name == "content-length" {
            if content_length.is_some() {
                debug!(action = "rejected", "duplicate content-length");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Duplicate Content-Length",
                ));
            }
            let value_str = std::str::from_utf8(header.value)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            content_length = Some(
                value_str
                    .trim()
                    .parse()
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?,
            );
        } else if name == "transfer-encoding" {
            transfer_encoding = true;
        } else if name == "accept-encoding" {
            accept_encoding = Some(String::from_utf8_lossy(header.value).to_string());
        }
    }

    if transfer_encoding {
        debug!(action = "rejected", "chunked encoding disallowed");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Chunked Transfer-Encoding disallowed",
        ));
    }

    let mut modified_request = String::new();
    if let (Some(method), Some(path), Some(version)) = (req.method, req.path, req.version) {
        let _ = write!(modified_request, "{method} {path} HTTP/1.{version}\r\n");
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Malformed Request Line",
        ));
    }

    for header in req.headers.iter() {
        let name = header.name;
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("x-circuit-id")
        {
            continue;
        }
        let value = std::str::from_utf8(header.value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let _ = write!(modified_request, "{name}: {value}\r\n");
    }

    modified_request.push_str("Connection: close\r\n");
    if let Some(cid) = circuit_id {
        let _ = write!(modified_request, "X-Circuit-ID: {cid}\r\n");
    }
    if let Some(cl) = content_length {
        let _ = write!(modified_request, "Content-Length: {cl}\r\n");
    }
    modified_request.push_str("\r\n");

    Ok((modified_request, content_length, accept_encoding))
}

async fn process_req(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    circuit_id: Option<String>,
) -> std::io::Result<Option<String>> {
    let mut buf = [0u8; 8192];
    let mut pos = 0;

    loop {
        let Some(slice) = buf.get_mut(pos..) else {
            debug!("header buffer full");
            return Ok(None);
        };

        let bytes_read = if let Ok(result) =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.read(slice)).await
        {
            result?
        } else {
            debug!("header read timeout");
            return Ok(None);
        };

        if bytes_read == 0 {
            return Ok(None);
        }
        pos += bytes_read;

        let mut headers = [httparse::Header {
            name: "",
            value: &[],
        }; 64];
        let mut req = httparse::Request::new(&mut headers);

        let Some(slice) = buf.get(..pos) else {
            return Ok(None);
        };

        match req.parse(slice) {
            Ok(httparse::Status::Complete(header_len)) => {
                let Ok((modified_request, content_length, accept_encoding)) =
                    build_headers(&req, circuit_id.as_ref())
                else {
                    return Ok(None);
                };

                upstream.write_all(modified_request.as_bytes()).await?;

                let body_start = header_len;
                let body_in_buf = pos - body_start;

                if body_in_buf > 0
                    && let Some(slice) = buf.get(body_start..pos)
                {
                    upstream.write_all(slice).await?;
                }

                let cl = content_length.unwrap_or(0);
                if cl > body_in_buf {
                    let remaining = (cl - body_in_buf) as u64;
                    let mut limited = client.take(remaining);
                    tokio::io::copy(&mut limited, upstream).await?;
                }

                upstream.flush().await?;
                return Ok(accept_encoding);
            }
            Ok(httparse::Status::Partial) => {
                if pos >= buf.len() {
                    debug!("headers too large");
                    return Ok(None);
                }
            }
            Err(e) => {
                debug!(error = ?e, "invalid http request");
                return Ok(None);
            }
        }
    }
}

fn build_res_headers(resp: &httparse::Response, compress: Option<&str>) -> std::io::Result<String> {
    let mut modified_response = String::new();
    if let (Some(version), Some(code), Some(reason)) = (resp.version, resp.code, resp.reason) {
        let _ = write!(modified_response, "HTTP/1.{version} {code} {reason}\r\n");
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Malformed Response",
        ));
    }

    for header in resp.headers.iter() {
        let name = header.name;
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("server")
            || (compress.is_some()
                && (name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("transfer-encoding")
                    || name.eq_ignore_ascii_case("content-encoding")))
        {
            continue;
        }
        let value = std::str::from_utf8(header.value).unwrap_or("");
        let _ = write!(modified_response, "{name}: {value}\r\n");
    }

    modified_response.push_str("Connection: close\r\n");
    modified_response.push_str("Server: Gaunter\r\n");

    if let Some(enc) = compress {
        let _ = write!(modified_response, "Content-Encoding: {enc}\r\n");
        modified_response.push_str("Transfer-Encoding: chunked\r\n");
    }

    modified_response.push_str("\r\n");
    Ok(modified_response)
}

async fn forward_response_body(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    initial_body: &[u8],
    compress: Option<&str>,
    content_length: usize,
    is_chunked: bool,
) -> std::io::Result<()> {
    let cursor = std::io::Cursor::new(initial_body);
    let mut chain = cursor.chain(upstream);

    if let Some(enc) = compress {
        let mut chunked_writer = Encoder::new(&mut *client);
        if enc == "br" {
            let mut encoder = BrotliEncoder::new(&mut chunked_writer);
            tokio::io::copy(&mut chain, &mut encoder).await?;
            encoder.shutdown().await?;
        } else {
            let mut encoder = GzipEncoder::new(&mut chunked_writer);
            tokio::io::copy(&mut chain, &mut encoder).await?;
            encoder.shutdown().await?;
        }
        chunked_writer.shutdown().await?;
    } else if is_chunked {
        tokio::io::copy(&mut chain, client).await?;
    } else if content_length > 0 {
        let mut limited = chain.take(content_length as u64);
        tokio::io::copy(&mut limited, client).await?;
    } else {
        tokio::io::copy(&mut chain, client).await?;
    }

    client.flush().await?;
    Ok(())
}

async fn process_res(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    accept_encoding: Option<String>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    let mut pos = 0;

    loop {
        let Some(slice) = buf.get_mut(pos..) else {
            debug!("header buffer full");
            return Ok(());
        };
        let bytes_read = upstream.read(slice).await?;
        if bytes_read == 0 {
            return Ok(());
        }
        pos += bytes_read;

        let mut headers = [httparse::Header {
            name: "",
            value: &[],
        }; 64];
        let mut resp = httparse::Response::new(&mut headers);

        let Some(slice) = buf.get(..pos) else {
            debug!("parse buffer error");
            return Ok(());
        };

        match resp.parse(slice) {
            Ok(httparse::Status::Complete(header_len)) => {
                let body_start = header_len;

                let mut is_chunked = false;
                let mut content_length: usize = 0;
                let mut is_upstream_compressed = false;

                for header in resp.headers.iter() {
                    let name = header.name;
                    let value = std::str::from_utf8(header.value)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                    if name.eq_ignore_ascii_case("content-length") {
                        if let Ok(cl) = value.trim().parse() {
                            content_length = cl;
                        }
                    } else if name.eq_ignore_ascii_case("transfer-encoding") {
                        if value.to_lowercase().contains("chunked") {
                            is_chunked = true;
                        }
                    } else if name.eq_ignore_ascii_case("content-encoding") {
                        is_upstream_compressed = true;
                    }
                }

                let compress = match accept_encoding.as_ref() {
                    Some(ae) if !is_upstream_compressed && !is_chunked && content_length > 0 => {
                        let ae_lower = ae.to_lowercase();
                        if ae_lower.contains("br") {
                            Some("br")
                        } else if ae_lower.contains("gzip") {
                            Some("gzip")
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                let modified_response = build_res_headers(&resp, compress)?;
                client.write_all(modified_response.as_bytes()).await?;

                if let Some(slice) = buf.get(body_start..pos) {
                    forward_response_body(
                        client,
                        upstream,
                        slice,
                        compress,
                        content_length,
                        is_chunked,
                    )
                    .await?;
                }
                return Ok(());
            }
            Ok(httparse::Status::Partial) => {
                if pos >= buf.len() {
                    debug!("headers too large");
                    return Ok(());
                }
            }
            Err(e) => {
                debug!(error = ?e, "invalid http response");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn proxy_parsing() {
        let v6: std::net::IpAddr = "fd87:d87e:eb43::dead:beef".parse().unwrap();
        assert_eq!(
            extract_circuit(&v6, "fd87:d87e:eb43"),
            Some("tor:3735928559".to_string())
        );

        let miss: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert!(extract_circuit(&miss, "fd87:d87e:eb43").is_none());

        let v4: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        assert!(extract_circuit(&v4, "fd87:d87e:eb43").is_none());

        let h = b"PROXY TCP4 192.168.1.1 192.168.1.2 12345 80\r\nGET /\r\n";
        let (n, src, cid) = parse_proxy_header(h, "fd87:d87e:eb43").unwrap();
        assert!(n > 0);
        assert_eq!(src.ip().to_string(), "192.168.1.1");
        assert!(cid.is_none());

        let v6h = b"PROXY TCP6 fd87:d87e:eb43::dead:beef fd87:d87e:eb43::1 12345 80\r\nGET /\r\n";
        let (_, _, cid) = parse_proxy_header(v6h, "fd87:d87e:eb43").unwrap();
        assert_eq!(cid.unwrap(), "tor:3735928559");

        assert!(parse_proxy_header(b"INVALID\r\n", "fd87:d87e:eb43").is_none());

        let mut h1 = [httparse::EMPTY_HEADER; 16];
        let mut r1 = httparse::Request::new(&mut h1);
        r1.parse(b"GET /x HTTP/1.1\r\nHost: h\r\nAccept-Encoding: br\r\n\r\n")
            .unwrap();
        let (b, cl, ae) = build_headers(&r1, None).unwrap();
        assert!(b.contains("GET /x HTTP/1.1"));
        assert!(b.contains("Connection: close"));
        assert!(cl.is_none());
        assert!(ae.unwrap().contains("br"));

        let val = "tor:2748".to_string();
        let mut h2 = [httparse::EMPTY_HEADER; 16];
        let mut r2 = httparse::Request::new(&mut h2);
        r2.parse(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\n")
            .unwrap();
        let (b2, cl2, _) = build_headers(&r2, Some(&val)).unwrap();
        assert!(b2.contains("X-Circuit-ID: tor:2748"));
        assert_eq!(cl2, Some(1));

        let mut h3 = [httparse::EMPTY_HEADER; 16];
        let mut r3 = httparse::Request::new(&mut h3);
        r3.parse(b"GET / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n")
            .unwrap();
        assert!(build_headers(&r3, None).is_err());

        let mut h4 = [httparse::EMPTY_HEADER; 16];
        let mut r4 = httparse::Request::new(&mut h4);
        r4.parse(b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
            .unwrap();
        assert!(build_headers(&r4, None).is_err());
    }
}
