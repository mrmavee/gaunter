//! HTTP response utilities.
//!
//! Provides helper functions for serving HTML and redirect responses.

use crate::config::Config;
use crate::core::proxy::headers::inject_security_headers;
use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;

pub async fn serve_html(
    session: &mut Session,
    config: &Config,
    status: u16,
    html: String,
    set_cookie: Option<&str>,
) -> Result<bool> {
    let mut header = ResponseHeader::build(status, None)?;
    header.insert_header("Content-Type", "text/html; charset=utf-8")?;
    header.insert_header("Content-Length", html.len().to_string())?;
    header.insert_header(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0",
    )?;
    header.insert_header("Pragma", "no-cache")?;
    header.insert_header("Expires", "0")?;

    if let Some(cookie) = set_cookie {
        header.insert_header("Set-Cookie", cookie)?;
    }

    inject_security_headers(&mut header, config)?;

    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::from(html)), true)
        .await?;
    Ok(true)
}

pub async fn serve_redirect(
    session: &mut Session,
    config: &Config,
    location: &str,
    set_cookie: Option<&str>,
    clear_cache: bool,
) -> Result<bool> {
    let mut header = ResponseHeader::build(303, None)?;
    header.insert_header("Location", location)?;
    header.insert_header(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0",
    )?;
    header.insert_header("Pragma", "no-cache")?;
    header.insert_header("Expires", "0")?;

    if let Some(cookie) = set_cookie {
        header.insert_header("Set-Cookie", cookie)?;
    }

    if clear_cache {
        header.insert_header("Clear-Site-Data", "\"cache\"")?;
    }

    inject_security_headers(&mut header, config)?;

    session
        .write_response_header(Box::new(header), true)
        .await?;
    Ok(true)
}

pub async fn handle_health_check(session: &mut Session, config: &Config) -> Result<bool> {
    let path = session.req_header().uri.path();
    if path != "/.well-known/health" && path != "/health" {
        return Ok(false);
    }

    let is_internal = session.client_addr().is_some_and(|addr| {
        if let pingora::protocols::l4::socket::SocketAddr::Inet(inet) = addr {
            inet.ip().is_loopback()
        } else {
            false
        }
    });

    if is_internal {
        let mut header = ResponseHeader::build(200, None)?;
        header.insert_header("Content-Type", "text/plain")?;
        header.insert_header("Content-Length", "2")?;
        header.insert_header("Cache-Control", "no-store")?;

        inject_security_headers(&mut header, config)?;

        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(bytes::Bytes::from_static(b"OK")), true)
            .await?;
        return Ok(true);
    }

    Ok(false)
}

/// Parses form submission.
#[must_use]
pub fn parse_form(body: &[u8]) -> (String, String) {
    use percent_encoding::percent_decode_str;
    use std::collections::HashMap;

    let body_str = String::from_utf8_lossy(body);
    let mut token = String::new();
    let mut solution = String::new();
    let mut c_map = HashMap::new();

    for pair in body_str.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let dk = percent_decode_str(&k.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned();
        let dv = percent_decode_str(&v.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned();

        match dk.as_str() {
            "s" => token = dv,
            "solution" => solution = dv,
            key if key.starts_with('c') && key.len() == 2 => {
                c_map.insert(key.to_string(), dv);
            }
            _ => {}
        }
    }

    let answer = if solution.is_empty() {
        format!(
            "{}{}{}{}{}{}",
            c_map.get("c1").map_or("", String::as_str),
            c_map.get("c2").map_or("", String::as_str),
            c_map.get("c3").map_or("", String::as_str),
            c_map.get("c4").map_or("", String::as_str),
            c_map.get("c5").map_or("", String::as_str),
            c_map.get("c6").map_or("", String::as_str),
        )
    } else {
        solution
    };

    (token, answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_parsing() {
        let (token, answer) = parse_form(b"s=token_id&c1=A&c2=B&c3=C&c4=D&c5=E&c6=F");
        assert_eq!(token, "token_id");
        assert_eq!(answer, "ABCDEF");

        let (token, answer) = parse_form(b"s=alt_token&solution=solution_val");
        assert_eq!(token, "alt_token");
        assert_eq!(answer, "solution_val");

        let (token, answer) = parse_form(b"s=encoded%20val&solution=hello+world");
        assert_eq!(token, "encoded val");
        assert_eq!(answer, "hello world");

        let (token, answer) = parse_form(b"");
        assert!(token.is_empty());
        assert!(answer.is_empty());

        let (token, answer) = parse_form(b"invalid_data&no_equals&===&");
        assert!(token.is_empty());
        assert!(answer.is_empty());

        let (token, answer) = parse_form(b"s=token_val&c1=X");
        assert_eq!(token, "token_val");
        assert_eq!(answer, "X");

        let (token, answer) = parse_form(b"s=t&c1=A&c2=B&c3=C&c4=D&c5=E&c6=F&solution=OVER");
        assert_eq!(token, "t");
        assert_eq!(answer, "OVER");
    }
}
