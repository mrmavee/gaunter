//! HTTP header manipulation.
//!
//! Provides utilities for sanitizing, validating, and injecting proxy headers.

use crate::config::Config;
use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;

pub fn inject_security_headers(
    upstream_response: &mut ResponseHeader,
    config: &Config,
) -> Result<()> {
    let has_upstream_csp = upstream_response
        .headers
        .contains_key("Content-Security-Policy");

    let is_widget_allowed = upstream_response
        .headers
        .get("X-Frame-Options")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("ALLOWALL"));

    let is_cross_origin_allowed = upstream_response
        .headers
        .get("Access-Control-Allow-Origin")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "*");

    upstream_response.remove_header("Server");
    upstream_response.remove_header("Date");
    upstream_response.remove_header("X-Powered-By");
    upstream_response.remove_header("X-AspNet-Version");
    upstream_response.remove_header("X-AspNetMvc-Version");
    upstream_response.remove_header("X-XSS-Protection");
    upstream_response.remove_header("Expect-CT");
    upstream_response.remove_header("Via");
    upstream_response.remove_header("ETag");
    upstream_response.remove_header("Pragma");
    upstream_response.remove_header("Warning");
    upstream_response.remove_header("Feature-Policy");
    upstream_response.remove_header("Public-Key-Pins");

    if config.security.hide_server {
        upstream_response.remove_header("Server");
    } else {
        upstream_response.insert_header("Server", "Gaunter")?;
    }

    upstream_response.insert_header(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload",
    )?;

    if config.features.csp_injected || !has_upstream_csp {
        let csp = if is_widget_allowed {
            &config.security.csp_widget
        } else {
            &config.security.csp_normal
        };
        upstream_response.insert_header("Content-Security-Policy", csp)?;
    }

    upstream_response.insert_header("X-Content-Type-Options", "nosniff")?;
    upstream_response.insert_header("Referrer-Policy", "no-referrer")?;

    if config.security.coop_policy != "off" {
        upstream_response
            .insert_header("Cross-Origin-Opener-Policy", &config.security.coop_policy)?;
    }

    let corp_policy = if is_cross_origin_allowed {
        "cross-origin"
    } else {
        "same-origin"
    };
    upstream_response.insert_header("Cross-Origin-Resource-Policy", corp_policy)?;

    Ok(())
}

pub fn extract_circuit_id(session: &Session) -> Option<String> {
    let cid = session
        .req_header()
        .headers
        .get("x-circuit-id")
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    if cid.is_some() {
        return cid;
    }

    session
        .req_header()
        .headers
        .get("x-i2p-destb64")
        .and_then(|v| v.to_str().ok())
        .map(|s| format!("i2p:{s}"))
}

/// Checks if the request URI points to a static asset.
#[must_use]
pub fn is_static_asset(session: &Session) -> bool {
    let path = session.req_header().uri.path();
    std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "css"
                    | "js"
                    | "mjs"
                    | "map"
                    | "png"
                    | "jpg"
                    | "jpeg"
                    | "gif"
                    | "webp"
                    | "avif"
                    | "bmp"
                    | "heic"
                    | "heif"
                    | "ico"
                    | "svg"
                    | "svgz"
                    | "woff"
                    | "woff2"
                    | "ttf"
                    | "eot"
                    | "otf"
                    | "mp4"
                    | "webm"
                    | "ogg"
                    | "ogv"
                    | "mp3"
                    | "wav"
                    | "flac"
                    | "aac"
                    | "m4a"
                    | "pdf"
                    | "txt"
                    | "md"
                    | "json"
                    | "xml"
                    | "rss"
                    | "atom"
                    | "manifest"
                    | "webmanifest"
                    | "appcache"
                    | "wasm"
                    | "zip"
                    | "gz"
                    | "br"
                    | "zst"
            )
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cfg(csp_inject: bool, coop: &str, hide_server: bool) -> Config {
        Config {
            network: crate::config::settings::NetworkSettings::default(),
            tor: crate::config::settings::TorSettings::default(),
            security: crate::config::settings::SecuritySettings {
                csp_normal: "default-src 'self'".to_string(),
                csp_widget: "default-src 'self'; frame-ancestors *".to_string(),
                coop_policy: coop.to_string(),
                hide_server,
                ..crate::config::settings::SecuritySettings::default()
            },
            captcha: crate::config::settings::CaptchaSettings::default(),
            session: crate::config::settings::SessionSettings::default(),
            defense: crate::config::settings::DefenseSettings::default(),
            meta: crate::config::settings::MetaSettings::default(),
            webhook: crate::config::settings::WebhookSettings::default(),
            features: crate::config::settings::FeatureFlags {
                csp_injected: csp_inject,
                ..crate::config::settings::FeatureFlags::default()
            },
            log_format: "json".to_string(),
        }
    }

    #[test]
    fn header_injection() {
        let config = cfg(false, "same-origin", false);
        let mut r = ResponseHeader::build(200, None).unwrap();
        inject_security_headers(&mut r, &config).unwrap();

        assert_eq!(
            r.headers.get("Server").unwrap().to_str().unwrap(),
            "Gaunter"
        );
        assert!(!r.headers.contains_key("X-Powered-By"));

        assert!(r.headers.contains_key("Strict-Transport-Security"));
        assert!(r.headers.contains_key("Content-Security-Policy"));

        let mut r_hide = ResponseHeader::build(200, None).unwrap();
        inject_security_headers(&mut r_hide, &cfg(false, "same-origin", true)).unwrap();
        assert!(!r_hide.headers.contains_key("Server"));

        let mut r2 = ResponseHeader::build(200, None).unwrap();
        r2.insert_header("Content-Security-Policy", "existing")
            .unwrap();
        inject_security_headers(&mut r2, &cfg(false, "same-origin", false)).unwrap();
        assert_eq!(
            r2.headers
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "existing"
        );

        let mut r3 = ResponseHeader::build(200, None).unwrap();
        r3.insert_header("Content-Security-Policy", "old").unwrap();
        inject_security_headers(&mut r3, &cfg(true, "same-origin", false)).unwrap();
        assert_ne!(
            r3.headers
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "old"
        );

        let mut r4 = ResponseHeader::build(200, None).unwrap();
        r4.insert_header("X-Frame-Options", "ALLOWALL").unwrap();
        inject_security_headers(&mut r4, &cfg(false, "same-origin", false)).unwrap();
        assert!(
            r4.headers
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("frame-ancestors")
        );

        let mut r5 = ResponseHeader::build(200, None).unwrap();
        r5.insert_header("Access-Control-Allow-Origin", "*")
            .unwrap();
        inject_security_headers(&mut r5, &cfg(false, "same-origin", false)).unwrap();
        assert_eq!(
            r5.headers
                .get("Cross-Origin-Resource-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "cross-origin"
        );

        let mut r6 = ResponseHeader::build(200, None).unwrap();
        inject_security_headers(&mut r6, &cfg(false, "off", false)).unwrap();
        assert!(!r6.headers.contains_key("Cross-Origin-Opener-Policy"));
    }
}
