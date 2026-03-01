//! WAF inspection engine.
//!
//! Provides scanning via libinjection (SQLi/XSS), regex rules, and SSRF protection.

use super::rules::RuleEngine;
pub use crate::features::webhook::{EventType, WebhookNotifier, WebhookPayload};
use percent_encoding::percent_decode_str;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::error::Result;

const BLOCK_SCORE: u8 = 100;
const SEVERITY_CRITICAL: u8 = 5;
const SEVERITY_HIGH: u8 = 4;

/// Result of a WAF scan.
#[derive(Debug, Clone)]
pub struct WafResult {
    /// Whether the request should be blocked.
    pub blocked: bool,
    /// Reason for the block.
    pub reason: Option<String>,
    /// Security severity score.
    pub score: u8,
}

impl WafResult {
    /// Returns a safe result.
    #[must_use]
    pub const fn safe() -> Self {
        Self {
            blocked: false,
            reason: None,
            score: 0,
        }
    }

    /// Returns a blocked result with reason and score.
    #[must_use]
    pub const fn blocked(reason: String, score: u8) -> Self {
        Self {
            blocked: true,
            reason: Some(reason),
            score,
        }
    }
}

/// Primary WAF inspection engine.
#[derive(Clone)]
pub struct WafEngine {
    webhook: Arc<WebhookNotifier>,
    allowed_hosts: Vec<String>,
    rule_engine: RuleEngine,
}

impl WafEngine {
    /// Initializes a new WAF engine.
    ///
    /// # Errors
    /// Returns error if rule engine fails to initialize.
    pub fn try_new(webhook: Arc<WebhookNotifier>, allowed_hosts: Vec<String>) -> Result<Self> {
        Ok(Self {
            webhook,
            allowed_hosts,
            rule_engine: RuleEngine::try_new()?,
        })
    }

    /// Scans input for security violations.
    pub fn scan(&self, input: &str, location: &str) -> WafResult {
        let decoded_input = percent_decode_str(input).decode_utf8_lossy();

        if Self::is_traversal(&decoded_input) {
            warn!(location = %location, action = "waf_block", "path traversal: block");
            let reason = format!("Path Traversal in {location}");
            self.notify("Path Traversal", &reason, SEVERITY_CRITICAL);
            return WafResult::blocked(reason, BLOCK_SCORE);
        }

        if self.is_ssrf(&decoded_input) {
            warn!(location = %location, action = "waf_block", "ssrf/lfi: block");
            let reason = format!("SSRF/LFI in {location}");
            self.notify("SSRF/LFI", &reason, SEVERITY_CRITICAL);
            return WafResult::blocked(reason, BLOCK_SCORE);
        }

        let mut inputs_to_scan = vec![input];
        if decoded_input != input {
            inputs_to_scan.push(decoded_input.as_ref());
        }

        let plus_decoded = decoded_input.replace('+', " ");
        if plus_decoded != decoded_input {
            inputs_to_scan.push(plus_decoded.as_ref());
        }

        for check_input in inputs_to_scan {
            let sqli_res = libinjectionrs::detect_sqli(check_input.as_bytes());
            if sqli_res.is_injection() {
                let fingerprint = sqli_res
                    .fingerprint
                    .map_or_else(|| "unknown".to_string(), |f| f.to_string());
                warn!(
                    location = %location,
                    fingerprint = %fingerprint,
                    action = "waf_block",
                    "sqli block: {fingerprint}"
                );
                let reason = format!("SQLi in {location}: {fingerprint}");
                self.notify("SQL Injection", &reason, SEVERITY_CRITICAL);
                return WafResult::blocked(reason, BLOCK_SCORE);
            }

            let xss_res = libinjectionrs::detect_xss(check_input.as_bytes());
            if xss_res.is_injection() {
                warn!(location = %location, action = "waf_block", "xss block");
                let reason = format!("XSS in {location}");
                self.notify("XSS", &reason, SEVERITY_HIGH);
                return WafResult::blocked(reason, BLOCK_SCORE);
            }
        }

        let (uri_path, uri_query) = input.split_once('?').unwrap_or((input, ""));
        let eval = self.rule_engine.eval(uri_path, uri_query, "", "");
        if eval.blocked {
            warn!(
                location = %location,
                rules = ?eval.matched_rules,
                scores = ?eval.scores,
                action = "waf_block",
                "rule accumulation block"
            );
            let reason = format!("Rule accumulation: {:?}", eval.matched_rules);
            self.notify("RuleEngine", &reason, SEVERITY_CRITICAL);
            return WafResult::blocked(reason, BLOCK_SCORE);
        }

        WafResult::safe()
    }

    fn is_traversal(decoded: &str) -> bool {
        let double_decoded = percent_decode_str(decoded).decode_utf8_lossy();
        for check_input in [decoded, double_decoded.as_ref()] {
            if check_input.contains('\0') {
                return true;
            }

            let path = std::path::Path::new(check_input);
            let cleaned = path_clean::clean(path);
            let cleaned_str = cleaned.to_string_lossy();

            if cleaned_str.starts_with("..") {
                return true;
            }

            if cleaned_str.starts_with("/etc/")
                || cleaned_str.starts_with("/proc/")
                || cleaned_str.starts_with("/sys/")
            {
                return true;
            }

            if check_input.contains("../") || check_input.contains("..\\") {
                return true;
            }
        }

        false
    }

    fn is_ssrf(&self, decoded: &str) -> bool {
        if self.is_dangerous(decoded) {
            return true;
        }

        if let Some((_, query)) = decoded.split_once('?') {
            for pair in query.split('&') {
                if let Some((_, value)) = pair.split_once('=') {
                    let decoded_value = percent_decode_str(value).decode_utf8_lossy();
                    if self.is_dangerous(&decoded_value) {
                        return true;
                    }
                }
            }
        } else if let Ok(parsed) = url::Url::parse(decoded) {
            for (_, value) in parsed.query_pairs() {
                let decoded_value = percent_decode_str(&value).decode_utf8_lossy();
                if self.is_dangerous(&decoded_value) {
                    return true;
                }
            }
        }

        let lower = decoded.to_lowercase();
        if lower.contains("c:\\windows\\") {
            return true;
        }

        false
    }

    fn is_dangerous(&self, input: &str) -> bool {
        let Ok(parsed_url) = url::Url::parse(input) else {
            return false;
        };

        let scheme = parsed_url.scheme();
        if scheme == "file" || scheme == "gopher" || scheme == "dict" || scheme == "ftp" {
            return true;
        }

        if scheme != "http" && scheme != "https" {
            return true;
        }

        let Some(host_str) = parsed_url.host_str() else {
            return false;
        };

        if !self.allowed_hosts.is_empty() {
            return !self.allowed_hosts.iter().any(|h| h == host_str);
        }

        if host_str == "localhost"
            || host_str == "127.0.0.1"
            || host_str == "::1"
            || host_str == "[::1]"
        {
            return true;
        }

        if let Ok(ip) = host_str.parse::<std::net::IpAddr>() {
            if ip.is_loopback() {
                return true;
            }

            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    if ipv4.is_private() || ipv4.is_link_local() || ipv4.is_unspecified() {
                        return true;
                    }
                    let octets = ipv4.octets();
                    if octets[0] == 169 && octets[1] == 254 {
                        return true;
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    if (ipv6.segments()[0] & 0xfe00) == 0xfc00 {
                        return true;
                    }
                    if (ipv6.segments()[0] & 0xffc0) == 0xfe80 {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn notify(&self, attack_type: &str, reason: &str, severity: u8) {
        let full_message = format!("[{attack_type}] {reason}");
        self.webhook.notify(WebhookPayload {
            event_type: EventType::WafBlock,
            timestamp: i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )
            .unwrap_or(0),
            circuit_id: None,
            severity,
            message: full_message,
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn engine() -> WafEngine {
        let config = Arc::new(crate::config::settings::Config {
            network: crate::config::settings::NetworkSettings::default(),
            tor: crate::config::settings::TorSettings::default(),
            security: crate::config::settings::SecuritySettings::default(),
            captcha: crate::config::settings::CaptchaSettings::default(),
            session: crate::config::settings::SessionSettings::default(),
            defense: crate::config::settings::DefenseSettings::default(),
            meta: crate::config::settings::MetaSettings::default(),
            webhook: crate::config::settings::WebhookSettings::default(),
            features: crate::config::settings::FeatureFlags::default(),
            log_format: "json".to_string(),
        });
        let webhook = Arc::new(WebhookNotifier::new(&config));
        WafEngine::try_new(webhook, vec![]).unwrap()
    }

    #[test]
    fn waf_scans() {
        let w = engine();

        assert!(w.scan("/search?q=' OR 1=1--", "URI").blocked);
        assert!(w.scan("/p?x=<script>alert(1)</script>", "URI").blocked);
        assert!(w.scan("/p?x=<img onerror=alert(1)>", "URI").blocked);
        assert!(w.scan("/../../etc/passwd", "URI").blocked);
        assert!(w.scan("/path?file=..\\..\\win\\system32", "URI").blocked);
        assert!(w.scan("/path%00.html", "URI").blocked);

        assert!(w.scan("/p?url=file:///etc/shadow", "URI").blocked);
        assert!(w.scan("/p?url=gopher://127.0.0.1:25", "URI").blocked);
        assert!(w.scan("/p?url=http://127.0.0.1/admin", "URI").blocked);
        assert!(w.scan("/p?url=http://[::1]/admin", "URI").blocked);
        assert!(w.scan("/p?url=http://192.168.1.1/secret", "URI").blocked);
        assert!(w.scan("/p?url=http://10.0.0.1/internal", "URI").blocked);
        assert!(
            w.scan("/p?url=http://169.254.169.254/latest", "URI")
                .blocked
        );
        assert!(w.scan("/p?url=http://localhost/admin", "URI").blocked);

        assert!(
            w.scan("/search?q=%252e%252e%252fetc%252fpasswd", "URI")
                .blocked
        );

        assert!(!w.scan("/", "URI").blocked);
        assert!(!w.scan("/about", "URI").blocked);
        assert!(!w.scan("/search?q=hello", "URI").blocked);
        assert!(!w.scan("/api/d?p=2&l=50", "URI").blocked);
    }
}
