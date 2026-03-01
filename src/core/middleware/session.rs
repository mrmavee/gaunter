//! Session state management.
//!
//! Handles serialization, encryption, and validation of client session data.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default)]
/// Encrypted session data.
pub struct EncryptedSession {
    /// Session ID.
    pub session_id: String,
    /// Circuit ID.
    pub circuit_id: Option<String>,
    /// Creation time.
    pub created_at: u64,
    /// Queue start.
    pub queue_started_at: u64,
    /// Queue status.
    pub queue_completed: bool,
    /// CAPTCHA failures.
    pub captcha_failures: u8,
    /// CAPTCHA count.
    pub captcha_gen_count: u8,
    /// Verification status.
    pub verified: bool,
    /// Verification time.
    pub verified_at: u64,
    /// Last active.
    pub last_active_at: u64,
    /// Block status.
    pub blocked: bool,
    /// Block time.
    pub blocked_at: u64,
    /// Block reason.
    pub block_reason: String,
    /// WAF violations.
    pub waf_violations: u8,
    /// Upload violations.
    pub upload_violations: u8,
    /// Rate limit violations.
    pub ratelimit_violations: u8,
    /// Karma total.
    pub karma_total: u32,
}

impl EncryptedSession {
    #[must_use]
    /// Serializes session.
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.session_id,
            self.circuit_id.as_deref().unwrap_or("").replace('|', "_"),
            self.created_at,
            self.queue_started_at,
            u8::from(self.queue_completed),
            self.captcha_failures,
            self.captcha_gen_count,
            u8::from(self.verified),
            self.verified_at,
            self.last_active_at,
            u8::from(self.blocked),
            self.blocked_at,
            self.block_reason.replace('|', "_"),
            self.waf_violations,
            self.upload_violations,
            self.ratelimit_violations,
            self.karma_total
        )
        .into_bytes()
    }

    #[must_use]
    /// Deserializes session.
    pub fn from_bytes(data: &[u8], expiry_secs: u64) -> Option<Self> {
        let s = std::str::from_utf8(data).ok()?;
        let parts: Vec<&str> = s.split('|').collect();

        if parts.len() < 8 || parts.len() > 20 {
            return None;
        }

        let created_at: u64 = parts.get(2)?.parse().ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

        if now.saturating_sub(created_at) > expiry_secs {
            return None;
        }

        let verified_at = parts.get(8).and_then(|&s| s.parse().ok()).unwrap_or(0);
        let last_active_at = parts.get(9).and_then(|&s| s.parse().ok()).unwrap_or(0);
        let blocked = parts.get(10).is_some_and(|&s| s == "1");
        let blocked_at = parts.get(11).and_then(|&s| s.parse().ok()).unwrap_or(0);
        let block_reason = parts.get(12).map(ToString::to_string).unwrap_or_default();
        let waf_violations = parts.get(13).and_then(|&s| s.parse().ok()).unwrap_or(0);
        let upload_violations = parts.get(14).and_then(|&s| s.parse().ok()).unwrap_or(0);
        let ratelimit_violations = parts.get(15).and_then(|&s| s.parse().ok()).unwrap_or(0);
        let karma_total = parts.get(16).and_then(|&s| s.parse().ok()).unwrap_or(0);

        Some(Self {
            session_id: parts.first()?.to_string(),
            circuit_id: parts
                .get(1)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string),
            created_at,
            queue_started_at: parts.get(3)?.parse().ok()?,
            queue_completed: parts.get(4)? == &"1",
            captcha_failures: parts.get(5)?.parse().ok()?,
            captcha_gen_count: parts.get(6)?.parse().ok()?,
            verified: parts.get(7)? == &"1",
            verified_at,
            last_active_at,
            blocked,
            blocked_at,
            block_reason,
            waf_violations,
            upload_violations,
            ratelimit_violations,
            karma_total,
        })
    }
}

#[must_use]
pub fn generate_session_id() -> String {
    let random_bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

#[must_use]
pub fn format_set_cookie(name: &str, value: &str, max_age: u64, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("{name}={value}; HttpOnly{secure_flag}; SameSite=Strict; Path=/; Max-Age={max_age}")
}

pub const SESSION_COOKIE_NAME: &str = "gaunter_session";

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn session_serialization() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let s = EncryptedSession {
            session_id: "session_id".to_string(),
            circuit_id: Some("fd87::1".to_string()),
            created_at: now,
            queue_started_at: 100,
            queue_completed: true,
            captcha_failures: 3,
            captcha_gen_count: 5,
            verified: true,
            verified_at: 999,
            last_active_at: 1000,
            blocked: true,
            blocked_at: 500,
            block_reason: "violation".to_string(),
            waf_violations: 7,
            upload_violations: 2,
            ratelimit_violations: 4,
            karma_total: 150,
        };

        let b = s.to_bytes();
        let r = EncryptedSession::from_bytes(&b, 3600).unwrap();
        assert_eq!(r.session_id, "session_id");
        assert_eq!(r.circuit_id.as_deref(), Some("fd87::1"));
        assert!(r.queue_completed);
        assert_eq!(r.captcha_failures, 3);
        assert_eq!(r.captcha_gen_count, 5);
        assert!(r.verified);
        assert!(r.blocked);
        assert_eq!(r.waf_violations, 7);
        assert_eq!(r.upload_violations, 2);
        assert_eq!(r.ratelimit_violations, 4);
        assert_eq!(r.karma_total, 150);

        let old = EncryptedSession {
            created_at: 1_000_000,
            ..Default::default()
        };
        assert!(EncryptedSession::from_bytes(&old.to_bytes(), 3600).is_none());

        assert!(EncryptedSession::from_bytes(b"a|b", 3600).is_none());
        assert!(EncryptedSession::from_bytes(b"", 3600).is_none());

        let big = "a|".repeat(30);
        assert!(EncryptedSession::from_bytes(big.as_bytes(), 3600).is_none());

        let piped = EncryptedSession {
            session_id: "piped".to_string(),
            block_reason: "pipe|inject".to_string(),
            created_at: now,
            ..Default::default()
        };
        let r_p = EncryptedSession::from_bytes(&piped.to_bytes(), 3600).unwrap();
        assert!(!r_p.block_reason.contains('|'));

        let no_cid = EncryptedSession {
            session_id: "no_circuit".to_string(),
            circuit_id: None,
            created_at: now,
            ..Default::default()
        };
        let r_nc = EncryptedSession::from_bytes(&no_cid.to_bytes(), 3600).unwrap();
        assert!(r_nc.circuit_id.is_none());
    }
}
