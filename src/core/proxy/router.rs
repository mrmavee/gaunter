//! Request routing logic.
//!
//! Orchestrates request flow between WAF engine and challenge handlers.

use crate::security::captcha::CaptchaManager;

use crate::core::middleware::{
    EncryptedSession, RateLimiter, SESSION_COOKIE_NAME, format_set_cookie, generate_session_id,
};
use crate::core::proxy::challenge::ChallengeHandler;
use crate::core::proxy::headers::inject_security_headers;
use crate::core::proxy::response::serve_html;
use crate::core::proxy::service::RequestCtx;
use crate::features::tor::circuit;
use crate::features::webhook::{EventType, WebhookNotifier, WebhookPayload};
use crate::security::defense::DefenseMonitor;
use crate::web::ui;

use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, trace, warn};

pub struct WafRouterDeps {
    pub config: Arc<crate::config::Config>,
    pub captcha: Arc<CaptchaManager>,
    pub cookie_crypto: crate::security::crypto::CookieCrypto,
    pub defense_monitor: Arc<DefenseMonitor>,
    pub webhook: Arc<WebhookNotifier>,
    pub rate_limiter: RateLimiter,
    pub session_rate_limiter: RateLimiter,
}

pub struct WafRouter {
    pub config: Arc<crate::config::Config>,
    pub cookie_crypto: crate::security::crypto::CookieCrypto,
    pub defense_monitor: Arc<DefenseMonitor>,
    pub handler: ChallengeHandler,
    pub webhook: Arc<WebhookNotifier>,
    pub rate_limiter: RateLimiter,
    pub session_rate_limiter: RateLimiter,
}

impl WafRouter {
    #[must_use]
    pub fn new(deps: WafRouterDeps) -> Self {
        let handler = ChallengeHandler::new(
            Arc::clone(&deps.config),
            deps.captcha,
            deps.cookie_crypto.clone(),
            Arc::clone(&deps.defense_monitor),
        );
        Self {
            config: deps.config,
            cookie_crypto: deps.cookie_crypto,
            defense_monitor: deps.defense_monitor,
            handler,
            webhook: deps.webhook,
            rate_limiter: deps.rate_limiter,
            session_rate_limiter: deps.session_rate_limiter,
        }
    }

    pub async fn route(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        let is_defense = self.config.security.waf_mode == crate::config::WafMode::Defense
            || self.defense_monitor.is_defense_active();

        let is_challenged = ctx
            .circuit_id
            .as_deref()
            .is_some_and(|cid| self.defense_monitor.has_challenge(cid));

        if is_defense || is_challenged {
            return self.process_defense(session, ctx).await;
        }

        Ok(false)
    }

    async fn process_defense(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        let path = session.req_header().uri.path();
        let method = session.req_header().method.clone();
        let session_state = &ctx.session_data;

        let is_exempt = session_state.as_ref().is_some_and(|s| s.verified);

        if is_exempt {
            if path == "/captcha" || path == "/queue" {
                let mut header = ResponseHeader::build(303, None)?;
                header.insert_header("Location", "/")?;
                header.insert_header(
                    "Cache-Control",
                    "no-store, no-cache, must-revalidate, max-age=0",
                )?;
                header.insert_header("Pragma", "no-cache")?;
                header.insert_header("Expires", "0")?;
                header.insert_header("Clear-Site-Data", "\"cache\"")?;

                inject_security_headers(&mut header, &self.config)?;

                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }

            return Ok(false);
        }

        let request_uri = session.req_header().uri.to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if method == pingora::http::Method::POST
            && let Ok(Some(body)) = session.read_request_body().await
        {
            if !self.config.features.captcha_enabled {
                return self.handler.verify_access(session, ctx, &body, now).await;
            }

            let queue_ok = session_state.as_ref().is_some_and(|s| s.queue_completed);
            if !queue_ok {
                return self.handler.queue(session, ctx, &request_uri, now).await;
            }

            return self.handler.verify_captcha(session, ctx, &body, now).await;
        } else if session_state.as_ref().is_some_and(|s| s.queue_completed) {
            let show_error = session_state
                .as_ref()
                .is_some_and(|s| s.captcha_failures > 0);
            return self.handler.captcha(session, ctx, show_error).await;
        } else if let Some(sess) = session_state
            && sess.queue_started_at > 0
        {
            return self
                .process_queue(session, ctx, sess, &request_uri, now)
                .await;
        }

        self.handler.queue(session, ctx, &request_uri, now).await
    }

    async fn process_queue(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        sess: &crate::core::middleware::EncryptedSession,
        request_uri: &str,
        now: u64,
    ) -> Result<bool> {
        let waited = now.saturating_sub(sess.queue_started_at);
        let elapsed_since_active = now.saturating_sub(sess.last_active_at);

        if elapsed_since_active < 2 && waited < 5 {
            let mut reset_session = sess.clone();
            reset_session.queue_started_at = now;
            reset_session.last_active_at = now;
            let cookie_val = self
                .cookie_crypto
                .try_encrypt(&reset_session.to_bytes())
                .map_err(|e| {
                    error!("cookie encryption failed: {e}");
                    pingora::Error::new(pingora::ErrorType::InternalError)
                })?;
            let secure = !sess
                .circuit_id
                .as_deref()
                .is_some_and(|cid| cid.starts_with("i2p:"));
            let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 300, secure);

            return self
                .handler
                .queue_time_cookie(session, ctx, request_uri, 5, Some(&cookie_header))
                .await;
        }

        if waited >= 5 {
            if !self.config.features.captcha_enabled {
                return self.handler.access(session, ctx).await;
            }

            let mut new_session = sess.clone();
            new_session.queue_completed = true;
            new_session.captcha_gen_count = 1;
            new_session.last_active_at = now;
            let cookie_val = self
                .cookie_crypto
                .try_encrypt(&new_session.to_bytes())
                .map_err(|e| {
                    error!("cookie encryption failed: {e}");
                    pingora::Error::new(pingora::ErrorType::InternalError)
                })?;
            let secure = !sess
                .circuit_id
                .as_deref()
                .is_some_and(|cid| cid.starts_with("i2p:"));
            let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 300, secure);

            return self
                .handler
                .captcha_cookie(session, ctx, false, &cookie_header)
                .await;
        }

        let remaining = 5u64.saturating_sub(waited).max(1);
        let mut updated_session = sess.clone();
        updated_session.last_active_at = now;
        let cookie_val = self
            .cookie_crypto
            .try_encrypt(&updated_session.to_bytes())
            .map_err(|e| {
                error!("cookie encryption failed: {e}");
                pingora::Error::new(pingora::ErrorType::InternalError)
            })?;
        let secure = !sess
            .circuit_id
            .as_deref()
            .is_some_and(|cid| cid.starts_with("i2p:"));
        let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 300, secure);

        self.handler
            .queue_time_cookie(session, ctx, request_uri, remaining, Some(&cookie_header))
            .await
    }

    pub fn ensure_session(ctx: &RequestCtx) -> EncryptedSession {
        ctx.session_data
            .clone()
            .unwrap_or_else(|| EncryptedSession {
                session_id: generate_session_id(),
                circuit_id: ctx.circuit_id.clone(),
                created_at: ctx.request_ts,
                ..Default::default()
            })
    }

    pub fn penalize(
        &self,
        ctx: &RequestCtx,
        sess: &mut EncryptedSession,
        violation_type: &str,
        karma_points: u32,
    ) {
        match violation_type {
            "waf" => sess.waf_violations = sess.waf_violations.saturating_add(1),
            "upload" => sess.upload_violations = sess.upload_violations.saturating_add(1),
            "ratelimit" => sess.ratelimit_violations = sess.ratelimit_violations.saturating_add(1),
            _ => {}
        }

        sess.karma_total = sess.karma_total.saturating_add(karma_points);
        if let Some(cid) = ctx.circuit_id.as_ref() {
            self.defense_monitor.add_karma(cid, karma_points);
        }

        if sess.waf_violations >= 10
            || sess.upload_violations >= 10
            || sess.ratelimit_violations >= 10
            || sess.karma_total >= 100
            || violation_type == "restricted_path"
            || violation_type == "missing_circuit"
        {
            sess.blocked = true;
            sess.blocked_at = ctx.request_ts;
            sess.block_reason = match violation_type {
                "waf" => format!(
                    "WAF violations: {}, total karma: {}",
                    sess.waf_violations, sess.karma_total
                ),
                "upload" => format!(
                    "Upload violations: {}, total karma: {}",
                    sess.upload_violations, sess.karma_total
                ),
                "ratelimit" => format!(
                    "Rate limit violations: {}, total karma: {}",
                    sess.ratelimit_violations, sess.karma_total
                ),
                "restricted_path" => ctx
                    .body_block_reason
                    .clone()
                    .unwrap_or_else(|| "Restricted path violation".to_string()),
                _ => "Violation detected".to_string(),
            };

            self.defense_monitor.block_session(&sess.session_id);

            self.webhook.notify(WebhookPayload {
                event_type: EventType::SessionBlocked,
                timestamp: i64::try_from(sess.blocked_at).unwrap_or(0),
                circuit_id: ctx.circuit_id.clone(),
                severity: 5,
                message: sess.block_reason.clone(),
            });
        }
    }

    pub async fn send_block(
        &self,
        session: &mut Session,
        sess: &EncryptedSession,
        html: String,
        status_code: u16,
    ) -> Result<bool> {
        let cookie = self
            .cookie_crypto
            .try_encrypt(&sess.to_bytes())
            .ok()
            .map(|enc| {
                let secure = !sess
                    .circuit_id
                    .as_deref()
                    .is_some_and(|cid| cid.starts_with("i2p:"));
                format_set_cookie(
                    SESSION_COOKIE_NAME,
                    &enc,
                    self.config.session.expiry_secs,
                    secure,
                )
            });
        serve_html(session, &self.config, status_code, html, cookie.as_deref()).await
    }

    pub fn load_session_data(&self, session: &Session, ctx: &mut RequestCtx) {
        const PREFIX: &str = concat!("gaunter_session", "=");

        let cookie_header = session
            .req_header()
            .headers
            .get("Cookie")
            .and_then(|v| v.to_str().ok());

        if let Some(cookies) = cookie_header {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(value) = cookie.strip_prefix(PREFIX) {
                    if let Some(decrypted) = self.cookie_crypto.decrypt(value) {
                        ctx.session_data = EncryptedSession::from_bytes(
                            &decrypted,
                            self.config.session.expiry_secs,
                        );
                    }
                    break;
                }
            }
        }
    }

    pub async fn is_session_blocked(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
    ) -> Result<bool> {
        if let Some(cid) = ctx.circuit_id.as_ref()
            && self.defense_monitor.is_circuit_blocked(cid)
        {
            warn!(
                circuit = %cid,
                action = "circuit_block",
                "circuit blocked by karma"
            );

            let html = ui::error_page(
                "Access Denied",
                "Your session has been blocked. To regain access, please delete your cookies or use \"New Identity\" if using Tor Browser.",
                Some(vec![("Reason", "Security Violation")]),
                Some(&self.config),
            );
            return serve_html(session, &self.config, 400, html, None).await;
        }

        if let Some(sess) = ctx.session_data.as_ref()
            && (sess.blocked || self.defense_monitor.is_session_blocked(&sess.session_id))
        {
            warn!(
                session = %sess.session_id,
                circuit = ?ctx.circuit_id,
                reason = %sess.block_reason,
                action = "session_block",
                "session blocked: {}", sess.block_reason
            );

            let html = ui::error_page(
                "Access Denied",
                "Your session has been blocked. To regain access, please delete your cookies or use \"New Identity\" if using Tor Browser.",
                Some(vec![("Reason", "Security Violation")]),
                Some(&self.config),
            );
            return serve_html(session, &self.config, 400, html, None).await;
        }

        Ok(false)
    }

    pub fn is_flooding_circuit(&self, ctx: &mut RequestCtx) -> bool {
        let session_id = ctx.session_data.as_ref().map(|s| s.session_id.as_str());
        ctx.rate_key = circuit::rate_limit_key(ctx.circuit_id.as_deref(), session_id);

        if ctx.rate_key.is_none()
            && let Some(cid) = ctx.circuit_id.as_ref()
        {
            ctx.rate_key = Some(cid.clone());
        }

        if let Some(circuit) = ctx.circuit_id.as_ref() {
            trace!(circuit_id = %circuit, "Request from Tor circuit");

            if ctx.session_data.is_none() {
                self.defense_monitor.record_unverified();
            }

            if self.defense_monitor.is_flooding(circuit) {
                info!(circuit = %circuit, action = "challenge", "circuit flood: challenge required");
                self.defense_monitor.challenge_circuit(circuit);
                self.defense_monitor.add_karma(circuit, 10);

                self.webhook.notify(WebhookPayload {
                    event_type: EventType::CircuitChallenged,
                    timestamp: i64::try_from(ctx.request_ts).unwrap_or(0),
                    circuit_id: Some(circuit.clone()),
                    severity: 4,
                    message: format!("Circuit challenged due to flood: {circuit}"),
                });

                return true;
            }
        }
        false
    }

    pub async fn is_restricted_path(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        path: &str,
    ) -> Result<bool> {
        if !self.config.security.restricted_paths.contains(path) {
            return Ok(false);
        }

        let silent = path == "/server-status";
        let karma_penalty = if silent { 300 } else { 100 };

        let mut sess = Self::ensure_session(ctx);
        ctx.body_block_reason = Some(format!("Restricted: {path}"));
        self.penalize(ctx, &mut sess, "restricted_path", karma_penalty);

        ctx.session_data = Some(sess.clone());
        info!(path = %path, circuit = ?ctx.circuit_id, session = %sess.session_id, action = "restricted_path_block", "restricted path triggered");

        let html = ui::block_page("restricted_path", &sess.session_id, &self.config);

        self.send_block(session, &sess, html, 400).await
    }

    pub async fn is_excessive_karma(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<bool> {
        let Some(cid) = ctx.circuit_id.as_ref() else {
            return Ok(false);
        };

        if !self.defense_monitor.is_malicious(cid) {
            return Ok(false);
        }

        let mut sess = Self::ensure_session(ctx);
        ctx.body_block_reason = Some(format!("Karma threshold exceeded for circuit {cid}"));
        self.penalize(ctx, &mut sess, "restricted_path", 0);

        info!(circuit = %cid, session = %sess.session_id, action = "karma_block", "excessive karma: block");

        let html = ui::block_page("karma", &sess.session_id, &self.config);

        self.send_block(session, &sess, html, 400).await
    }

    pub async fn check_circuit(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        if ctx.circuit_id.is_some() {
            return Ok(false);
        }

        warn!("request rejected: missing circuit id");
        let html = ui::block_page("missing_circuit", "direct", &self.config);
        serve_html(session, &self.config, 400, html, None).await
    }

    pub async fn verify_security(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<bool> {
        let path = session.req_header().uri.path();
        let path_owned = path.to_string();

        if self.is_restricted_path(session, ctx, &path_owned).await? {
            return Ok(true);
        }

        if self.is_excessive_karma(session, ctx).await? {
            return Ok(true);
        }

        if self.check_circuit(session, ctx).await? {
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn verify_length(&self, session: &mut Session, ctx: &mut RequestCtx) -> Result<bool> {
        if let Some(content_length) = session
            .req_header()
            .headers
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&len| len > self.config.security.client_max_body_size)
        {
            let mut sess = Self::ensure_session(ctx);

            warn!(
                circuit = ?ctx.circuit_id,
                session = %sess.session_id,
                size = content_length,
                limit = self.config.security.client_max_body_size,
                violations = sess.upload_violations.saturating_add(1),
                karma = sess.karma_total.saturating_add(5),
                action = "size_block",
                "body too large"
            );

            ctx.is_error = true;
            self.penalize(ctx, &mut sess, "upload", 5);

            if sess.upload_violations >= 10
                && let Some(cid) = &ctx.circuit_id
            {
                info!(circuit = %cid, action = "flood_block", "upload flood");
            }

            let html = ui::error_page(
                "Request Too Large",
                "The request size exceeds the limit.",
                None,
                Some(&self.config),
            );

            self.send_block(session, &sess, html, 413).await?;
            return Ok(true);
        }
        Ok(false)
    }

    pub async fn is_rate_limited(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        if let Some(key) = ctx.rate_key.as_ref()
            && !self.rate_limiter.check_and_record(key)
        {
            let mut sess = Self::ensure_session(ctx);

            warn!(
                circuit = %key,
                session = %sess.session_id,
                violations = sess.ratelimit_violations.saturating_add(1),
                karma = sess.karma_total.saturating_add(3),
                action = "rate_limit",
                "rate limit exceeded"
            );

            self.penalize(ctx, &mut sess, "ratelimit", 3);

            if sess.ratelimit_violations >= 10
                && let Some(cid) = &ctx.circuit_id
            {
                info!(circuit = %cid, action = "limit_block", "persistent rate limit: block");
            }

            if sess.blocked {
                let html = ui::error_page(
                    "Access Denied",
                    "Your session has been permanently blocked due to excessive rate limit violations.",
                    None,
                    Some(&self.config),
                );
                return self.send_block(session, &sess, html, 400).await;
            }

            self.webhook.notify(WebhookPayload {
                event_type: EventType::RateLimitExceeded,
                timestamp: i64::try_from(ctx.request_ts).unwrap_or(0),
                circuit_id: ctx.circuit_id.clone(),
                severity: 3,
                message: format!("Circuit rate limit exceeded for {key}"),
            });

            sess.queue_started_at = ctx.request_ts;
            sess.verified = false;
            let cookie = self
                .handler
                .session_cookie(&sess, self.config.session.expiry_secs)?;

            let uri = session.req_header().uri.to_string();

            return self
                .handler
                .queue_time_cookie(session, ctx, &uri, 5, Some(&cookie))
                .await;
        }
        Ok(false)
    }

    pub async fn mitigate_flood(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<bool> {
        let mut sess = Self::ensure_session(ctx);
        self.penalize(ctx, &mut sess, "ratelimit", 5);
        ctx.session_data = Some(sess.clone());

        if sess.blocked {
            let html = ui::error_page(
                "Access Denied",
                "Your session has been permanently blocked due to extreme flooding.",
                None,
                Some(&self.config),
            );
            return self.send_block(session, &sess, html, 400).await;
        }

        sess.queue_started_at = ctx.request_ts;
        sess.verified = false;
        let cookie = self
            .handler
            .session_cookie(&sess, self.config.session.expiry_secs)?;

        let uri = session.req_header().uri.to_string();
        self.handler
            .queue_time_cookie(session, ctx, &uri, 5, Some(&cookie))
            .await
    }
}
