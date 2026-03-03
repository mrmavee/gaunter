//! Proxy service logic.
//!
//! Handles the core proxy logic including request filtering, WAF integration,
//! and upstream forwarding.

use crate::config::Config;
use crate::core::middleware::{EncryptedSession, RateLimiter};
use crate::core::proxy::headers::{extract_circuit_id, inject_security_headers, is_static_asset};
use crate::core::proxy::response::handle_health_check;
use crate::core::proxy::router::WafRouter;
use crate::features::tor::control::TorControl;
use crate::features::webhook::{EventType, WebhookNotifier, WebhookPayload};
use crate::security::captcha::CaptchaManager;
use crate::security::crypto::CookieCrypto;
use crate::security::defense::{DefenseMonitor, TrackMode};
use crate::security::waf::WafEngine;
use crate::web::ui;
use async_trait::async_trait;
use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, trace, warn};

#[derive(Default)]
pub struct RequestCtx {
    pub circuit_id: Option<String>,
    pub session_data: Option<EncryptedSession>,
    pub rate_key: Option<String>,
    pub set_session_cookie: Option<String>,
    pub body_buffer: Vec<u8>,
    pub body_block_reason: Option<String>,
    pub is_error: bool,
    pub scan_flags: ScanFlags,
    pub request_ts: u64,
}

#[derive(Default)]
pub struct ScanFlags {
    pub skip_body_scan: bool,
    pub body_blocked: bool,
}

/// Main proxy implementation.
pub struct GaunterProxy {
    config: Arc<Config>,
    defense_monitor: Arc<DefenseMonitor>,
    webhook: Arc<WebhookNotifier>,
    waf_engine: Arc<WafEngine>,
    tor_control: Option<TorControl>,
    waf_router: WafRouter,
}

impl GaunterProxy {
    /// Creates a new proxy instance.
    pub fn new(
        config: Arc<Config>,
        rate_limiter: RateLimiter,
        session_rate_limiter: RateLimiter,
        defense_monitor: Arc<DefenseMonitor>,
        webhook: Arc<WebhookNotifier>,
        captcha: Arc<CaptchaManager>,
        waf_engine: Arc<WafEngine>,
    ) -> Self {
        let cookie_crypto = CookieCrypto::new(&config.session.secret);
        let tor_control = config
            .tor
            .control_addr
            .map(|addr| TorControl::new(addr, config.tor.control_password.clone()));

        let waf_router = WafRouter::new(crate::core::proxy::router::WafRouterDeps {
            config: Arc::clone(&config),
            captcha,
            cookie_crypto,
            defense_monitor: Arc::clone(&defense_monitor),
            webhook: Arc::clone(&webhook),
            rate_limiter,
            session_rate_limiter,
        });

        Self {
            config,
            defense_monitor,
            webhook,
            waf_engine,
            tor_control,
            waf_router,
        }
    }

    async fn update_defense(&self) {
        if let Some(tor) = &self.tor_control
            && self.defense_monitor.check_pow_expiry()
        {
            match tor.disable_pow().await {
                Ok(()) => {
                    self.defense_monitor.disable_pow();
                    let msg = "pow disabled: recovery".to_string();
                    info!(action = "defense_off", "{msg}");
                    self.webhook.notify(WebhookPayload {
                        event_type: EventType::DefenseModeDeactivated,
                        timestamp: i64::try_from(
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        )
                        .unwrap_or(0),
                        circuit_id: None,
                        severity: 2,
                        message: msg,
                    });
                }
                Err(e) => warn!(error = %e, "failed to disable pow"),
            }
        }

        if self.defense_monitor.trigger_defense() {
            let msg = "defense mode on".to_string();
            warn!(action = "defense_on", "{msg}");
            self.webhook.notify(WebhookPayload {
                event_type: EventType::DefenseModeActivated,
                timestamp: i64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                )
                .unwrap_or(0),
                circuit_id: None,
                severity: 3,
                message: msg,
            });
        }

        if let Some(tor) = &self.tor_control
            && let Some(effort) = self.defense_monitor.detect_pow_need()
        {
            match tor.enable_pow("gaunter-service", effort).await {
                Ok(()) => {
                    self.defense_monitor.enable_pow();
                    let msg = format!("pow enabled at effort {effort}");
                    warn!(action = "defense_escalation", "{msg}");
                    self.webhook.notify(WebhookPayload {
                        event_type: EventType::DefenseModeActivated,
                        timestamp: i64::try_from(
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        )
                        .unwrap_or(0),
                        circuit_id: None,
                        severity: 4,
                        message: msg,
                    });
                }
                Err(e) => warn!(error = %e, "failed to enable pow"),
            }
        }
    }

    async fn inspect_waf(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        let uri = session.req_header().uri.to_string();
        let waf_result = self.waf_engine.scan(&uri, "URI");

        if waf_result.blocked {
            let method = session.req_header().method.as_str();
            let path = session.req_header().uri.path();

            let mut sess = WafRouter::ensure_session(ctx);
            let reason = waf_result.reason.as_deref().unwrap_or("unknown");

            warn!(
                method = %method,
                path = %path,
                circuit = ?ctx.circuit_id,
                session = %sess.session_id,
                violations = sess.waf_violations.saturating_add(1),
                karma = sess.karma_total.saturating_add(10),
                rule = reason,
                action = "waf_block",
                "waf block: {}", reason
            );

            self.waf_router.penalize(ctx, &mut sess, "waf", 10);

            let html = ui::block_page("waf", &sess.session_id, &self.config);
            return self.waf_router.send_block(session, &sess, html, 400).await;
        }

        if self.waf_router.route(session, ctx).await? {
            return Ok(true);
        }

        Ok(false)
    }
}

#[async_trait]
impl ProxyHttp for GaunterProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            request_ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ..RequestCtx::default()
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if handle_health_check(session, &self.config).await? {
            return Ok(true);
        }

        ctx.circuit_id = extract_circuit_id(session);
        self.waf_router.load_session_data(session, ctx);

        if !is_static_asset(session) && self.waf_router.is_flooding_circuit(ctx) {
            return self.waf_router.mitigate_flood(session, ctx).await;
        }

        self.update_defense().await;

        if self.waf_router.is_session_blocked(session, ctx).await? {
            return Ok(true);
        }

        if let Some(cid) = ctx.circuit_id.as_ref()
            && self.defense_monitor.has_challenge(cid)
            && !ctx.session_data.as_ref().is_some_and(|s| s.verified)
        {
            info!(
                circuit = %cid,
                action = "challenge_redirect",
                "redirecting to challenge"
            );
            if self.waf_router.route(session, ctx).await? {
                return Ok(true);
            }
        }

        if self.waf_router.verify_length(session, ctx).await? {
            return Ok(true);
        }

        if self.config.features.waf_body_scan_enabled
            && let Some(len) = session
                .req_header()
                .headers
                .get("Content-Length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
        {
            let cap = len.min(self.config.security.waf_body_scan_max_size);
            if cap > 0 {
                ctx.body_buffer.reserve(cap);
            }
        }

        if session
            .req_header()
            .headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("multipart/form-data"))
        {
            trace!("multipart detected: skipping scan");
            ctx.scan_flags.skip_body_scan = true;
        }

        if self.waf_router.verify_security(session, ctx).await? {
            return Ok(true);
        }

        let is_static = is_static_asset(session);
        if !is_static {
            if self.waf_router.is_rate_limited(session, ctx).await? {
                return Ok(true);
            }

            if let Some(enc_session) = ctx.session_data.as_ref()
                && !self
                    .waf_router
                    .session_rate_limiter
                    .check_and_record(&enc_session.session_id)
            {
                if let Some(cid) = ctx.circuit_id.as_ref() {
                    self.defense_monitor.add_karma(cid, 3);
                }

                warn!(session = %enc_session.session_id, action = "session_rate_limit", "session rate limit exceeded");
                let uri = session.req_header().uri.to_string();

                return self
                    .waf_router
                    .handler
                    .queue(session, ctx, &uri, ctx.request_ts)
                    .await;
            }
        }

        self.inspect_waf(session, ctx).await
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if !self.config.features.waf_body_scan_enabled || ctx.scan_flags.skip_body_scan {
            return Ok(());
        }

        if let Some(b) = body.take() {
            if ctx.body_buffer.is_empty() && !b.is_empty() {
                let peek_len = b.len().min(512);
                if let Some(slice) = b.get(..peek_len)
                    && let Some(mime) = crate::security::waf::signatures::detect_safe_mime(slice)
                {
                    trace!(mime = %mime, "safe mime detected: skipping scan");
                    ctx.scan_flags.skip_body_scan = true;
                    *body = Some(b);
                    return Ok(());
                }
            }

            if ctx.body_buffer.len() + b.len() > self.config.security.waf_body_scan_max_size {
                warn!(
                    limit = self.config.security.waf_body_scan_max_size,
                    action = "inspect_block",
                    "body exceeds scan limit"
                );
                return Err(pingora::Error::new(pingora::ErrorType::Custom(
                    "Request body too large for inspection",
                )));
            }
            ctx.body_buffer.extend_from_slice(&b);

            if !end_of_stream {
                *body = None;
            }
        }

        if end_of_stream && !ctx.body_buffer.is_empty() {
            let Ok(body_str) = String::from_utf8(ctx.body_buffer.clone()) else {
                warn!(
                    circuit = ?ctx.circuit_id,
                    action = "malformed_block",
                    "invalid utf-8: block"
                );
                ctx.scan_flags.body_blocked = true;
                ctx.body_block_reason = Some("WAF_MALFORMED_UTF8".to_string());
                return Err(pingora::Error::new(pingora::ErrorType::Custom(
                    "body_waf_blocked",
                )));
            };

            let waf_engine = Arc::clone(&self.waf_engine);

            let waf_result =
                tokio::task::spawn_blocking(move || waf_engine.scan(&body_str, "Body"))
                    .await
                    .unwrap_or(crate::security::waf::WafResult::safe());

            if waf_result.blocked {
                warn!(
                    circuit = ?ctx.circuit_id,
                    rule = waf_result.reason.as_deref().unwrap_or("unknown"),
                    action = "waf_body_block",
                    "waf body block: {}", waf_result.reason.as_deref().unwrap_or("unknown")
                );

                ctx.scan_flags.body_blocked = true;
                ctx.body_block_reason = waf_result.reason;

                return Err(pingora::Error::new(pingora::ErrorType::Custom(
                    "body_waf_blocked",
                )));
            }

            *body = Some(bytes::Bytes::from(std::mem::take(&mut ctx.body_buffer)));
        }

        Ok(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let addr = self
            .config
            .network
            .backend_url
            .strip_prefix("http://")
            .or_else(|| self.config.network.backend_url.strip_prefix("https://"))
            .unwrap_or(&self.config.network.backend_url);

        let peer = Box::new(HttpPeer::new(addr, false, String::new()));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.remove_header("X-Forwarded-For");
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        _e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        if ctx.scan_flags.body_blocked {
            let mut sess = WafRouter::ensure_session(ctx);
            let reason = ctx.body_block_reason.as_deref().unwrap_or("unknown");

            warn!(
                circuit = ?ctx.circuit_id,
                session = %sess.session_id,
                violations = sess.waf_violations.saturating_add(1),
                karma = sess.karma_total.saturating_add(10),
                rule = reason,
                action = "waf_body_block",
                "waf body block: {}", reason
            );

            self.waf_router.penalize(ctx, &mut sess, "waf", 10);

            let html = ui::block_page("Bad Request", &sess.session_id, &self.config);
            let _ = self.waf_router.send_block(session, &sess, html, 400).await;

            return FailToProxy {
                error_code: 400,
                can_reuse_downstream: false,
            };
        }

        let code = match _e.esource() {
            pingora::ErrorSource::Upstream => 502,
            pingora::ErrorSource::Downstream => 400,
            _ => 500,
        };

        if code > 0 {
            let (title, desc) = match code {
                502 => (
                    "Bad Gateway",
                    "The server encountered a temporary error and could not complete your request.",
                ),
                400 => (
                    "Bad Request",
                    "The server cannot process the request due to a client error.",
                ),
                _ => (
                    "Internal Server Error",
                    "The server encountered an unexpected condition that prevented it from fulfilling the request.",
                ),
            };

            let html = ui::error_page(title, desc, None, Some(&self.config));

            if let Ok(mut header) = ResponseHeader::build(code, None) {
                let _ = header.insert_header("Content-Type", "text/html; charset=utf-8");
                let _ = header.insert_header("Content-Length", html.len().to_string());
                let _ = header.insert_header("Cache-Control", "private, no-store");
                let _ = header.insert_header("Connection", "close");

                let _ = inject_security_headers(&mut header, &self.config);

                let _ = session.write_response_header(Box::new(header), false).await;
                let _ = session
                    .write_response_body(Some(bytes::Bytes::from(html)), true)
                    .await;
            }
        }

        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    fn suppress_error_log(
        &self,
        _session: &Session,
        ctx: &Self::CTX,
        _error: &pingora::Error,
    ) -> bool {
        ctx.scan_flags.body_blocked
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let status = upstream_response.status.as_u16();
        if status >= 500 || status == 403 {
            ctx.is_error = true;
        }

        if let Some(cookie) = ctx.set_session_cookie.as_ref() {
            upstream_response.insert_header("Set-Cookie", cookie)?;
        }

        inject_security_headers(upstream_response, &self.config)?;

        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = session.response_written().map_or(0, |r| r.status.as_u16());

        let mode = if let Some(sess) = ctx.session_data.as_ref()
            && (sess.blocked || self.defense_monitor.is_session_blocked(&sess.session_id))
        {
            TrackMode::LocalOnly
        } else {
            TrackMode::GlobalAndLocal
        };

        if mode == TrackMode::GlobalAndLocal && ctx.session_data.is_none() {
            self.defense_monitor.record_unverified();
        }

        self.defense_monitor
            .record_request(ctx.circuit_id.as_deref(), ctx.is_error, mode);

        if let Some(cid) = ctx.circuit_id.as_ref() {
            let karma_points = match status {
                400 => 2,
                404 => 1,
                403 => 5,
                429 => 10,
                500..=599 => 3,
                _ => 0,
            };

            if karma_points > 0 {
                let total = self.defense_monitor.add_karma(cid, karma_points);
                if self.defense_monitor.is_malicious(cid) {
                    info!(circuit = %cid, karma = total, action = "karma_eviction", "karma threshold met: circuit eviction");
                }
            }
        }

        let circuit = ctx.circuit_id.as_deref().unwrap_or("direct");
        trace!(circuit = %circuit, status = status, "request complete");

        if status >= 400 {
            let path = session.req_header().uri.path();
            warn!(circuit = %circuit, status = status, path = %path, "request error");
        }
    }
}
