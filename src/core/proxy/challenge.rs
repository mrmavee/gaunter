//! Challenge handling logic.
//!
//! Manages CAPTCHA generation, validation, and queue page serving.

use crate::config::Config;
use crate::core::middleware::{
    EncryptedSession, SESSION_COOKIE_NAME, format_set_cookie, generate_session_id,
};
use crate::core::proxy::response::{parse_form, serve_html, serve_redirect};
use crate::core::proxy::service::RequestCtx;

use crate::security::captcha::CaptchaManager;
use crate::security::crypto::CookieCrypto;
use crate::security::defense::DefenseMonitor;
use crate::web::ui;
use pingora::Result;
use pingora::proxy::Session;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

pub struct ChallengeHandler {
    pub config: Arc<Config>,
    pub captcha: Arc<CaptchaManager>,
    pub cookie_crypto: CookieCrypto,

    pub defense_monitor: Arc<DefenseMonitor>,
}

impl ChallengeHandler {
    #[must_use]
    pub const fn new(
        config: Arc<Config>,
        captcha: Arc<CaptchaManager>,
        cookie_crypto: CookieCrypto,

        defense_monitor: Arc<DefenseMonitor>,
    ) -> Self {
        Self {
            config,
            captcha,
            cookie_crypto,

            defense_monitor,
        }
    }

    pub fn session_cookie(&self, session: &EncryptedSession, max_age: u64) -> Result<String> {
        let cookie_val = self
            .cookie_crypto
            .try_encrypt(&session.to_bytes())
            .map_err(|e| {
                error!("cookie encryption failed: {e}");
                pingora::Error::new(pingora::ErrorType::InternalError)
            })?;
        let secure = !session
            .circuit_id
            .as_deref()
            .is_some_and(|cid| cid.starts_with("i2p:"));
        Ok(format_set_cookie(
            SESSION_COOKIE_NAME,
            &cookie_val,
            max_age,
            secure,
        ))
    }

    pub async fn queue(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        target_url: &str,
        now: u64,
    ) -> Result<bool> {
        debug!(circuit = ?ctx.circuit_id, "queue page served");
        let new_session = EncryptedSession {
            session_id: generate_session_id(),
            circuit_id: ctx.circuit_id.clone(),
            created_at: now,
            queue_started_at: now,
            queue_completed: false,
            captcha_failures: 0,
            captcha_gen_count: 0,
            verified: false,
            verified_at: 0,
            last_active_at: now,
            blocked: false,
            blocked_at: 0,
            block_reason: String::new(),
            waf_violations: 0,
            upload_violations: 0,
            ratelimit_violations: 0,
            karma_total: 0,
        };
        let cookie_header = self.session_cookie(&new_session, 300)?;
        let html = ui::queue_page(5, &new_session.session_id, target_url, &self.config);
        serve_html(session, &self.config, 200, html, Some(&cookie_header)).await
    }

    pub async fn queue_time(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        target_url: &str,
        remaining: u64,
    ) -> Result<bool> {
        self.queue_time_cookie(session, ctx, target_url, remaining, None)
            .await
    }

    pub async fn queue_time_cookie(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        target_url: &str,
        remaining: u64,
        cookie_header: Option<&str>,
    ) -> Result<bool> {
        debug!(circuit = ?ctx.circuit_id, remaining = remaining, "queueing: {remaining}s");
        let session_id = ctx
            .session_data
            .as_ref()
            .map_or("unknown", |s| s.session_id.as_str());
        let html = ui::queue_page(remaining, session_id, target_url, &self.config);
        serve_html(session, &self.config, 200, html, cookie_header).await
    }

    pub async fn captcha(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        show_error: bool,
    ) -> Result<bool> {
        debug!(circuit = ?ctx.circuit_id, "captcha served");

        let mut session_data = ctx.session_data.clone().unwrap_or_default();

        if let Some(remaining) = Self::can_bypass_queue(&session_data) {
            warn!(
                circuit = ?ctx.circuit_id,
                remaining = remaining,
                action = "queue_bypass",
                "queue bypass blocked"
            );
            return self.queue_time(session, ctx, "/", remaining).await;
        }

        session_data.captcha_gen_count += 1;

        if session_data.captcha_gen_count > self.config.captcha.gen_limit {
            return self.limit_exceeded(session, ctx).await;
        }

        let cookie_header = self.session_cookie(&session_data, 300)?;
        self.gen_captcha(session, show_error, &cookie_header).await
    }

    fn can_bypass_queue(session_data: &EncryptedSession) -> Option<u64> {
        const REQUIRED_WAIT: u64 = 5;

        if session_data.queue_started_at == 0 {
            return None;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now < session_data.queue_started_at + REQUIRED_WAIT {
            let remaining = (session_data.queue_started_at + REQUIRED_WAIT).saturating_sub(now);
            Some(remaining.max(1))
        } else {
            None
        }
    }

    async fn limit_exceeded(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        let mut sess = ctx
            .session_data
            .clone()
            .unwrap_or_else(|| EncryptedSession {
                session_id: generate_session_id(),
                circuit_id: ctx.circuit_id.clone(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                ..Default::default()
            });

        sess.blocked = true;
        sess.blocked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        sess.block_reason = "CAPTCHA generation limit exceeded".to_string();
        sess.karma_total = sess.karma_total.saturating_add(100);

        self.defense_monitor.block_session(&sess.session_id);

        warn!(
            circuit = ?ctx.circuit_id,
            session = %sess.session_id,
            action = "session_block",
            "captcha limit met: block"
        );

        let html = ui::block_page("captcha", &sess.session_id, &self.config);

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

        serve_html(session, &self.config, 400, html, cookie.as_deref()).await
    }

    async fn gen_captcha(
        &self,
        session: &mut Session,
        show_error: bool,
        cookie_header: &str,
    ) -> Result<bool> {
        let captcha = Arc::clone(&self.captcha);
        let config = Arc::clone(&self.config);
        let cookie = cookie_header.to_string();

        let res = tokio::task::spawn_blocking(move || captcha.generate()).await;

        match res {
            Ok(Ok((id, img, positions))) => {
                let html = ui::captcha_page(
                    &id,
                    &img,
                    config.captcha.ttl,
                    show_error,
                    &positions,
                    &config,
                );
                serve_html(session, &self.config, 200, html, Some(&cookie)).await
            }
            Ok(Err(e)) => self.captcha_error(session, &e.to_string()).await,
            Err(e) => self.captcha_panic(session, &e.to_string()).await,
        }
    }

    async fn captcha_error(&self, session: &mut Session, error: &str) -> Result<bool> {
        let ref_id = generate_session_id();
        error!(ref_id = %ref_id, error = %error, "captcha generation failed");
        let html = ui::error_page(
            "Verification Error",
            "Unable to generate security challenge. Please reload the page.",
            Some(vec![("Error ID", &ref_id)]),
            Some(&self.config),
        );
        serve_html(session, &self.config, 500, html, None).await
    }

    async fn captcha_panic(&self, session: &mut Session, error: &str) -> Result<bool> {
        let ref_id = generate_session_id();
        error!(ref_id = %ref_id, error = %error, "captcha task panic");
        let html = ui::error_page(
            "System Error",
            "A temporary system error occurred.",
            Some(vec![("Error ID", &ref_id)]),
            Some(&self.config),
        );
        serve_html(session, &self.config, 500, html, None).await
    }

    pub async fn captcha_cookie(
        &self,
        session: &mut Session,
        _ctx: &RequestCtx,
        show_error: bool,
        cookie_header: &str,
    ) -> Result<bool> {
        debug!("queue done: serving captcha");
        self.gen_captcha(session, show_error, cookie_header).await
    }

    pub async fn access(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        debug!(circuit = ?ctx.circuit_id, "access page served");

        let default_session = EncryptedSession::default();
        let session_ref = ctx.session_data.as_ref().unwrap_or(&default_session);

        let cookie_header = self.session_cookie(session_ref, 300)?;

        let token = self
            .captcha
            .create_token(&session_ref.session_id.to_uppercase())
            .map_err(|e| {
                error!("token creation failed: {e}");
                pingora::Error::new(pingora::ErrorType::InternalError)
            })?;

        let html = ui::access_page(&token, &self.config);
        serve_html(session, &self.config, 200, html, Some(&cookie_header)).await
    }

    pub async fn verify_access(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        body: &[u8],
        now: u64,
    ) -> Result<bool> {
        let (token, _) = parse_form(body);
        let session_id = ctx
            .session_data
            .as_ref()
            .map_or("unknown", |s| s.session_id.as_str());

        if self.captcha.verify(&token, session_id) {
            info!(
                circuit = ?ctx.circuit_id,
                session = ?session_id,
                "access verified: click"
            );

            if let Some(cid) = ctx.circuit_id.as_ref() {
                self.defense_monitor.resolve_challenge(cid);
            }

            let uri = session.req_header().uri.to_string();
            let new_session = Self::verified_session(ctx, now);
            let cookie_header = self.session_cookie(&new_session, 3600)?;
            serve_redirect(session, &self.config, &uri, Some(&cookie_header), true).await
        } else {
            warn!(
                circuit = ?ctx.circuit_id,
                session = ?session_id,
                "verification failed: invalid token"
            );
            let uri = session.req_header().uri.to_string();
            serve_redirect(session, &self.config, &uri, None, true).await
        }
    }

    pub async fn verify_captcha(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        body: &[u8],
        now: u64,
    ) -> Result<bool> {
        let (token, answer) = parse_form(body);

        if self.captcha.verify(&token, &answer) {
            info!(
                circuit = ?ctx.circuit_id,
                session = ?ctx.session_data.as_ref().map(|s| &s.session_id),
                "captcha verified"
            );

            if let Some(cid) = ctx.circuit_id.as_ref() {
                self.defense_monitor.resolve_challenge(cid);
            }

            let uri = session.req_header().uri.to_string();
            let new_session = Self::verified_session(ctx, now);
            let cookie_header = self.session_cookie(&new_session, 3600)?;
            serve_redirect(session, &self.config, &uri, Some(&cookie_header), true).await
        } else {
            self.captcha_fail(session, ctx, now).await
        }
    }

    fn verified_session(ctx: &RequestCtx, now: u64) -> EncryptedSession {
        let prev = ctx.session_data.as_ref();
        EncryptedSession {
            session_id: generate_session_id(),
            circuit_id: ctx.circuit_id.clone(),
            created_at: now,
            queue_started_at: 0,
            queue_completed: true,
            captcha_failures: 0,
            captcha_gen_count: 0,
            verified: true,
            verified_at: now,
            last_active_at: now,
            blocked: prev.is_some_and(|s| s.blocked),
            blocked_at: prev.map_or(0, |s| s.blocked_at),
            block_reason: prev.map_or_else(String::new, |s| s.block_reason.clone()),
            waf_violations: prev.map_or(0, |s| s.waf_violations),
            upload_violations: prev.map_or(0, |s| s.upload_violations),
            ratelimit_violations: prev.map_or(0, |s| s.ratelimit_violations),
            karma_total: prev.map_or(0, |s| s.karma_total),
        }
    }

    async fn captcha_fail(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        now: u64,
    ) -> Result<bool> {
        let mut current_session = ctx.session_data.clone().unwrap_or_default();
        current_session.captcha_failures += 1;

        warn!(
            circuit = ?ctx.circuit_id,
            session = ?current_session.session_id,
            failures = current_session.captcha_failures,
            "captcha failed: {}", current_session.captcha_failures
        );

        let uri = session.req_header().uri.to_string();

        if current_session.captcha_failures >= self.config.captcha.max_failures {
            info!(
                circuit = ?ctx.circuit_id,
                action = "session_reset",
                "captcha threshold met: session reset"
            );
            let reset_session = EncryptedSession {
                session_id: generate_session_id(),
                circuit_id: ctx.circuit_id.clone(),
                created_at: now,
                queue_started_at: now,
                queue_completed: false,
                captcha_failures: 0,
                captcha_gen_count: 0,
                verified: false,
                verified_at: 0,
                last_active_at: now,
                blocked: current_session.blocked,
                blocked_at: current_session.blocked_at,
                block_reason: current_session.block_reason.clone(),
                waf_violations: current_session.waf_violations,
                upload_violations: current_session.upload_violations,
                ratelimit_violations: current_session.ratelimit_violations,
                karma_total: current_session.karma_total,
            };
            let cookie_header = self.session_cookie(&reset_session, 300)?;
            return serve_redirect(session, &self.config, &uri, Some(&cookie_header), true).await;
        }

        current_session.created_at = now;
        current_session.circuit_id.clone_from(&ctx.circuit_id);
        let cookie_header = self.session_cookie(&current_session, 300)?;
        serve_redirect(session, &self.config, &uri, Some(&cookie_header), true).await
    }
}
