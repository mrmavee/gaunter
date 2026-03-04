//! Configuration settings.
//!
//! Defines application settings and environment variable loading logic.

use crate::error::{Error, Result};
use std::collections::HashSet;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_LISTEN_ADDR_PORT: u16 = 8080;
const DEFAULT_LISTEN_ADDR_HOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEFAULT_INTERNAL_ADDR_PORT: u16 = 8081;
const DEFAULT_CONCURRENCY_LIMIT: usize = 1024;
const DEFAULT_WAF_MODE: &str = "NORMAL";
const DEFAULT_COOP_POLICY: &str = "same-origin-allow-popups";
const DEFAULT_CLIENT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
const DEFAULT_WAF_BODY_SCAN_MAX_SIZE: usize = 32768;
const DEFAULT_CAPTCHA_TTL: u64 = 300;
const DEFAULT_CAPTCHA_DIFFICULTY: &str = "medium";
const DEFAULT_MAX_CAPTCHA_FAILURES: u8 = 3;
const DEFAULT_CAPTCHA_GEN_LIMIT: u8 = 5;
const DEFAULT_SESSION_EXPIRY_SECS: u64 = 3600;
const DEFAULT_RATE_LIMIT_SESSION_RPS: u32 = 3;
const DEFAULT_RATE_LIMIT_SESSION_BURST: u32 = 5;
const DEFAULT_DEFENSE_COOLDOWN_SECS: u64 = 300;
const DEFAULT_KARMA_THRESHOLD: u32 = 50;
const DEFAULT_ATTACK_CHURN_THRESHOLD: u32 = 30;
const DEFAULT_ATTACK_RPS_THRESHOLD: u32 = 30;
const DEFAULT_ATTACK_RPC_THRESHOLD: u32 = 5;
const DEFAULT_ATTACK_DEFENSE_SCORE: f64 = 2.0;
const DEFAULT_ATTACK_POW_SCORE: f64 = 4.0;
const DEFAULT_ATTACK_POW_EFFORT: u32 = 5;
const DEFAULT_ATTACK_RECOVERY_SECS: u64 = 300;
const DEFAULT_META_TITLE: &str = "Security Check";
const DEFAULT_META_DESCRIPTION: &str = "Protected by Gaunter";
const DEFAULT_TOR_BW_ABUSE_THRESHOLD: u64 = 50 * 1024 * 1024;
const DEFAULT_TOR_STREAM_FLOOD_THRESHOLD: u32 = 200;
const DEFAULT_LOG_FORMAT: &str = "json";

const DEFAULT_RESTRICTED_PATHS: &[&str] = &[
    "/.env",
    "/.git",
    "/.git/HEAD",
    "/.git/config",
    "/.aws",
    "/.aws/credentials",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/config.php",
    "/.htaccess",
    "/.htpasswd",
    "/backup.sql",
    "/database.sql",
    "/.vscode",
    "/.idea",
    "/node_modules",
    "/vendor",
    "/.svn",
    "/.hg",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/Thumbs.db",
    "/web.config",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/elmah.axd",
    "/trace.axd",
];

/// Environment variable provider interface.
pub trait EnvProvider {
    fn var(&self, key: &str) -> Option<String>;
}

/// Standard OS environment provider.
pub struct StdEnvProvider;

impl EnvProvider for StdEnvProvider {
    fn var(&self, key: &str) -> Option<String> {
        env::var(key).ok()
    }
}

/// WAF operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WafMode {
    /// Standard filtering.
    #[default]
    Normal,
    /// Aggressive filtering and CAPTCHA.
    Defense,
}

impl WafMode {
    fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "DEFENSE" => Self::Defense,
            _ => Self::Normal,
        }
    }
}

impl std::fmt::Display for WafMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "Normal"),
            Self::Defense => write!(f, "Defense"),
        }
    }
}

fn env<P: EnvProvider>(provider: &P, key: &str) -> Result<String> {
    provider
        .var(key)
        .ok_or_else(|| Error::MissingEnv(key.to_string()))
}

fn env_or<P: EnvProvider>(provider: &P, key: &str, default: &str) -> String {
    provider.var(key).unwrap_or_else(|| default.to_string())
}

fn env_bool<P: EnvProvider>(provider: &P, key: &str) -> bool {
    provider
        .var(key)
        .is_some_and(|v| v.to_lowercase() == "true" || v == "1")
}

fn env_u32<P: EnvProvider>(provider: &P, key: &str) -> Result<u32> {
    env(provider, key)?
        .parse()
        .map_err(|e| Error::InvalidEnv(key.to_string(), format!("{e}")))
}

fn env_f64<P: EnvProvider>(provider: &P, key: &str) -> Result<f64> {
    env(provider, key)?
        .parse()
        .map_err(|e| Error::InvalidEnv(key.to_string(), format!("{e}")))
}

fn env_f64_or<P: EnvProvider>(provider: &P, key: &str, default: f64) -> f64 {
    provider
        .var(key)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u64_or<P: EnvProvider>(provider: &P, key: &str, default: u64) -> u64 {
    provider
        .var(key)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u32_or<P: EnvProvider>(provider: &P, key: &str, default: u32) -> u32 {
    provider
        .var(key)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u8_or<P: EnvProvider>(provider: &P, key: &str, default: u8) -> u8 {
    provider
        .var(key)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_usize_or<P: EnvProvider>(provider: &P, key: &str, default: usize) -> usize {
    provider
        .var(key)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Boolean feature toggles.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct FeatureFlags {
    /// Enable CAPTCHA challenges.
    pub captcha_enabled: bool,
    /// Enable webhook notifications.
    pub webhook_enabled: bool,
    /// Enable request body scanning.
    pub waf_body_scan_enabled: bool,
    /// Enable COEP security header.
    pub coep_enabled: bool,
    /// Enable CSP header injection.
    pub csp_injected: bool,
}

impl FeatureFlags {
    fn from_provider<P: EnvProvider>(provider: &P) -> Self {
        Self {
            captcha_enabled: env_bool(provider, "CAPTCHA_ENABLED"),
            webhook_enabled: env_bool(provider, "WEBHOOK_ENABLED"),
            waf_body_scan_enabled: env_bool(provider, "WAF_BODY_SCAN_ENABLED"),
            coep_enabled: env_bool(provider, "COEP_ENABLED"),
            csp_injected: env_bool(provider, "CSP_INJECTED"),
        }
    }
}

/// Network and bind configurations.
#[derive(Debug, Clone)]
pub struct NetworkSettings {
    /// External bind address (PROXY protocol).
    pub listen_addr: SocketAddr,
    /// Internal bind address (Pingora engine).
    pub internal_addr: SocketAddr,
    /// Upstream backend URL.
    pub backend_url: String,
    /// Maximum concurrent connections.
    pub concurrency_limit: usize,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(DEFAULT_LISTEN_ADDR_HOST, DEFAULT_LISTEN_ADDR_PORT),
            internal_addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                DEFAULT_INTERNAL_ADDR_PORT,
            ),
            backend_url: String::new(),
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
        }
    }
}

/// Tor integration settings.
#[derive(Debug, Clone)]
pub struct TorSettings {
    /// Circuit ID IPv6 prefix.
    pub circuit_prefix: String,
    /// Tor control port address.
    pub control_addr: Option<SocketAddr>,
    /// Tor control port password.
    pub control_password: Option<String>,
    /// Path to local torrc file.
    pub torrc_path: Option<PathBuf>,
    /// Bandwidth abuse threshold (bytes).
    pub bandwidth_abuse_threshold: u64,
    /// Stream flood threshold.
    pub stream_flood_threshold: u32,
}

impl Default for TorSettings {
    fn default() -> Self {
        Self {
            circuit_prefix: String::new(),
            control_addr: None,
            control_password: None,
            torrc_path: None,
            bandwidth_abuse_threshold: DEFAULT_TOR_BW_ABUSE_THRESHOLD,
            stream_flood_threshold: DEFAULT_TOR_STREAM_FLOOD_THRESHOLD,
        }
    }
}

/// WAF and security policy settings.
#[derive(Debug, Clone)]
pub struct SecuritySettings {
    /// Active WAF mode.
    pub waf_mode: WafMode,
    /// SSRF protection allowlist.
    pub ssrf_allowed_hosts: Vec<String>,
    /// Paths that trigger immediate karma penalty.
    pub restricted_paths: HashSet<String>,
    /// Extra CSP sources.
    pub csp_extra_sources: String,
    /// COOP security policy.
    pub coop_policy: String,
    /// Max client request body size (bytes).
    pub client_max_body_size: usize,
    /// Max body scan size (bytes).
    pub waf_body_scan_max_size: usize,
    /// Max response buffer size (bytes).
    pub response_buffer_size: usize,
    pub csp_normal: String,
    pub csp_widget: String,
    pub hide_server: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            waf_mode: WafMode::default(),
            ssrf_allowed_hosts: Vec::new(),
            restricted_paths: DEFAULT_RESTRICTED_PATHS
                .iter()
                .map(|&s| s.to_string())
                .collect(),
            csp_extra_sources: String::new(),
            coop_policy: DEFAULT_COOP_POLICY.to_string(),
            client_max_body_size: DEFAULT_CLIENT_MAX_BODY_SIZE,
            waf_body_scan_max_size: DEFAULT_WAF_BODY_SCAN_MAX_SIZE,
            response_buffer_size: 10 * 1024 * 1024,
            csp_normal: build_csp("'none'", ""),
            csp_widget: build_csp("*", ""),
            hide_server: false,
        }
    }
}

#[must_use]
pub fn build_csp(frame_ancestors: &str, csp_extra: &str) -> String {
    if csp_extra.is_empty() {
        format!(
            "default-src 'self'; \
             base-uri 'self'; \
             object-src 'none'; \
             form-action 'self'; \
             frame-ancestors {frame_ancestors}; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data: blob:; \
             font-src 'self' data:; \
             connect-src 'self';"
        )
    } else {
        format!(
            "default-src 'self' {csp_extra}; \
             base-uri 'self' {csp_extra}; \
             object-src 'none'; \
             form-action 'self' {csp_extra}; \
             frame-ancestors {frame_ancestors}; \
             script-src 'self' 'unsafe-inline' {csp_extra}; \
             style-src 'self' 'unsafe-inline' {csp_extra}; \
             img-src 'self' data: blob: {csp_extra}; \
             font-src 'self' data: {csp_extra}; \
             connect-src 'self' {csp_extra};"
        )
    }
}

/// CAPTCHA challenge configuration.
#[derive(Debug, Clone)]
pub struct CaptchaSettings {
    /// Signing secret.
    pub secret: String,
    /// Challenge validity duration.
    pub ttl: u64,
    /// Visual difficulty level.
    pub difficulty: String,
    /// Max failures before block.
    pub max_failures: u8,
    /// Max generations per session.
    pub gen_limit: u8,
}

impl Default for CaptchaSettings {
    fn default() -> Self {
        Self {
            secret: String::new(),
            ttl: DEFAULT_CAPTCHA_TTL,
            difficulty: DEFAULT_CAPTCHA_DIFFICULTY.to_string(),
            max_failures: DEFAULT_MAX_CAPTCHA_FAILURES,
            gen_limit: DEFAULT_CAPTCHA_GEN_LIMIT,
        }
    }
}

/// Session and rate limit settings.
#[derive(Debug, Clone)]
pub struct SessionSettings {
    /// Cookie signing secret.
    pub secret: String,
    /// Cookie validity duration.
    pub expiry_secs: u64,
    /// Requests per second limit.
    pub rate_limit_rps: u32,
    /// Burst capacity.
    pub rate_limit_burst: u32,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            secret: String::new(),
            expiry_secs: DEFAULT_SESSION_EXPIRY_SECS,
            rate_limit_rps: DEFAULT_RATE_LIMIT_SESSION_RPS,
            rate_limit_burst: DEFAULT_RATE_LIMIT_SESSION_BURST,
        }
    }
}

/// Automated defense thresholds.
#[derive(Debug, Clone)]
pub struct DefenseSettings {
    /// Error rate threshold.
    pub error_rate_threshold: f64,
    /// Circuit flood threshold.
    pub circuit_flood_threshold: u32,
    /// Defense mode cooldown (secs).
    pub cooldown_secs: u64,
    /// Karma threshold for blocking.
    pub karma_threshold: u32,
    /// Circuit churn threshold.
    pub attack_churn_threshold: u32,
    /// Global RPS threshold.
    pub attack_rps_threshold: u32,
    /// Requests per circuit threshold.
    pub attack_rpc_threshold: u32,
    /// Score to trigger defense mode.
    pub attack_defense_score: f64,
    /// Score to trigger Tor `PoW`.
    pub attack_pow_score: f64,
    /// Tor `PoW` effort level.
    pub attack_pow_effort: u32,
    /// Auto-recovery cooldown (secs).
    pub attack_recovery_secs: u64,
    /// Circuit RPS limit.
    pub rate_limit_rps: u32,
    /// Circuit burst capacity.
    pub rate_limit_burst: u32,
}

impl Default for DefenseSettings {
    fn default() -> Self {
        Self {
            error_rate_threshold: 0.0,
            circuit_flood_threshold: 0,
            cooldown_secs: DEFAULT_DEFENSE_COOLDOWN_SECS,
            karma_threshold: DEFAULT_KARMA_THRESHOLD,
            attack_churn_threshold: DEFAULT_ATTACK_CHURN_THRESHOLD,
            attack_rps_threshold: DEFAULT_ATTACK_RPS_THRESHOLD,
            attack_rpc_threshold: DEFAULT_ATTACK_RPC_THRESHOLD,
            attack_defense_score: DEFAULT_ATTACK_DEFENSE_SCORE,
            attack_pow_score: DEFAULT_ATTACK_POW_SCORE,
            attack_pow_effort: DEFAULT_ATTACK_POW_EFFORT,
            attack_recovery_secs: DEFAULT_ATTACK_RECOVERY_SECS,
            rate_limit_rps: 0,
            rate_limit_burst: 0,
        }
    }
}

/// Branding and UI metadata.
#[derive(Debug, Clone)]
pub struct MetaSettings {
    /// Website name.
    pub app_name: String,
    /// Base64 favicon/logo.
    pub favicon_base64: String,
    /// HTML title tag.
    pub title: String,
    /// HTML meta description.
    pub description: String,
    /// HTML meta keywords.
    pub keywords: String,
}

impl Default for MetaSettings {
    fn default() -> Self {
        Self {
            app_name: String::new(),
            favicon_base64: String::new(),
            title: DEFAULT_META_TITLE.to_string(),
            description: DEFAULT_META_DESCRIPTION.to_string(),
            keywords: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct WebhookSettings {
    pub url: Option<String>,

    pub token: Option<String>,
}

#[derive(Debug, Clone)]
/// Application configuration.
pub struct Config {
    /// Network settings.
    pub network: NetworkSettings,
    /// Tor integration.
    pub tor: TorSettings,
    /// Security and WAF policy.
    pub security: SecuritySettings,
    /// CAPTCHA settings.
    pub captcha: CaptchaSettings,
    /// Session management.
    pub session: SessionSettings,
    /// Automated defense.
    pub defense: DefenseSettings,
    /// UI metadata.
    pub meta: MetaSettings,
    /// Webhook settings.
    pub webhook: WebhookSettings,
    /// Feature flags.
    pub features: FeatureFlags,
    /// Output log format.
    pub log_format: String,
}

#[cfg(any(test, fuzzing, feature = "fuzzing", feature = "testing"))]
impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkSettings::default(),
            tor: TorSettings::default(),
            security: SecuritySettings::default(),
            captcha: CaptchaSettings::default(),
            session: SessionSettings::default(),
            defense: DefenseSettings::default(),
            meta: MetaSettings::default(),
            webhook: WebhookSettings::default(),
            features: FeatureFlags::default(),
            log_format: DEFAULT_LOG_FORMAT.to_string(),
        }
    }
}

impl Config {
    /// Loads config from environment.
    ///
    /// # Errors
    /// Returns error if environment variables are invalid or missing.
    pub fn from_env() -> Result<Arc<Self>> {
        Self::from_provider(&StdEnvProvider)
    }

    /// Loads config from provider.
    ///
    /// # Errors
    /// Returns error if environment variables are invalid or missing.
    pub fn from_provider<P: EnvProvider>(provider: &P) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            network: load_network(provider)?,
            tor: load_tor(provider)?,
            security: load_security(provider),
            captcha: load_captcha(provider)?,
            session: load_session(provider)?,
            defense: load_defense(provider)?,
            meta: load_meta(provider)?,
            webhook: load_webhook(provider),
            features: FeatureFlags::from_provider(provider),
            log_format: env_or(provider, "LOG_FORMAT", DEFAULT_LOG_FORMAT),
        }))
    }

    fn load_logo<P: EnvProvider>(provider: &P) -> Result<String> {
        use base64::prelude::*;
        provider.var("LOGO_PATH").map_or_else(
            || {
                Ok("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAACHUExURf///w2m6Q6l6Q2m6g+l6A6k6g2k6SKZ02R0ixKj5hCk52B2kGN0jB6b1x6c1w+l6Rqe3Bmf3Q2l6TyLt1R9nSqWyw+l6jSPwEuCpxif3kiEqzSOvw+m6UWErGN0izGRwg6l6jmNuieXzS+TxR2c2DGRw0yCplN9nimWzDuLtzyLuCOY0g2l6mTRFyAAAAABdFJOUwBA5thmAAAAAWJLR0QAiAUdSAAAAAd0SU1FB+oDARcSDZs7NmoAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjYtMDMtMDFUMjM6MTY6MzErMDA6MDDLnyD5AAAAJXRFWHRkYXRlOm1vZGlmeQAyMDI2LTAzLTAxVDIzOjE2OjMxKzAwOjAwusKYRQAAACh0RVh0ZGF0ZTp0aW1lc3RhbXAAMjAyNi0wMy0wMVQyMzoxODoxMyswMDowMCakn30AAAIfSURBVHja7ZrbWsIwEIRhsVIKWkHk7PmE4vs/nxVQ6IWwm0w7n34717szP2mbNiGNhsvlcrlcLpdLoaaItGwtJ0WLgOJlq8TeAkEQMdsFtKjMtGOw3xJN0AxwK7WcAgdApJ0q1BbkEJTNOhqArEIA6R7P70qFAFnvOECvyhE401yC81JLHgmQl9wuNC39UssgEiDkoYbOA/yZsHEZYIbMT9PhVWY2O13ff9HXfwNQPFkIo4j8NGUDsPPpAOx8OgA7nw7AzqcDsPPpAOx8OgA7nw7AzqcDsPPpAOx8OgAtfSTjSU8JYFov5DLSORaazjT5pvWPrni3qJvrLTUEia54YVlWmtbAe7WL36tMW2KmfRDllkG4p1zfHNKt0rlcdmfIl/uDuzYPQQC5BeDxIMDT3wSgXwLgTfisdB6EA4CK2RNRhVPxXFu8LYK/jNLZdFOr2DkrXscv6Nfx11bbZCxNTe22HvtBYjVEf5LZ/aoAqBgZ7YYHqAEa64UGqAkb6YQFqBEc54MEqBkd5YIDIMBjPFAAJHyEAwaA/QOYvyD+JgLcxMy7GDGRRE9kkJks8M/rHuRlkqavy45yRbHTerMnWw4Rb7M3wwLsWz8t7/H59CMclkV4eIvSTPqaFuwxnjKA6iCTdkMoBIB+lIt/mE1zCaocgZUGYAUFGMQ+htjnUNeSIPP5M2HQybQEmb9ByD9sLa0cF+9yuVwul8v1z/UJXXMzoxn2prcAAAAASUVORK5CYII=".to_string())
            },
            |path| {
                let data = std::fs::read(&path)?;

                if data.len() > 10 * 1024 * 1024 {
                     return Err(Error::InvalidEnv("LOGO_PATH".to_string(), format!("File '{path}' exceeds 10MB limit")));
                }

                let img = image::load_from_memory(&data)?;

                let final_data = if data.len() <= 100 * 1024
                    && img.width() <= 128
                    && img.height() <= 128
                {
                    let mut buf = std::io::Cursor::new(Vec::new());
                    img.write_to(&mut buf, image::ImageFormat::Png)?;
                    buf.into_inner()
                } else {
                    let scaled = img.resize(128, 128, image::imageops::FilterType::Lanczos3);
                    let mut buf = std::io::Cursor::new(Vec::new());
                    scaled
                        .write_to(&mut buf, image::ImageFormat::Png)?;
                    buf.into_inner()
                };

                let b64 = BASE64_STANDARD.encode(&final_data);
                Ok(format!("data:image/png;base64,{b64}"))
            },
        )
    }
}

fn load_network<P: EnvProvider>(provider: &P) -> Result<NetworkSettings> {
    let defaults = NetworkSettings::default();
    let net_defaults = NetworkSettings::default();
    let listen_str = env_or(
        provider,
        "LISTEN_ADDR",
        &format!(
            "{}:{}",
            defaults.listen_addr.ip(),
            defaults.listen_addr.port()
        ),
    );

    Ok(NetworkSettings {
        listen_addr: listen_str
            .parse()
            .map_err(|e| Error::InvalidEnv("LISTEN_ADDR".to_string(), format!("{e}")))?,
        internal_addr: env_or(
            provider,
            "INTERNAL_ADDR",
            &format!(
                "{}:{}",
                net_defaults.internal_addr.ip(),
                net_defaults.internal_addr.port()
            ),
        )
        .parse()
        .map_err(|e| Error::InvalidEnv("INTERNAL_ADDR".to_string(), format!("{e}")))?,
        backend_url: env(provider, "BACKEND_URL")?,
        concurrency_limit: env_usize_or(provider, "CONCURRENCY_LIMIT", defaults.concurrency_limit),
    })
}

fn load_tor<P: EnvProvider>(provider: &P) -> Result<TorSettings> {
    Ok(TorSettings {
        circuit_prefix: env(provider, "TOR_CIRCUIT_PREFIX")?,
        control_addr: provider
            .var("TOR_CONTROL_ADDR")
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse().ok()),
        control_password: provider
            .var("TOR_CONTROL_PASSWORD")
            .filter(|s| !s.is_empty()),
        torrc_path: provider
            .var("TORRC_PATH")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
        bandwidth_abuse_threshold: env_u64_or(
            provider,
            "TOR_BW_ABUSE_THRESHOLD",
            DEFAULT_TOR_BW_ABUSE_THRESHOLD,
        ),
        stream_flood_threshold: env_u32_or(
            provider,
            "TOR_STREAM_FLOOD_THRESHOLD",
            DEFAULT_TOR_STREAM_FLOOD_THRESHOLD,
        ),
    })
}

fn load_security<P: EnvProvider>(provider: &P) -> SecuritySettings {
    let sec_defaults = SecuritySettings::default();
    let csp_extra = env_or(provider, "CSP_EXTRA_SOURCES", "");
    SecuritySettings {
        waf_mode: WafMode::from_str(&env_or(provider, "WAF_MODE", DEFAULT_WAF_MODE)),
        ssrf_allowed_hosts: env_or(provider, "SSRF_ALLOWED_HOSTS", "")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        restricted_paths: env_or(provider, "RESTRICTED_PATHS", "")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .chain(sec_defaults.restricted_paths)
            .collect(),
        coop_policy: env_or(provider, "COOP_POLICY", &sec_defaults.coop_policy),
        client_max_body_size: env_usize_or(
            provider,
            "CLIENT_MAX_BODY_SIZE",
            sec_defaults.client_max_body_size,
        ),
        waf_body_scan_max_size: env_usize_or(
            provider,
            "WAF_BODY_SCAN_MAX_SIZE",
            sec_defaults.waf_body_scan_max_size,
        ),
        response_buffer_size: env_usize_or(
            provider,
            "RESPONSE_BUFFER_SIZE",
            sec_defaults.response_buffer_size,
        ),
        csp_normal: build_csp("'none'", &csp_extra),
        csp_widget: build_csp("*", &csp_extra),
        csp_extra_sources: csp_extra,
        hide_server: env_bool(provider, "HIDE_SERVER"),
    }
}

fn load_captcha<P: EnvProvider>(provider: &P) -> Result<CaptchaSettings> {
    let cap_defaults = CaptchaSettings::default();
    Ok(CaptchaSettings {
        secret: env(provider, "CAPTCHA_SECRET")?,
        ttl: env(provider, "CAPTCHA_TTL")
            .unwrap_or_else(|_| cap_defaults.ttl.to_string())
            .parse()
            .unwrap_or(cap_defaults.ttl),
        difficulty: env_or(provider, "CAPTCHA_DIFFICULTY", &cap_defaults.difficulty),
        max_failures: env_u8_or(provider, "MAX_CAPTCHA_FAILURES", cap_defaults.max_failures),
        gen_limit: env_u8_or(provider, "CAPTCHA_GEN_LIMIT", cap_defaults.gen_limit),
    })
}

fn load_session<P: EnvProvider>(provider: &P) -> Result<SessionSettings> {
    let sess_defaults = SessionSettings::default();
    Ok(SessionSettings {
        secret: env(provider, "SESSION_SECRET")?,
        expiry_secs: env_u64_or(provider, "SESSION_EXPIRY_SECS", sess_defaults.expiry_secs),
        rate_limit_rps: env_u32_or(
            provider,
            "RATE_LIMIT_SESSION_RPS",
            sess_defaults.rate_limit_rps,
        ),
        rate_limit_burst: env_u32_or(
            provider,
            "RATE_LIMIT_SESSION_BURST",
            sess_defaults.rate_limit_burst,
        ),
    })
}

fn load_defense<P: EnvProvider>(provider: &P) -> Result<DefenseSettings> {
    let def_defaults = DefenseSettings::default();
    Ok(DefenseSettings {
        error_rate_threshold: env_f64(provider, "DEFENSE_ERROR_RATE_THRESHOLD")?,
        circuit_flood_threshold: env_u32(provider, "DEFENSE_CIRCUIT_FLOOD_THRESHOLD")?,
        cooldown_secs: env_u64_or(
            provider,
            "DEFENSE_COOLDOWN_SECS",
            def_defaults.cooldown_secs,
        ),
        karma_threshold: env_u32_or(provider, "KARMA_THRESHOLD", def_defaults.karma_threshold),
        attack_churn_threshold: env_u32_or(
            provider,
            "ATTACK_CHURN_THRESHOLD",
            def_defaults.attack_churn_threshold,
        ),
        attack_rps_threshold: env_u32_or(
            provider,
            "ATTACK_RPS_THRESHOLD",
            def_defaults.attack_rps_threshold,
        ),
        attack_rpc_threshold: env_u32_or(
            provider,
            "ATTACK_RPC_THRESHOLD",
            def_defaults.attack_rpc_threshold,
        ),
        attack_defense_score: env_f64_or(
            provider,
            "ATTACK_DEFENSE_SCORE",
            def_defaults.attack_defense_score,
        ),
        attack_pow_score: env_f64_or(provider, "ATTACK_POW_SCORE", def_defaults.attack_pow_score),
        attack_pow_effort: env_u32_or(
            provider,
            "ATTACK_POW_EFFORT",
            def_defaults.attack_pow_effort,
        ),
        attack_recovery_secs: env_u64_or(
            provider,
            "ATTACK_RECOVERY_SECS",
            def_defaults.attack_recovery_secs,
        ),
        rate_limit_rps: env_u32(provider, "RATE_LIMIT_RPS")?,
        rate_limit_burst: env_u32(provider, "RATE_LIMIT_BURST")?,
    })
}

fn load_meta<P: EnvProvider>(provider: &P) -> Result<MetaSettings> {
    let meta_defaults = MetaSettings::default();
    Ok(MetaSettings {
        app_name: env_or(provider, "APP_NAME", ""),
        favicon_base64: Config::load_logo(provider)?,
        title: env_or(provider, "META_TITLE", &meta_defaults.title),
        description: env_or(provider, "META_DESCRIPTION", &meta_defaults.description),
        keywords: env_or(provider, "META_KEYWORDS", ""),
    })
}

fn load_webhook<P: EnvProvider>(provider: &P) -> WebhookSettings {
    WebhookSettings {
        url: provider.var("WEBHOOK_URL").filter(|s| !s.is_empty()),
        token: provider.var("WEBHOOK_TOKEN").filter(|s| !s.is_empty()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Provider(HashMap<String, String>);

    impl EnvProvider for Provider {
        fn var(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    fn base_env() -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("BACKEND_URL".into(), "http://127.0.0.1:3000".into());
        env.insert("TOR_CIRCUIT_PREFIX".into(), "fd87:d87e:eb43".into());
        env.insert("CAPTCHA_SECRET".into(), "captcha_secret_key".into());
        env.insert("SESSION_SECRET".into(), "session_secret_key".into());
        env.insert("APP_NAME".into(), "gaunter".into());
        env.insert("DEFENSE_ERROR_RATE_THRESHOLD".into(), "0.5".into());
        env.insert("DEFENSE_CIRCUIT_FLOOD_THRESHOLD".into(), "100".into());
        env.insert("RATE_LIMIT_RPS".into(), "10".into());
        env.insert("RATE_LIMIT_BURST".into(), "20".into());
        env
    }

    #[test]
    fn env_loading() {
        assert!(Config::from_provider(&Provider(HashMap::new())).is_err());

        let mut e = base_env();
        e.remove("TOR_CIRCUIT_PREFIX");
        assert!(Config::from_provider(&Provider(e)).is_err());

        let c = Config::from_provider(&Provider(base_env())).unwrap();
        assert_eq!(c.network.backend_url, "http://127.0.0.1:3000");
        assert_eq!(c.tor.circuit_prefix, "fd87:d87e:eb43");
        assert_eq!(c.security.waf_mode, WafMode::Normal);

        let mut e = base_env();
        e.insert("WAF_MODE".into(), "DEFENSE".into());
        let c = Config::from_provider(&Provider(e)).unwrap();
        assert_eq!(c.security.waf_mode, WafMode::Defense);

        let mut e = base_env();
        e.insert("WAF_MODE".into(), "UNKNOWN".into());
        let c = Config::from_provider(&Provider(e)).unwrap();
        assert_eq!(c.security.waf_mode, WafMode::Normal);

        let mut e = base_env();
        e.insert("CAPTCHA_ENABLED".into(), "true".into());
        e.insert("WAF_BODY_SCAN_ENABLED".into(), "1".into());
        let c = Config::from_provider(&Provider(e)).unwrap();
        assert!(c.features.captcha_enabled);
        assert!(c.features.waf_body_scan_enabled);

        let mut e = base_env();
        e.insert("LISTEN_ADDR".into(), "mismatch".into());
        assert!(Config::from_provider(&Provider(e)).is_err());
    }
}
