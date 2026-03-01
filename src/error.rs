//! Error types and Result alias.
//!
//! Centralized error handling for the `Gaunter` proxy.

use thiserror::Error;

/// `Gaunter` error variants.
#[derive(Debug, Error)]
pub enum Error {
    /// Required environment variable missing.
    #[error("Configuration error: environment variable {0} must be set")]
    MissingEnv(String),

    /// Invalid environment variable format or value.
    #[error("Configuration error: environment variable {0} invalid: {1}")]
    InvalidEnv(String, String),

    /// Generic configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Underlying I/O failure.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Image processing failure.
    #[error("Image decoding error: {0}")]
    Image(#[from] image::ImageError),

    /// Target identity exceeded rate limits.
    #[error("Rate limit exceeded for circuit: {circuit_id}")]
    RateLimited {
        /// ID of the limited circuit.
        circuit_id: String,
    },

    /// CAPTCHA solution incorrect.
    #[error("CAPTCHA verification failed")]
    CaptchaFailed,

    /// Internal CAPTCHA generator error.
    #[error("CAPTCHA error: {0}")]
    Captcha(String),

    /// Cryptographic operation failure.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// WAF rule violation or compilation error.
    #[error("Rule engine error: {0}")]
    Rule(String),

    /// Tor control port communication failure.
    #[error("Tor control error: {0}")]
    TorControl(String),

    /// Webhook HTTP dispatch failure.
    #[error("Webhook reqwest error: {0}")]
    WebhookReqwest(#[from] reqwest::Error),

    /// Webhook payload or logic error.
    #[error("Webhook error: {0}")]
    Webhook(String),

    /// General proxy engine error.
    #[error("Proxy error: {0}")]
    Proxy(String),
}

/// Crate-wide Result alias.
pub type Result<T> = std::result::Result<T, Error>;
