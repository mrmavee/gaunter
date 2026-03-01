#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
#![warn(clippy::panic_in_result_fn)]
#![warn(clippy::indexing_slicing)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::ref_patterns)]
#![warn(clippy::unused_result_ok)]
#![warn(clippy::clone_on_ref_ptr)]

//! `Gaunter` core library exports.
//!
//! Provides public interfaces for proxy, WAF, and Tor integration.

mod config;
mod core;
pub mod error;

#[cfg(any(fuzzing, feature = "fuzzing", feature = "testing"))]
#[allow(missing_docs)]
pub mod test_helpers {
    pub use crate::core::middleware::EncryptedSession;
    pub use crate::core::proxy::headers::is_static_asset;
    pub use crate::core::proxy::protocol::parse_proxy_header;
    pub use crate::core::proxy::response::parse_form;
    pub use crate::security::captcha::generator::CaptchaGenerator;
    pub use crate::security::crypto::CookieCrypto;
    pub use crate::security::waf::RuleEngine;
    pub use crate::security::waf::signatures::detect_safe_mime;
}
mod features;
mod security;
mod web;

pub use config::Config;
pub use core::middleware::RateLimiter;
pub use core::proxy::GaunterProxy;
pub use core::proxy::protocol::{ProxyProtocolConfig, run_proxy_listener};
pub use features::tor::control::TorControl;
pub use features::tor::observer::TorObserver;
pub use features::webhook::WebhookNotifier;
pub use security::captcha::CaptchaManager;
pub use security::defense::DefenseMonitor;
pub use security::waf::WafEngine;
pub use web::ui::preload_templates;
