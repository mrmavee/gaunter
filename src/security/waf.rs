//! Web Application Firewall (WAF).
//!
//! Provides inspection engine, signature matching, and security rules.

mod engine;
mod rules;

#[cfg(any(fuzzing, feature = "fuzzing", feature = "testing"))]
pub use rules::RuleEngine;
pub mod signatures;

pub use engine::{WafEngine, WafResult};
