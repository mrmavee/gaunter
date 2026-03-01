//! Configuration management and initialization.
//!
//! Provides thread-safe access to application settings loaded from environment variables.

pub mod settings;

pub use settings::{Config, WafMode};
