//! CAPTCHA system components.
//!
//! Provides image generation, difficulty management, and validation.

pub mod generator;
pub mod manager;
pub use manager::CaptchaManager;
