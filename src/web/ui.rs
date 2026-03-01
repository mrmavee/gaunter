//! Web user interface.
//!
//! Exports HTML page generators and template preloading logic.

mod pages;

pub use pages::{access_page, block_page, captcha_page, error_page, preload_templates, queue_page};
