//! Adaptive defense controller.
//!
//! Manages automated state transitions based on traffic scoring.

mod monitor;

pub use monitor::{DefenseMonitor, TrackMode};
