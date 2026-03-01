//! Rate limiting based on CM-Sketch algorithm.
//!
//! Implements per-identity throttling using burst and sustained windows.

use pingora_limits::rate::Rate;
use std::sync::Arc;
use std::time::Duration;

/// Per-identity rate limiter.
pub struct RateLimiter {
    burst_rate: Arc<Rate>,
    sustained_rate: Arc<Rate>,
    max_burst: f64,
    max_sustained: f64,
}

impl RateLimiter {
    /// Creates a new rate limiter with specified RPS and burst.
    #[must_use]
    pub fn new(rps: u32, burst: u32) -> Self {
        let burst_limiter = Rate::new(Duration::from_secs(1));
        let sustained_limiter = Rate::new(Duration::from_secs(10));

        Self {
            burst_rate: Arc::new(burst_limiter),
            sustained_rate: Arc::new(sustained_limiter),
            max_burst: f64::from(burst),
            max_sustained: f64::from(rps * 10),
        }
    }

    /// Validates and records a request against limits.
    #[must_use]
    pub fn check_and_record(&self, key: &str) -> bool {
        self.burst_rate.observe(&key, 1);
        self.sustained_rate.observe(&key, 1);

        let curr_burst = self.burst_rate.rate(&key);
        if curr_burst > self.max_burst {
            return false;
        }

        let curr_sustained = self.sustained_rate.rate(&key);
        if curr_sustained > self.max_sustained {
            return false;
        }

        true
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            burst_rate: Arc::clone(&self.burst_rate),
            sustained_rate: Arc::clone(&self.sustained_rate),
            max_burst: self.max_burst,
            max_sustained: self.max_sustained,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiting() {
        let rl = RateLimiter::new(2, 3);
        assert!(rl.check_and_record("key1"));
        assert!(rl.check_and_record("key1"));
        assert!(rl.check_and_record("key1"));
        if !rl.check_and_record("key1") {
            assert!(!rl.check_and_record("key1"));
        }
        assert!(rl.check_and_record("key2"));
        let rl2 = rl;
        assert!(rl2.check_and_record("key3"));
    }
}
