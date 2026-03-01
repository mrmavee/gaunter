//! Defense monitoring and scoring.
//!
//! Tracks traffic metrics, karma points, and automated defense states.

use crate::config::{Config, WafMode};
use papaya::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use tracing::{debug, info, trace, warn};

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct KarmaEntry {
    pub points: AtomicU32,
    pub last_updated: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackMode {
    GlobalAndLocal,
    LocalOnly,
}

/// Centralized traffic monitor and scoring engine.
pub struct DefenseMonitor {
    config: Arc<Config>,
    error_count: AtomicU64,
    request_count: AtomicU64,
    circuit_counts: HashMap<String, AtomicU64>,
    circuit_karma: HashMap<String, KarmaEntry>,
    blocked_sessions: HashMap<String, AtomicU64>,
    last_reset_epoch: AtomicU64,
    current_mode: std::sync::atomic::AtomicU8,
    defense_activated_at: AtomicU64,

    attack_window_start: AtomicU64,
    attack_unverified_count: AtomicU64,
    attack_circuits: HashMap<String, ()>,
    attack_request_count: AtomicU64,
    pow_enabled: AtomicBool,
    pow_enabled_at: AtomicU64,
    last_score_check: AtomicU64,
    last_karma_reset_epoch: AtomicU64,
    threshold_check_counter: AtomicU64,
    challenged_circuits: HashMap<String, AtomicU64>,
}

impl DefenseMonitor {
    /// Initializes a new defense monitor.
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        let initial_mode = match config.security.waf_mode {
            WafMode::Normal => 0,
            WafMode::Defense => 1,
        };
        let now_epoch = epoch_secs();
        let defense_activated_at = if initial_mode == 1 { now_epoch } else { 0 };

        Self {
            config,
            error_count: AtomicU64::new(0),
            request_count: AtomicU64::new(0),
            circuit_counts: HashMap::new(),
            circuit_karma: HashMap::new(),
            blocked_sessions: HashMap::new(),
            last_reset_epoch: AtomicU64::new(now_epoch),
            current_mode: std::sync::atomic::AtomicU8::new(initial_mode),
            defense_activated_at: AtomicU64::new(defense_activated_at),

            attack_window_start: AtomicU64::new(now_epoch),
            attack_unverified_count: AtomicU64::new(0),
            attack_circuits: HashMap::new(),
            attack_request_count: AtomicU64::new(0),
            pow_enabled: AtomicBool::new(false),
            pow_enabled_at: AtomicU64::new(0),
            last_score_check: AtomicU64::new(0),
            last_karma_reset_epoch: AtomicU64::new(now_epoch),
            threshold_check_counter: AtomicU64::new(0),
            challenged_circuits: HashMap::new(),
        }
    }

    /// Retrieves current configuration.
    #[must_use]
    pub fn config(&self) -> Arc<Config> {
        Arc::clone(&self.config)
    }

    /// Records request metrics for a circuit.
    pub fn record_request(&self, circuit_id: Option<&str>, is_error: bool, mode: TrackMode) {
        if mode == TrackMode::LocalOnly {
            trace!("local request recorded");
        }
        self.request_count.fetch_add(1, Ordering::Relaxed);
        if mode == TrackMode::GlobalAndLocal {
            self.attack_request_count.fetch_add(1, Ordering::Relaxed);
        }

        if is_error {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(circuit) = circuit_id {
            let circuit_counts = self.circuit_counts.pin();
            if let Some(count) = circuit_counts.get(circuit) {
                count.fetch_add(1, Ordering::Relaxed);
            } else {
                circuit_counts.insert(circuit.to_string(), AtomicU64::new(1));
            }
            if mode == TrackMode::GlobalAndLocal {
                self.attack_circuits.pin().insert(circuit.to_string(), ());
            }
        }

        if self
            .threshold_check_counter
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(8)
        {
            self.tick();
        }
    }

    /// Checks if circuit is blocked (L7).
    pub fn is_circuit_blocked(&self, circuit_id: &str) -> bool {
        self.circuit_karma
            .pin()
            .get(circuit_id)
            .is_some_and(|entry| {
                entry.points.load(Ordering::Relaxed) >= self.config.defense.karma_threshold
            })
    }

    /// Checks if circuit is banned (L4).
    pub fn is_circuit_banned(&self, circuit_id: &str) -> bool {
        self.circuit_karma
            .pin()
            .get(circuit_id)
            .is_some_and(|entry| {
                entry.points.load(Ordering::Relaxed)
                    >= self.config.defense.karma_threshold.saturating_mul(5)
            })
    }

    /// Evaluates global defense thresholds.
    pub fn tick(&self) {
        let last_check = self.last_reset_epoch.load(Ordering::Relaxed);
        let now_epoch = epoch_secs();
        if now_epoch.saturating_sub(last_check) < 60 {
            return;
        }

        if self
            .last_reset_epoch
            .compare_exchange(last_check, now_epoch, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let requests = self.request_count.load(Ordering::Relaxed);
        let errors = self.error_count.load(Ordering::Relaxed);
        let mut should_activate = false;

        if requests >= 5 {
            let req_f64 = f64::from(u32::try_from(requests).unwrap_or(u32::MAX));
            let err_f64 = f64::from(u32::try_from(errors).unwrap_or(u32::MAX));
            let error_rate = err_f64 / req_f64;
            if error_rate > self.config.defense.error_rate_threshold {
                should_activate = true;
            }
        }

        if should_activate {
            self.activate(now_epoch);
        } else {
            self.deactivate(now_epoch);
        }

        self.error_count.store(0, Ordering::Relaxed);
        self.request_count.store(0, Ordering::Relaxed);
        self.circuit_counts.pin().clear();

        let recovery = self.config.defense.attack_recovery_secs;
        let last_karma_reset = self.last_karma_reset_epoch.load(Ordering::Relaxed);
        let since_last_reset = now_epoch.saturating_sub(last_karma_reset);

        if since_last_reset >= recovery {
            self.prune(now_epoch, recovery);
            self.last_karma_reset_epoch
                .store(now_epoch, Ordering::Relaxed);
        }

        if since_last_reset >= recovery.saturating_mul(3) {
            self.circuit_karma.pin().clear();
            self.blocked_sessions.pin().clear();
            self.challenged_circuits.pin().clear();
        }
    }

    fn prune(&self, now: u64, max_age: u64) {
        let karma = self.circuit_karma.pin();
        let stale_keys: Vec<String> = karma
            .iter()
            .filter(|(_, entry)| {
                now.saturating_sub(entry.last_updated.load(Ordering::Relaxed)) >= max_age
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale_keys {
            karma.remove(key);
        }

        let challenged = self.challenged_circuits.pin();
        let stale_challenged: Vec<String> = challenged
            .iter()
            .filter(|(_, ts)| now.saturating_sub(ts.load(Ordering::Relaxed)) >= max_age)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale_challenged {
            challenged.remove(key);
        }

        let sessions = self.blocked_sessions.pin();
        let stale_sessions: Vec<String> = sessions
            .iter()
            .filter(|(_, ts)| now.saturating_sub(ts.load(Ordering::Relaxed)) >= max_age)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale_sessions {
            sessions.remove(key);
        }
    }

    fn activate(&self, now: u64) {
        let was_normal = self.current_mode.swap(1, Ordering::Relaxed) == 0;
        if was_normal {
            self.defense_activated_at.store(now, Ordering::Relaxed);
            warn!(activated_at = now, action = "defense_on", "defense mode on");
        }
    }

    fn deactivate(&self, now: u64) {
        if self.config.security.waf_mode == WafMode::Defense {
            return;
        }

        let activated_at = self.defense_activated_at.load(Ordering::Relaxed);
        if activated_at == 0 {
            return;
        }

        let elapsed = now.saturating_sub(activated_at);
        if elapsed < self.config.defense.cooldown_secs {
            return;
        }

        let score = self.attack_score();
        if score >= self.config.defense.attack_defense_score {
            debug!(
                score = score,
                threshold = self.config.defense.attack_defense_score,
                "defense on: attack score high"
            );
            return;
        }

        self.current_mode.store(0, Ordering::Relaxed);
        self.defense_activated_at.store(0, Ordering::Relaxed);
        info!(
            cooldown_secs = elapsed,
            score = score,
            action = "defense_off",
            "defense mode off"
        );
    }

    /// Checks if a circuit has exceeded the flood threshold.
    pub fn is_flooding(&self, circuit_id: &str) -> bool {
        let circuit_counts = self.circuit_counts.pin();
        if let Some(count) = circuit_counts.get(circuit_id) {
            let current = count.load(Ordering::Relaxed);
            if current > u64::from(self.config.defense.circuit_flood_threshold) {
                warn!(
                    circuit = circuit_id,
                    count = current,
                    threshold = self.config.defense.circuit_flood_threshold,
                    action = "flood_detected",
                    "circuit flood detected"
                );
                return true;
            }
        }
        false
    }

    /// Checks if defense mode is currently active.
    #[must_use]
    pub fn is_defense_active(&self) -> bool {
        self.current_mode.load(Ordering::Relaxed) == 1
    }

    /// Returns the timestamp when defense mode started.
    #[must_use]
    pub fn activation_time(&self) -> u64 {
        self.defense_activated_at.load(Ordering::Relaxed)
    }

    /// Returns the active WAF operation mode.
    #[must_use]
    pub fn current_mode(&self) -> WafMode {
        if self.current_mode.load(Ordering::Relaxed) == 1 {
            WafMode::Defense
        } else {
            WafMode::Normal
        }
    }

    /// Increments karma points for a circuit.
    pub fn add_karma(&self, circuit_id: &str, points: u32) -> u32 {
        let now = epoch_secs();
        let karma = self.circuit_karma.pin();
        karma.get(circuit_id).map_or_else(
            || {
                karma.insert(
                    circuit_id.to_string(),
                    KarmaEntry {
                        points: AtomicU32::new(points),
                        last_updated: AtomicU64::new(now),
                    },
                );
                points
            },
            |entry| {
                entry.last_updated.store(now, Ordering::Relaxed);
                entry.points.fetch_add(points, Ordering::Relaxed) + points
            },
        )
    }

    /// Retrieves current karma points for a circuit.
    #[must_use]
    pub fn karma(&self, circuit_id: &str) -> u32 {
        self.circuit_karma
            .pin()
            .get(circuit_id)
            .map_or(0, |entry| entry.points.load(Ordering::Relaxed))
    }

    /// Validates if a circuit has exceeded the karma threshold.
    #[must_use]
    pub fn is_malicious(&self, circuit_id: &str) -> bool {
        self.circuit_karma
            .pin()
            .get(circuit_id)
            .is_some_and(|entry| {
                entry.points.load(Ordering::Relaxed) >= self.config.defense.karma_threshold
            })
    }

    /// Checks if a session is explicitly blocked.
    pub fn is_session_blocked(&self, session_id: &str) -> bool {
        self.blocked_sessions.pin().contains_key(session_id)
    }

    /// Permanently blocks a session.
    pub fn block_session(&self, session_id: &str) {
        self.blocked_sessions
            .pin()
            .insert(session_id.to_string(), AtomicU64::new(epoch_secs()));
        warn!(session = %session_id, action = "session_block", "session blocked");
    }

    /// Marks a circuit as challenged (CAPTCHA pending).
    pub fn challenge_circuit(&self, circuit_id: &str) {
        self.challenged_circuits
            .pin()
            .insert(circuit_id.to_string(), AtomicU64::new(epoch_secs()));
    }

    /// Checks if a circuit is currently under challenge.
    #[must_use]
    pub fn has_challenge(&self, circuit_id: &str) -> bool {
        self.challenged_circuits.pin().contains_key(circuit_id)
    }

    /// Clears challenge status for a circuit.
    pub fn resolve_challenge(&self, circuit_id: &str) {
        self.challenged_circuits.pin().remove(circuit_id);
    }

    /// Removes all data associated with a circuit.
    pub fn remove_circuit(&self, circuit_id: &str) {
        self.circuit_karma.pin().remove(circuit_id);
        self.circuit_counts.pin().remove(circuit_id);
        self.attack_circuits.pin().remove(circuit_id);
        self.challenged_circuits.pin().remove(circuit_id);
    }

    /// Records a request from an unverified session.
    pub fn record_unverified(&self) {
        self.attack_unverified_count.fetch_add(1, Ordering::Relaxed);
    }

    fn reset_window(&self) {
        let now = epoch_secs();
        let window_start = self.attack_window_start.load(Ordering::Relaxed);
        if now.saturating_sub(window_start) >= 60 {
            self.attack_unverified_count.store(0, Ordering::Relaxed);
            self.attack_request_count.store(0, Ordering::Relaxed);
            self.attack_circuits.pin().clear();
            self.attack_window_start.store(now, Ordering::Relaxed);
        }
    }

    /// Computes current global attack score.
    #[must_use]
    pub fn attack_score(&self) -> f64 {
        self.reset_window();

        let raw_requests = self.attack_request_count.load(Ordering::Relaxed);
        let circuits_seen = u64::try_from(self.attack_circuits.pin().len()).unwrap_or(u64::MAX);
        let unverified = self.attack_unverified_count.load(Ordering::Relaxed);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = self.attack_window_start.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(window_start).max(1);

        if elapsed < 10 || (raw_requests < 10 && unverified == 0) {
            return 0.0;
        }

        let effective_circuits = circuits_seen;
        if effective_circuits < 3 {
            return 0.0;
        }

        let churn_per_min = effective_circuits.saturating_mul(60) / elapsed;
        let rps = raw_requests / elapsed;

        let rps_threshold = u64::from(self.config.defense.attack_rps_threshold).max(1);
        let churn_threshold = u64::from(self.config.defense.attack_churn_threshold).max(1);
        let req_per_circ_limit = u64::from(self.config.defense.attack_rpc_threshold).max(1);

        let mut score: u64 = 0;

        if churn_per_min > churn_threshold {
            let ratio = (churn_per_min / churn_threshold).min(2);
            score = score.saturating_add(ratio.saturating_mul(15));
        }

        if rps > rps_threshold {
            let ratio = (rps / rps_threshold).min(2);
            score = score.saturating_add(ratio.saturating_mul(10));
        }

        if raw_requests > 0 {
            let unverified_percent = unverified.saturating_mul(100) / raw_requests;
            score = score.saturating_add((unverified_percent.saturating_mul(5)) / 100);
        }

        if effective_circuits >= 5 {
            let avg_req = raw_requests / effective_circuits.max(1);
            if avg_req < req_per_circ_limit {
                let diff = req_per_circ_limit.saturating_sub(avg_req);
                let factor = diff.saturating_mul(100) / req_per_circ_limit;
                score = score.saturating_add((factor.saturating_mul(20)) / 100);
            }
        }

        f64::from(u32::try_from(score).unwrap_or(u32::MAX)) / 10.0
    }

    /// Determines if Tor `PoW` should be activated.
    #[must_use]
    pub fn detect_pow_need(&self) -> Option<u32> {
        if self.pow_enabled.load(Ordering::Relaxed) {
            return None;
        }

        let now = epoch_secs();
        let last_check = self.last_score_check.load(Ordering::Relaxed);
        if now.saturating_sub(last_check) < 5 {
            return None;
        }
        self.last_score_check.store(now, Ordering::Relaxed);

        let score = self.attack_score();
        if score >= self.config.defense.attack_pow_score {
            Some(self.config.defense.attack_pow_effort)
        } else {
            None
        }
    }

    /// Records that `PoW` has been enabled.
    pub fn enable_pow(&self) {
        let now = epoch_secs();
        self.pow_enabled.store(true, Ordering::Relaxed);
        self.pow_enabled_at.store(now, Ordering::Relaxed);
        if !self.is_defense_active() {
            self.activate(now);
        }
        warn!(
            score = self.attack_score(),
            action = "pow_on",
            "pow enabled"
        );
    }

    /// Determines if Tor `PoW` should be deactivated.
    #[must_use]
    pub fn check_pow_expiry(&self) -> bool {
        if !self.pow_enabled.load(Ordering::Relaxed) {
            return false;
        }
        let now = epoch_secs();

        let last_check = self.last_score_check.load(Ordering::Relaxed);
        if now.saturating_sub(last_check) < 5 {
            return false;
        }
        self.last_score_check.store(now, Ordering::Relaxed);

        let enabled_at = self.pow_enabled_at.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(enabled_at);
        let score = self.attack_score();
        elapsed >= self.config.defense.attack_recovery_secs
            && score < self.config.defense.attack_defense_score
    }

    /// Records that `PoW` has been disabled.
    pub fn disable_pow(&self) {
        self.pow_enabled.store(false, Ordering::Relaxed);
        self.pow_enabled_at.store(0, Ordering::Relaxed);
        info!(action = "pow_off", "pow disabled: recovery");
    }

    /// Determines if automated defense should be activated.
    #[must_use]
    pub fn assess_defense(&self) -> bool {
        let score = self.attack_score();
        score >= self.config.defense.attack_defense_score
    }

    /// Activates automated defense mode.
    pub fn trigger_defense(&self) -> bool {
        if self.is_defense_active() {
            return false;
        }

        let now = epoch_secs();
        let last_check = self.last_score_check.load(Ordering::Relaxed);
        if now.saturating_sub(last_check) < 5 {
            return false;
        }

        if self.assess_defense() {
            self.activate(now);
            return true;
        }
        false
    }

    /// Checks if Tor `PoW` is currently active.
    #[must_use]
    pub fn is_pow(&self) -> bool {
        self.pow_enabled.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cfg() -> Arc<Config> {
        Arc::new(Config {
            network: crate::config::settings::NetworkSettings::default(),
            tor: crate::config::settings::TorSettings::default(),
            security: crate::config::settings::SecuritySettings::default(),
            captcha: crate::config::settings::CaptchaSettings::default(),
            session: crate::config::settings::SessionSettings::default(),
            defense: crate::config::settings::DefenseSettings {
                karma_threshold: 50,
                circuit_flood_threshold: 10,
                cooldown_secs: 60,
                attack_churn_threshold: 30,
                attack_rps_threshold: 30,
                attack_rpc_threshold: 5,
                attack_defense_score: 2.0,
                attack_pow_score: 4.0,
                attack_pow_effort: 5,
                attack_recovery_secs: 300,
                rate_limit_rps: 10,
                rate_limit_burst: 20,
                error_rate_threshold: 0.5,
            },
            meta: crate::config::settings::MetaSettings::default(),
            webhook: crate::config::settings::WebhookSettings::default(),
            features: crate::config::settings::FeatureFlags::default(),
            log_format: "json".to_string(),
        })
    }

    #[test]
    fn karma_logic() {
        let monitor = DefenseMonitor::new(cfg());

        assert_eq!(monitor.karma("circuit_id"), 0);
        assert!(!monitor.is_malicious("circuit_id"));

        monitor.add_karma("circuit_id", 10);
        assert_eq!(monitor.karma("circuit_id"), 10);
        assert!(!monitor.is_malicious("circuit_id"));

        monitor.add_karma("circuit_id", 40);
        assert_eq!(monitor.karma("circuit_id"), 50);
        assert!(monitor.is_malicious("circuit_id"));
        assert!(monitor.is_circuit_blocked("circuit_id"));

        assert!(!monitor.is_circuit_banned("circuit_id"));
        monitor.add_karma("circuit_id", 200);
        assert!(monitor.is_circuit_banned("circuit_id"));

        assert!(!monitor.is_flooding("circuit_flood"));
        for _ in 0..11 {
            monitor.record_request(Some("circuit_flood"), false, TrackMode::GlobalAndLocal);
        }
        assert!(monitor.is_flooding("circuit_flood"));

        assert!(!monitor.is_session_blocked("session_id"));
        monitor.block_session("session_id");
        assert!(monitor.is_session_blocked("session_id"));

        assert!(!monitor.has_challenge("circuit_challenge"));
        monitor.challenge_circuit("circuit_challenge");
        assert!(monitor.has_challenge("circuit_challenge"));
        monitor.resolve_challenge("circuit_challenge");
        assert!(!monitor.has_challenge("circuit_challenge"));

        assert!(!monitor.is_defense_active());
        assert_eq!(monitor.current_mode(), WafMode::Normal);

        let defense_config = Arc::new(Config {
            security: crate::config::settings::SecuritySettings {
                waf_mode: WafMode::Defense,
                ..crate::config::settings::SecuritySettings::default()
            },
            ..(*cfg()).clone()
        });
        let defense_monitor = DefenseMonitor::new(defense_config);
        assert!(defense_monitor.is_defense_active());
        assert_eq!(defense_monitor.current_mode(), WafMode::Defense);

        let score = monitor.attack_score();
        assert!(score < 1.0);
        assert!(!monitor.assess_defense());
        assert!(!monitor.is_pow());
        assert!(monitor.detect_pow_need().is_none());
        assert!(!monitor.check_pow_expiry());
        assert_eq!(monitor.activation_time(), 0);

        monitor.enable_pow();
        assert!(monitor.is_pow());
        assert!(monitor.is_defense_active());
        assert!(monitor.activation_time() > 0);

        monitor.disable_pow();
        assert!(!monitor.is_pow());

        monitor.record_unverified();
        monitor.record_unverified();

        assert!(!monitor.trigger_defense());
    }

    #[test]
    fn removal_cleanup() {
        let monitor = DefenseMonitor::new(cfg());
        let cid = "circuit-gc-test";

        monitor.add_karma(cid, 100);
        monitor.record_request(Some(cid), false, TrackMode::GlobalAndLocal);
        monitor.challenge_circuit(cid);

        assert!(monitor.is_circuit_blocked(cid));
        assert!(monitor.has_challenge(cid));
        assert!(monitor.attack_circuits.pin().contains_key(cid));
        assert!(monitor.circuit_counts.pin().contains_key(cid));

        monitor.remove_circuit(cid);

        assert_eq!(monitor.karma(cid), 0);
        assert!(!monitor.is_circuit_blocked(cid));
        assert!(!monitor.has_challenge(cid));
        assert!(!monitor.attack_circuits.pin().contains_key(cid));
        assert!(!monitor.circuit_counts.pin().contains_key(cid));
    }

    #[test]
    fn session_isolation() {
        let monitor = DefenseMonitor::new(cfg());
        let cid = "circuit-sess-test";
        let sid = "session-persisted";

        monitor.add_karma(cid, 50);
        monitor.block_session(sid);

        monitor.remove_circuit(cid);

        assert!(monitor.is_session_blocked(sid));
    }

    #[test]
    fn stale_cleanup() {
        let monitor = DefenseMonitor::new(cfg());
        let stale_cid = "stale-circuit";
        let fresh_cid = "fresh-circuit";

        monitor.add_karma(stale_cid, 50);

        std::thread::sleep(std::time::Duration::from_secs(2));
        monitor.add_karma(fresh_cid, 50);

        assert!(monitor.is_circuit_blocked(stale_cid));
        assert!(monitor.is_circuit_blocked(fresh_cid));

        monitor.prune(epoch_secs(), 1);

        assert!(!monitor.is_circuit_blocked(stale_cid));
        assert!(monitor.is_circuit_blocked(fresh_cid));
    }
}
