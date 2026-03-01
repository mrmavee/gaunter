//! CAPTCHA lifecycle management.
//!
//! Coordinates CAPTCHA generation, background worker, and verification.

use crate::config::Config;
use crate::error::Result;
use crate::security::captcha::generator::{CaptchaGenerator, CharPosition, Difficulty};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

pub struct CachedCaptcha {
    pub passcode: String,
    pub img: String,
    pub pos: Vec<CharPosition>,
}

/// CAPTCHA manager and generator bridge.
pub struct CaptchaManager {
    generator: Arc<CaptchaGenerator>,
    queue: Arc<Mutex<VecDeque<CachedCaptcha>>>,
    condvar: Arc<Condvar>,
}

impl CaptchaManager {
    /// Initializes a new `CaptchaManager`.
    ///
    /// # Errors
    /// Returns error if generator fails to initialize.
    pub fn try_new(config: &Arc<Config>) -> Result<Self> {
        let difficulty: Difficulty = config
            .captcha
            .difficulty
            .parse()
            .unwrap_or(Difficulty::Medium);
        Ok(Self {
            generator: Arc::new(CaptchaGenerator::try_new(
                &config.captcha.secret,
                config.captcha.ttl,
                difficulty,
            )?),
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(50))),
            condvar: Arc::new(Condvar::new()),
        })
    }

    /// Starts the background generation worker.
    pub fn start_worker(&self) {
        let generator = Arc::clone(&self.generator);
        let queue = Arc::clone(&self.queue);
        let condvar = Arc::clone(&self.condvar);

        thread::spawn(move || {
            loop {
                let mut lock = queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if lock.len() >= 50 {
                    lock = condvar
                        .wait(lock)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                drop(lock);

                if let Ok((passcode, img, pos)) = generator.generate() {
                    let cached = CachedCaptcha { passcode, img, pos };
                    let mut lock = queue
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    lock.push_back(cached);
                }
            }
        });
    }

    /// Retrieves a pre-generated CAPTCHA.
    ///
    /// # Errors
    /// Returns error if the queue is empty or generator fails.
    pub fn generate(&self) -> Result<(String, String, Vec<CharPosition>)> {
        let mut lock = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cached) = lock.pop_front() {
            self.condvar.notify_one();
            let token = self.generator.create_token(&cached.passcode)?;
            return Ok((token, cached.img, cached.pos));
        }
        drop(lock);

        let (passcode, img, pos) = self.generator.generate()?;
        let token = self.generator.create_token(&passcode)?;
        Ok((token, img, pos))
    }

    /// Verifies a CAPTCHA solution.
    #[must_use]
    pub fn verify(&self, token: &str, answer: &str) -> bool {
        self.generator.verify(token, answer)
    }

    /// Creates a signed CAPTCHA token.
    ///
    /// # Errors
    /// Returns error if token signing fails.
    pub fn create_token(&self, input: &str) -> Result<String> {
        self.generator.create_token(input)
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
            captcha: crate::config::settings::CaptchaSettings {
                secret: "captcha_master_secret_key_v1".to_string(),
                ttl: 300,
                difficulty: "medium".to_string(),
                gen_limit: 5,
                max_failures: 3,
            },
            session: crate::config::settings::SessionSettings::default(),
            defense: crate::config::settings::DefenseSettings::default(),
            meta: crate::config::settings::MetaSettings::default(),
            webhook: crate::config::settings::WebhookSettings::default(),
            features: crate::config::settings::FeatureFlags::default(),
            log_format: "json".to_string(),
        })
    }

    #[test]
    fn lifecycle() {
        let mgr = CaptchaManager::try_new(&cfg()).unwrap();

        let (tok, img, _) = mgr.generate().unwrap();
        assert!(!tok.is_empty());
        assert!(!img.is_empty());

        assert!(!mgr.verify(&tok, "mismatch"));

        let tok2 = mgr.create_token("CAPTCHA").unwrap();
        assert!(mgr.verify(&tok2, "CAPTCHA"));
        assert!(!mgr.verify(&tok2, "INVALID"));

        assert!(!mgr.verify("invalid-token", "CAPTCHA"));
        assert!(!mgr.verify("", ""));
    }
}
