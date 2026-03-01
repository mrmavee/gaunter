//! Tor control protocol integration.
//!
//! Provides interface to Tor Control Port for managing Proof-of-Work (`PoW`) defenses.

use std::net::SocketAddr;
use tracing::{error, info};

use crate::error::{Error, Result};

/// Tor Control Port interface.
pub struct TorControl {
    addr: SocketAddr,
    password: Option<String>,
}

impl TorControl {
    /// Creates a new `TorControl` instance.
    #[must_use]
    pub const fn new(addr: SocketAddr, password: Option<String>) -> Self {
        Self { addr, password }
    }

    /// Enables Tor Proof-of-Work defense.
    ///
    /// # Errors
    /// Returns error if control port command fails.
    pub async fn enable_pow(&self, _onion_addr: &str, effort: u32) -> Result<()> {
        let mut ctrl = stem_rs::Controller::from_port(self.addr)
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        ctrl.authenticate(self.password.as_deref())
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        let burst = effort * 2;

        for (key, val) in [
            ("HiddenServiceEnableIntroDoSDefense", "1".to_string()),
            ("HiddenServicePoWDefensesEnabled", "1".to_string()),
            ("HiddenServicePoWQueueRate", effort.to_string()),
            ("HiddenServicePoWQueueBurst", burst.to_string()),
        ] {
            ctrl.set_conf(key, &val)
                .await
                .map_err(|e| Error::TorControl(format!("{key}: {e}")))?;
        }

        info!(effort, action = "pow_on", "pow enabled at effort {effort}");
        Ok(())
    }

    /// Disables Tor Proof-of-Work defense.
    ///
    /// # Errors
    /// Returns error if control port command fails.
    pub async fn disable_pow(&self) -> Result<()> {
        let mut ctrl = stem_rs::Controller::from_port(self.addr)
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        ctrl.authenticate(self.password.as_deref())
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        for key in [
            "HiddenServicePoWDefensesEnabled",
            "HiddenServiceEnableIntroDoSDefense",
        ] {
            if let Err(e) = ctrl.reset_conf(key).await {
                error!(key, error = %e, "failed to reset tor config: {key}");
            }
        }

        info!(action = "pow_off", "pow disabled");
        Ok(())
    }
}
