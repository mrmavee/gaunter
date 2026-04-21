//! Tor control protocol integration.
//!
//! Provides interface to Tor Control Port for managing Proof-of-Work (`PoW`) defenses.

use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

use crate::error::{Error, Result};

/// Tor Control Port interface.
pub struct TorControl {
    addr: SocketAddr,
    password: Option<String>,
    torrc_path: PathBuf,
}

impl TorControl {
    /// Creates a new `TorControl` instance.
    #[must_use]
    pub fn new(addr: SocketAddr, password: Option<String>, torrc_path: Option<PathBuf>) -> Self {
        Self {
            addr,
            password,
            torrc_path: torrc_path.unwrap_or_else(|| PathBuf::from("/etc/tor/torrc")),
        }
    }

    /// Enables Tor Proof-of-Work defense.
    ///
    /// # Errors
    /// Returns error if control port command fails.
    pub async fn enable_pow(&self, effort: u32) -> Result<()> {
        let burst = effort * 2;
        let cmd = self.build_hs_setconf(Some(effort), Some(burst)).await?;

        let mut ctrl = stem_rs::Controller::from_port(self.addr)
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        ctrl.authenticate(self.password.as_deref())
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        ctrl.msg(&cmd)
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        info!(effort, action = "pow_on", "pow enabled at effort {effort}");
        Ok(())
    }

    /// Disables Tor Proof-of-Work defense.
    ///
    /// # Errors
    /// Returns error if control port command fails.
    pub async fn disable_pow(&self) -> Result<()> {
        let cmd = self.build_hs_setconf(None, None).await?;

        let mut ctrl = stem_rs::Controller::from_port(self.addr)
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        ctrl.authenticate(self.password.as_deref())
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        ctrl.msg(&cmd)
            .await
            .map_err(|e| Error::TorControl(e.to_string()))?;

        info!(action = "pow_off", "pow disabled");
        Ok(())
    }

    async fn build_hs_setconf(
        &self,
        rate_override: Option<u32>,
        burst_override: Option<u32>,
    ) -> Result<String> {
        let torrc = tokio::fs::read_to_string(&self.torrc_path)
            .await
            .map_err(|e| {
                Error::TorControl(format!("read torrc {}: {e}", self.torrc_path.display()))
            })?;

        hs_setconf(&torrc, rate_override, burst_override)
    }
}

/// Builds a batched SETCONF command from torrc.
///
/// # Errors
/// Returns error if no `HiddenService` options are found.
#[cfg(any(fuzzing, feature = "fuzzing", feature = "testing"))]
pub fn hs_setconf(
    torrc: &str,
    rate_override: Option<u32>,
    burst_override: Option<u32>,
) -> Result<String> {
    hs_setconf_inner(torrc, rate_override, burst_override)
}

#[cfg(not(any(fuzzing, feature = "fuzzing", feature = "testing")))]
fn hs_setconf(
    torrc: &str,
    rate_override: Option<u32>,
    burst_override: Option<u32>,
) -> Result<String> {
    hs_setconf_inner(torrc, rate_override, burst_override)
}

fn hs_setconf_inner(
    torrc: &str,
    rate_override: Option<u32>,
    burst_override: Option<u32>,
) -> Result<String> {
    let mut blocks: Vec<Vec<(&str, &str)>> = Vec::new();
    let mut current: Vec<(&str, &str)> = Vec::new();

    for line in torrc.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.starts_with("HiddenService") {
            continue;
        }
        let Some(ws) = trimmed.find(char::is_whitespace) else {
            continue;
        };
        let key = &trimmed[..ws];
        let val = trimmed[ws..].trim();
        if key == "HiddenServiceDir" && !current.is_empty() {
            blocks.push(std::mem::take(&mut current));
        }
        current.push((key, val));
    }
    if !current.is_empty() {
        blocks.push(current);
    }

    if blocks.is_empty() {
        return Err(Error::TorControl(
            "no HiddenService options found in torrc".to_string(),
        ));
    }

    let mut out = String::with_capacity(torrc.len() + 128);
    out.push_str("SETCONF");

    for block in &blocks {
        let is_pow_block = block.iter().any(|&(k, _)| {
            k.starts_with("HiddenServicePoW") || k.starts_with("HiddenServiceEnableIntroDoS")
        });

        let mut has_rate = false;
        let mut has_burst = false;

        for &(key, val) in block {
            if key == "HiddenServicePoWQueueRate" && is_pow_block {
                has_rate = true;
                if let Some(rate) = rate_override {
                    out.push_str(" HiddenServicePoWQueueRate=");
                    out.push_str(&rate.to_string());
                    continue;
                }
            }
            if key == "HiddenServicePoWQueueBurst" && is_pow_block {
                has_burst = true;
                if let Some(burst) = burst_override {
                    out.push_str(" HiddenServicePoWQueueBurst=");
                    out.push_str(&burst.to_string());
                    continue;
                }
            }

            out.push(' ');
            out.push_str(key);
            out.push('=');
            if val.contains(' ') {
                out.push('"');
                for c in val.chars() {
                    if c == '\\' || c == '"' {
                        out.push('\\');
                    }
                    out.push(c);
                }
                out.push('"');
            } else {
                out.push_str(val);
            }
        }

        if is_pow_block {
            if let (false, Some(rate)) = (has_rate, rate_override) {
                out.push_str(" HiddenServicePoWQueueRate=");
                out.push_str(&rate.to_string());
            }
            if let (false, Some(burst)) = (has_burst, burst_override) {
                out.push_str(" HiddenServicePoWQueueBurst=");
                out.push_str(&burst.to_string());
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::hs_setconf;

    const TORRC: &str = r"
HiddenServiceDir /var/lib/tor/hs_a/
HiddenServicePort 80 127.0.0.1:8080
HiddenServicePoWDefensesEnabled 1
HiddenServicePoWQueueRate 50
HiddenServicePoWQueueBurst 100
HiddenServiceEnableIntroDoSDefense 1
HiddenServiceEnableIntroDoSRatePerSec 10
HiddenServiceEnableIntroDoSBurstPerSec 50
HiddenServiceMaxStreams 20
HiddenServiceMaxStreamsCloseCircuit 1
";

    const TORRC_TWO_HS: &str = r"
HiddenServiceDir /var/lib/tor/hs_a/
HiddenServicePort 80 127.0.0.1:8080
HiddenServicePoWDefensesEnabled 1
HiddenServicePoWQueueRate 50
HiddenServicePoWQueueBurst 100
HiddenServiceEnableIntroDoSDefense 1
HiddenServiceMaxStreams 20

HiddenServiceDir /var/lib/tor/hs_b/
HiddenServicePort 80 127.0.0.1:7777
";

    #[test]
    fn single_hs() {
        assert!(hs_setconf("# comment\n", None, None).is_err());

        let baseline = hs_setconf(TORRC, None, None).expect("baseline");
        assert!(baseline.starts_with("SETCONF "));
        assert!(baseline.contains("HiddenServiceDir=/var/lib/tor/hs_a/"));
        assert!(baseline.contains("HiddenServicePoWQueueRate=50"));
        assert!(baseline.contains("HiddenServicePoWQueueBurst=100"));
        assert!(baseline.contains("HiddenServicePort=\"80 127.0.0.1:8080\""));

        let ov = hs_setconf(TORRC, Some(5), Some(10)).expect("override");
        assert!(ov.contains("HiddenServicePoWQueueRate=5"));
        assert!(ov.contains("HiddenServicePoWQueueBurst=10"));
        assert!(!ov.contains("HiddenServicePoWQueueRate=50"));

        let no_rate = "HiddenServiceDir /var/lib/tor/hs/\nHiddenServicePoWDefensesEnabled 1\n";
        let appended = hs_setconf(no_rate, Some(3), Some(6)).expect("append");
        assert!(appended.contains("HiddenServicePoWQueueRate=3"));
        assert!(appended.contains("HiddenServicePoWQueueBurst=6"));
    }

    #[test]
    fn multi_hs() {
        let cmd = hs_setconf(TORRC_TWO_HS, Some(5), Some(10)).expect("multi");
        assert!(cmd.contains("HiddenServiceDir=/var/lib/tor/hs_a/"));
        assert!(cmd.contains("HiddenServicePoWQueueRate=5"));
        assert!(cmd.contains("HiddenServicePoWQueueBurst=10"));
        assert!(cmd.contains("HiddenServiceDir=/var/lib/tor/hs_b/"));
        assert!(cmd.contains("HiddenServicePort=\"80 127.0.0.1:7777\""));
        let hs_b_pos = cmd.find("/hs_b/").expect("hs_b block missing");
        let rate_pos = cmd.find("QueueRate=5").expect("rate missing");
        assert!(
            rate_pos < hs_b_pos,
            "rate override leaked into non-pow block"
        );
    }
}
