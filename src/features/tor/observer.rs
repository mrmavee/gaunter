//! Tor event observer.
//!
//! Listens to Tor Control Port events to monitor circuit bandwidth and lifecycle.

use crate::security::defense::DefenseMonitor;
use std::net::SocketAddr;
use std::sync::Arc;
use stem_rs::events::ParsedEvent;
use stem_rs::{CircStatus, EventType, StreamStatus};
use tracing::{debug, error, info, trace, warn};

/// Tor event observer and monitor bridge.
pub struct TorObserver {
    addr: SocketAddr,
    password: Option<String>,
    monitor: Arc<DefenseMonitor>,
}

fn tor_key(id: &impl std::fmt::Display) -> String {
    format!("tor:{id}")
}

impl TorObserver {
    /// Creates a new `TorObserver` instance.
    #[must_use]
    pub const fn new(
        addr: SocketAddr,
        password: Option<String>,
        monitor: Arc<DefenseMonitor>,
    ) -> Self {
        Self {
            addr,
            password,
            monitor,
        }
    }

    /// Starts the event observation loop.
    pub async fn run(&self) {
        loop {
            if let Err(e) = self.observe_loop().await {
                error!(error = %e, "observer disconnected: reconnecting in 10s");
            }
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }

    async fn observe_loop(&self) -> Result<(), stem_rs::Error> {
        let mut ctrl = stem_rs::Controller::from_port(self.addr).await?;
        ctrl.authenticate(self.password.as_deref()).await?;

        let version = ctrl.get_version().await?;
        info!(version = %version, "observer connected");

        ctrl.set_events(&[EventType::Circ, EventType::CircBw, EventType::Stream])
            .await?;

        let stream_counts: papaya::HashMap<String, std::sync::atomic::AtomicU32> =
            papaya::HashMap::new();

        let config = self.monitor.config();

        loop {
            let event = ctrl.recv_event().await?;
            match event {
                ParsedEvent::Circuit(ev) => {
                    let key = tor_key(&ev.id);
                    trace!(id = %ev.id, "observer event detected");

                    match ev.status {
                        CircStatus::Closed | CircStatus::Failed => {
                            self.monitor.remove_circuit(&key);
                            stream_counts.pin().remove(&key);
                            debug!(circuit = %key, status = ?ev.status, "circuit closed");
                        }
                        _ => {}
                    }
                }

                ParsedEvent::CircuitBandwidth(ev) => {
                    let total = ev.read.saturating_add(ev.written);
                    if total > config.tor.bandwidth_abuse_threshold {
                        let key = tor_key(&ev.id);
                        warn!(
                            circuit = %key,
                            bytes = total,
                            action = "abuse_detected",
                            "bandwidth abuse detected"
                        );
                        self.monitor.add_karma(&key, 30);
                    }
                }

                ParsedEvent::Stream(ev) => {
                    if ev.status == StreamStatus::New
                        && let Some(circ_id) = ev.circuit_id.as_ref()
                    {
                        let key = tor_key(circ_id);
                        let counts = stream_counts.pin();
                        let count = counts.get(&key).map_or(1, |v| {
                            v.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
                        });
                        if count == 1 {
                            counts.insert(key.clone(), std::sync::atomic::AtomicU32::new(1));
                        }
                        if count > config.tor.stream_flood_threshold {
                            warn!(
                                circuit = %key,
                                streams = count,
                                action = "exhaustion_detected",
                                "stream exhaustion detected"
                            );
                            self.monitor.add_karma(&key, 20);
                        }
                    }
                }

                _ => {}
            }
        }
    }
}
