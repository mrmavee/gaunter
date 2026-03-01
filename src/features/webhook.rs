//! Webhook notifications.
//!
//! Handles asynchronous dispatch of security alerts to external endpoints.

use crate::config::Config;
use crate::error::Result;
use reqwest::Client;
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, error};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    DefenseModeActivated,
    DefenseModeDeactivated,
    RateLimitExceeded,
    CircuitBlocked,
    CircuitChallenged,
    SessionBlocked,
    HighErrorRate,
    WafBlock,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event_type: EventType,
    pub timestamp: i64,
    pub circuit_id: Option<String>,
    pub severity: u8,
    pub message: String,
}

/// Dispatches security alerts via webhooks.
pub struct WebhookNotifier {
    client: Client,
    webhook_url: Option<Arc<String>>,
    webhook_token: Option<Arc<String>>,
}

impl WebhookNotifier {
    /// Creates a new `WebhookNotifier` instance.
    #[must_use]
    pub fn new(config: &Arc<Config>) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            webhook_url: config.webhook.url.clone().map(Arc::new),
            webhook_token: config.webhook.token.clone().map(Arc::new),
        }
    }

    /// Sends an asynchronous security alert.
    pub fn notify(&self, payload: WebhookPayload) {
        let Some(url) = self.webhook_url.clone() else {
            return;
        };

        let client = self.client.clone();
        let token = self.webhook_token.clone();
        tokio::spawn(async move {
            if let Err(e) =
                Self::send_notification(&client, &url, token.as_ref().map(|s| s.as_str()), &payload)
                    .await
            {
                error!(error = %e, "webhook failed");
            }
        });
    }

    async fn send_notification(
        client: &Client,
        url: &str,
        token: Option<&str>,
        payload: &WebhookPayload,
    ) -> Result<()> {
        let (tags, title) = match payload.event_type {
            EventType::DefenseModeActivated => ("shield,red_circle", "Defense Mode Activated"),
            EventType::DefenseModeDeactivated => {
                ("shield,green_circle", "Defense Mode Deactivated")
            }
            EventType::RateLimitExceeded => ("snail,warning", "Rate Limit Exceeded"),
            EventType::CircuitBlocked => ("no_entry_sign,tor", "Circuit Blocked"),
            EventType::CircuitChallenged => ("question,shield", "Circuit Challenged"),
            EventType::HighErrorRate => ("chart_with_upwards_trend,fire", "High Error Rate"),
            EventType::WafBlock => ("shield,stop_sign", "WAF Block"),
            EventType::SessionBlocked => ("lock,ban", "Session Blocked"),
        };

        let mut req = client
            .post(url)
            .header("Title", title)
            .header("Priority", payload.severity.to_string())
            .header("Tags", tags)
            .body(payload.message.clone());

        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }

        req.send().await?;

        debug!(event = ?payload.event_type, "webhook sent");
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cfg(url: Option<&str>, token: Option<&str>) -> Arc<Config> {
        Arc::new(Config {
            network: crate::config::settings::NetworkSettings::default(),
            tor: crate::config::settings::TorSettings::default(),
            security: crate::config::settings::SecuritySettings::default(),
            captcha: crate::config::settings::CaptchaSettings::default(),
            session: crate::config::settings::SessionSettings::default(),
            defense: crate::config::settings::DefenseSettings::default(),
            meta: crate::config::settings::MetaSettings::default(),
            webhook: crate::config::settings::WebhookSettings {
                url: url.map(String::from),
                token: token.map(String::from),
            },
            features: crate::config::settings::FeatureFlags::default(),
            log_format: "json".to_string(),
        })
    }

    #[test]
    fn notify_and_serialize() {
        let notifier = WebhookNotifier::new(&cfg(None, None));
        notifier.notify(WebhookPayload {
            event_type: EventType::WafBlock,
            timestamp: 1_000_000,
            circuit_id: Some("circuit_id".to_string()),
            severity: 5,
            message: "security_violation".to_string(),
        });

        let _ = WebhookNotifier::new(&cfg(
            Some("https://ntfy.example.com/alerts"),
            Some("api_token"),
        ));
    }

    #[test]
    fn serialization() {
        let events = vec![
            EventType::DefenseModeActivated,
            EventType::DefenseModeDeactivated,
            EventType::RateLimitExceeded,
            EventType::CircuitBlocked,
            EventType::CircuitChallenged,
            EventType::SessionBlocked,
            EventType::HighErrorRate,
            EventType::WafBlock,
        ];
        for e in events {
            let p = WebhookPayload {
                event_type: e,
                timestamp: 0,
                circuit_id: None,
                severity: 1,
                message: "x".to_string(),
            };
            let j = serde_json::to_string(&p).unwrap();
            assert!(j.contains("event_type"));
        }
    }
}
