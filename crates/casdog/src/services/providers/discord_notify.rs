use async_trait::async_trait;
use serde_json::json;

use super::notification_provider::NotificationProvider;
use crate::error::{AppError, AppResult};

pub struct DiscordNotifyProvider {
    webhook_url: String,
}

impl DiscordNotifyProvider {
    pub fn new(webhook_url: String) -> Self {
        Self { webhook_url }
    }
}

#[async_trait]
impl NotificationProvider for DiscordNotifyProvider {
    async fn send(&self, title: &str, content: &str, _receiver: &str) -> AppResult<()> {
        let client = reqwest::Client::new();

        let payload = json!({
            "embeds": [{
                "title": title,
                "description": content,
                "color": 5814783 // Blue color
            }]
        });

        let resp = client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Discord send failed: {}", e)))?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Discord webhook error: {}",
                error_text
            )));
        }

        Ok(())
    }

    fn provider_type(&self) -> &str {
        "Discord"
    }
}
