use async_trait::async_trait;
use serde_json::json;

use super::notification_provider::NotificationProvider;
use crate::error::{AppError, AppResult};

pub struct TeamsNotifyProvider {
    webhook_url: String,
}

impl TeamsNotifyProvider {
    pub fn new(webhook_url: String) -> Self {
        Self { webhook_url }
    }
}

#[async_trait]
impl NotificationProvider for TeamsNotifyProvider {
    async fn send(&self, title: &str, content: &str, _receiver: &str) -> AppResult<()> {
        let client = reqwest::Client::new();

        // Use MessageCard format for Teams
        let payload = json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": "0076D7",
            "title": title,
            "sections": [{
                "text": content
            }]
        });

        let resp = client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Teams send failed: {}", e)))?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Teams webhook error: {}",
                error_text
            )));
        }

        Ok(())
    }

    fn provider_type(&self) -> &str {
        "Teams"
    }
}
