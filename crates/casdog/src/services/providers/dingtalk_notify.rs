use async_trait::async_trait;
use serde::Serialize;

use super::notification_provider::NotificationProvider;
use crate::error::{AppError, AppResult};

pub struct DingTalkNotifyProvider {
    webhook_url: String,
    _secret: Option<String>,
}

impl DingTalkNotifyProvider {
    pub fn new(webhook_url: String, secret: Option<String>) -> Self {
        Self {
            webhook_url,
            _secret: secret, // Secret-based signing not implemented yet, requires hmac crate
        }
    }
}

#[derive(Serialize)]
struct DingTalkMessage {
    msgtype: String,
    markdown: DingTalkMarkdown,
}

#[derive(Serialize)]
struct DingTalkMarkdown {
    title: String,
    text: String,
}

#[async_trait]
impl NotificationProvider for DingTalkNotifyProvider {
    async fn send(&self, title: &str, content: &str, _receiver: &str) -> AppResult<()> {
        let client = reqwest::Client::new();

        let url = self.webhook_url.clone();
        // Note: Signature support requires hmac crate - add to Cargo.toml if needed

        let text = format!("## {}\n\n{}", title, content);

        let payload = DingTalkMessage {
            msgtype: "markdown".to_string(),
            markdown: DingTalkMarkdown {
                title: title.to_string(),
                text,
            },
        };

        let resp = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DingTalk send failed: {}", e)))?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "DingTalk webhook error: {}",
                error_text
            )));
        }

        Ok(())
    }

    fn provider_type(&self) -> &str {
        "DingTalk"
    }
}
