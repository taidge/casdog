use crate::error::{AppError, AppResult};
use super::notification_provider::NotificationProvider;
use async_trait::async_trait;
use serde::Serialize;

pub struct LarkNotifyProvider {
    webhook_url: String,
    _secret: Option<String>,
}

impl LarkNotifyProvider {
    pub fn new(webhook_url: String, secret: Option<String>) -> Self {
        Self {
            webhook_url,
            _secret: secret  // Secret-based signing not implemented yet, requires hmac crate
        }
    }
}

#[derive(Serialize)]
struct LarkMessage {
    msg_type: String,
    content: LarkContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sign: Option<String>,
}

#[derive(Serialize)]
struct LarkContent {
    post: LarkPost,
}

#[derive(Serialize)]
struct LarkPost {
    zh_cn: LarkPostContent,
}

#[derive(Serialize)]
struct LarkPostContent {
    title: String,
    content: Vec<Vec<LarkContentItem>>,
}

#[derive(Serialize)]
struct LarkContentItem {
    tag: String,
    text: String,
}

#[async_trait]
impl NotificationProvider for LarkNotifyProvider {
    async fn send(&self, title: &str, content: &str, _receiver: &str) -> AppResult<()> {
        let client = reqwest::Client::new();

        // Note: Signature support requires hmac crate - add to Cargo.toml if needed
        let timestamp = None;
        let sign = None;

        let payload = LarkMessage {
            msg_type: "post".to_string(),
            content: LarkContent {
                post: LarkPost {
                    zh_cn: LarkPostContent {
                        title: title.to_string(),
                        content: vec![vec![LarkContentItem {
                            tag: "text".to_string(),
                            text: content.to_string(),
                        }]],
                    },
                },
            },
            timestamp,
            sign,
        };

        let resp = client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Lark send failed: {}", e)))?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!("Lark webhook error: {}", error_text)));
        }

        Ok(())
    }

    fn provider_type(&self) -> &str {
        "Lark"
    }
}
