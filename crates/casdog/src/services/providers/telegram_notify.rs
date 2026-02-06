use async_trait::async_trait;
use serde::Serialize;

use super::notification_provider::NotificationProvider;
use crate::error::{AppError, AppResult};

pub struct TelegramNotifyProvider {
    bot_token: String,
}

impl TelegramNotifyProvider {
    pub fn new(bot_token: String) -> Self {
        Self { bot_token }
    }
}

#[derive(Serialize)]
struct TelegramMessage {
    chat_id: String,
    text: String,
    parse_mode: String,
}

#[async_trait]
impl NotificationProvider for TelegramNotifyProvider {
    async fn send(&self, title: &str, content: &str, receiver: &str) -> AppResult<()> {
        let client = reqwest::Client::new();

        let message = format!("<b>{}</b>\n\n{}", title, content);

        let payload = TelegramMessage {
            chat_id: receiver.to_string(),
            text: message,
            parse_mode: "HTML".to_string(),
        };

        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        let resp = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Telegram send failed: {}", e)))?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Telegram API error: {}",
                error_text
            )));
        }

        Ok(())
    }

    fn provider_type(&self) -> &str {
        "Telegram"
    }
}
