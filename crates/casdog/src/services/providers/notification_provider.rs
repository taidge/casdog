use crate::error::AppResult;
use async_trait::async_trait;

/// Trait for all notification providers (messaging, webhooks, etc.)
#[async_trait]
pub trait NotificationProvider: Send + Sync {
    /// Send a notification with title and content to a receiver
    ///
    /// # Arguments
    /// * `title` - Notification title/subject
    /// * `content` - Notification body/message
    /// * `receiver` - Receiver identifier (chat_id, channel, webhook URL, etc.)
    async fn send(&self, title: &str, content: &str, receiver: &str) -> AppResult<()>;

    /// Provider type name
    fn provider_type(&self) -> &str;
}

/// Factory function to create a notification provider
pub fn create_notification_provider(
    provider_type: &str,
    token_or_url: &str,
    config: Option<&str>,
) -> AppResult<Box<dyn NotificationProvider>> {
    match provider_type {
        "Telegram" => Ok(Box::new(super::telegram_notify::TelegramNotifyProvider::new(
            token_or_url.to_string(),
        ))),
        "Slack" => Ok(Box::new(super::slack_notify::SlackNotifyProvider::new(
            token_or_url.to_string(),
        ))),
        "Discord" => Ok(Box::new(super::discord_notify::DiscordNotifyProvider::new(
            token_or_url.to_string(),
        ))),
        "DingTalk" => Ok(Box::new(super::dingtalk_notify::DingTalkNotifyProvider::new(
            token_or_url.to_string(),
            config.map(|s| s.to_string()),
        ))),
        "Lark" => Ok(Box::new(super::lark_notify::LarkNotifyProvider::new(
            token_or_url.to_string(),
            config.map(|s| s.to_string()),
        ))),
        "Teams" => Ok(Box::new(super::teams_notify::TeamsNotifyProvider::new(
            token_or_url.to_string(),
        ))),
        "CustomHTTP" => Ok(Box::new(super::custom_http_notify::CustomHttpNotifyProvider::new(
            token_or_url.to_string(),
            config,
        ))),
        _ => Err(crate::error::AppError::Internal(
            format!("Unknown notification provider type: {}", provider_type)
        )),
    }
}
