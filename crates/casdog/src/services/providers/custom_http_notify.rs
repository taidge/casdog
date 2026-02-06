use async_trait::async_trait;
use serde_json::json;

use super::notification_provider::NotificationProvider;
use crate::error::{AppError, AppResult};

pub struct CustomHttpNotifyProvider {
    url: String,
    headers: Vec<(String, String)>,
}

impl CustomHttpNotifyProvider {
    pub fn new(url: String, config: Option<&str>) -> Self {
        let headers = config
            .and_then(|c| serde_json::from_str::<Vec<(String, String)>>(c).ok())
            .unwrap_or_default();

        Self { url, headers }
    }
}

#[async_trait]
impl NotificationProvider for CustomHttpNotifyProvider {
    async fn send(&self, title: &str, content: &str, receiver: &str) -> AppResult<()> {
        let client = reqwest::Client::new();

        let payload = json!({
            "title": title,
            "content": content,
            "receiver": receiver,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let mut request = client.post(&self.url).json(&payload);

        // Add custom headers
        for (key, value) in &self.headers {
            request = request.header(key, value);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Custom HTTP send failed: {}", e)))?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Custom HTTP error: {}",
                error_text
            )));
        }

        Ok(())
    }

    fn provider_type(&self) -> &str {
        "CustomHTTP"
    }
}
