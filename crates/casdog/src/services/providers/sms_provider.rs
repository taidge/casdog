use crate::error::{AppError, AppResult};
use async_trait::async_trait;

/// Trait for SMS sending providers
#[async_trait]
pub trait SmsProviderTrait: Send + Sync {
    async fn send_sms(&self, to: &str, content: &str) -> AppResult<()>;
}

/// Twilio SMS provider
pub struct TwilioSmsProvider {
    account_sid: String,
    auth_token: String,
    from_number: String,
}

impl TwilioSmsProvider {
    pub fn new(account_sid: String, auth_token: String, from_number: String) -> Self {
        Self {
            account_sid,
            auth_token,
            from_number,
        }
    }
}

#[async_trait]
impl SmsProviderTrait for TwilioSmsProvider {
    async fn send_sms(&self, to: &str, content: &str) -> AppResult<()> {
        let client = reqwest::Client::new();
        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.account_sid
        );

        let resp = client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&[
                ("To", to),
                ("From", &self.from_number),
                ("Body", content),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Twilio SMS send failed: {}", e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!("Twilio SMS failed: {}", body)));
        }

        Ok(())
    }
}

/// HTTP API-based SMS provider (generic)
pub struct HttpSmsProvider {
    api_url: String,
    api_key: String,
    from_number: String,
}

impl HttpSmsProvider {
    pub fn new(api_url: String, api_key: String, from_number: String) -> Self {
        Self {
            api_url,
            api_key,
            from_number,
        }
    }
}

#[async_trait]
impl SmsProviderTrait for HttpSmsProvider {
    async fn send_sms(&self, to: &str, content: &str) -> AppResult<()> {
        let client = reqwest::Client::new();
        let resp = client
            .post(&self.api_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&serde_json::json!({
                "to": to,
                "from": self.from_number,
                "body": content,
            }))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("SMS send failed: {}", e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!("SMS send failed: {}", body)));
        }

        Ok(())
    }
}
