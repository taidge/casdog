use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;

use crate::error::{AppError, AppResult};
use crate::services::providers::email_provider::EmailProviderTrait;

/// SendGrid email provider
pub struct SendGridEmailProvider {
    client: Client,
    api_key: String,
    from_address: String,
    from_name: Option<String>,
    api_url: String,
}

#[derive(Debug, Serialize)]
struct SendGridRequest {
    personalizations: Vec<Personalization>,
    from: EmailAddress,
    subject: String,
    content: Vec<Content>,
}

#[derive(Debug, Serialize)]
struct Personalization {
    to: Vec<EmailAddress>,
}

#[derive(Debug, Serialize)]
struct EmailAddress {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct Content {
    #[serde(rename = "type")]
    content_type: String,
    value: String,
}

impl SendGridEmailProvider {
    /// Create a new SendGrid email provider
    pub fn new(api_key: String, from_address: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            from_address,
            from_name: None,
            api_url: "https://api.sendgrid.com/v3/mail/send".into(),
        }
    }

    /// Create provider from database record fields
    pub fn from_provider_record(api_key: &str, from_address: &str) -> Self {
        Self::new(api_key.to_string(), from_address.to_string())
    }
    pub fn with_sender(mut self, sender: &lettre::message::Mailbox) -> Self {
        self.from_address = sender.email.to_string();
        self.from_name = sender.name.clone();
        self
    }
    /// Explicit transport hook for embedded integrations and loopback tests.
    /// Provider records cannot override SendGrid's official gateway.
    pub fn with_api_url(mut self, value: &str) -> AppResult<Self> {
        let url = reqwest::Url::parse(value)
            .map_err(|_| AppError::Validation("Invalid SendGrid API URL".into()))?;
        if (url.scheme() != "https"
            && !(url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(AppError::Validation("Invalid SendGrid API URL".into()));
        }
        self.api_url = url.into();
        Ok(self)
    }
}

#[async_trait]
impl EmailProviderTrait for SendGridEmailProvider {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        let url = &self.api_url;

        let request = SendGridRequest {
            personalizations: vec![Personalization {
                to: vec![EmailAddress {
                    email: to.to_string(),
                    name: None,
                }],
            }],
            from: EmailAddress {
                email: self.from_address.clone(),
                name: self.from_name.clone(),
            },
            subject: subject.to_string(),
            content: vec![Content {
                content_type: "text/html".to_string(),
                value: body.to_string(),
            }],
        };

        let response = self
            .client
            .post(url)
            .bearer_auth(&self.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("SendGrid API request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Internal(format!(
                "SendGrid API failed with status {}: {}",
                status, body
            )));
        }

        Ok(())
    }
}

/// Custom HTTP email provider
/// POSTs to a configurable URL with JSON payload
pub struct CustomHttpEmailProvider {
    client: Client,
    endpoint_url: String,
    api_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct CustomEmailRequest {
    to: String,
    subject: String,
    body: String,
    timestamp: String,
}

impl CustomHttpEmailProvider {
    /// Create a new custom HTTP email provider
    pub fn new(endpoint_url: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            endpoint_url,
            api_key,
        }
    }

    /// Create provider from database record fields
    pub fn from_provider_record(endpoint_url: &str, api_key: Option<&str>) -> Self {
        Self::new(endpoint_url.to_string(), api_key.map(|s| s.to_string()))
    }
}

#[async_trait]
impl EmailProviderTrait for CustomHttpEmailProvider {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        let request = CustomEmailRequest {
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let mut req_builder = self
            .client
            .post(&self.endpoint_url)
            .header("Content-Type", "application/json")
            .json(&request);

        // Add API key as Bearer token if provided
        if let Some(ref api_key) = self.api_key {
            req_builder = req_builder.bearer_auth(api_key);
        }

        let response = req_builder
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Custom HTTP email request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Internal(format!(
                "Custom HTTP email API failed with status {}: {}",
                status, body_text
            )));
        }

        Ok(())
    }
}
