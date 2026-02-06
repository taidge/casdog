use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Webhook {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub organization: String,
    pub url: String,
    pub method: String, // GET, POST
    pub content_type: String,
    pub headers: Option<String>, // JSON array
    pub events: Option<String>,  // JSON array of event types
    pub is_user_extended: bool,
    pub is_enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWebhookRequest {
    pub owner: String,
    pub name: String,
    pub organization: String,
    pub url: String,
    pub method: Option<String>,
    pub content_type: Option<String>,
    pub headers: Option<Vec<String>>,
    pub events: Option<Vec<String>>,
    pub is_user_extended: Option<bool>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub method: Option<String>,
    pub content_type: Option<String>,
    pub headers: Option<Vec<String>>,
    pub events: Option<Vec<String>>,
    pub is_user_extended: Option<bool>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub organization: String,
    pub url: String,
    pub method: String,
    pub content_type: String,
    pub events: Option<Vec<String>>,
    pub is_user_extended: bool,
    pub is_enabled: bool,
}

impl From<Webhook> for WebhookResponse {
    fn from(w: Webhook) -> Self {
        let events = w.events.and_then(|e| serde_json::from_str(&e).ok());
        Self {
            id: w.id,
            owner: w.owner,
            name: w.name,
            created_at: w.created_at,
            organization: w.organization,
            url: w.url,
            method: w.method,
            content_type: w.content_type,
            events,
            is_user_extended: w.is_user_extended,
            is_enabled: w.is_enabled,
        }
    }
}

// Webhook event types
pub const WEBHOOK_EVENTS: &[&str] = &["signup", "login", "logout", "update-user", "delete-user"];
