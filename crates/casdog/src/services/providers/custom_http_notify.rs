use super::notification_provider::NotificationProvider;
use crate::{error::AppResult, models::Provider};
use async_trait::async_trait;
/// Native Custom HTTP notifications and the method-empty legacy JSON protocol.
pub struct CustomHttpNotifyProvider {
    url: String,
    headers: Option<String>,
    record: Option<Provider>,
    allow_private: bool,
    pool: Option<sqlx::PgPool>,
}
impl CustomHttpNotifyProvider {
    pub fn new(url: String, config: Option<&str>) -> Self {
        Self {
            url,
            headers: config.map(str::to_owned),
            record: None,
            allow_private: false,
            pool: None,
        }
    }
    pub fn from_record(record: &Provider, allow_private: bool) -> AppResult<Self> {
        super::http_delivery::HttpDelivery::from_record(record, allow_private)?;
        Ok(Self {
            url: String::new(),
            headers: None,
            record: Some(record.clone()),
            allow_private,
            pool: None,
        })
    }
    pub fn with_private_network_access(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }
    pub fn with_pool(mut self, pool: sqlx::PgPool) -> Self {
        self.pool = Some(pool);
        self
    }
}
#[async_trait]
impl NotificationProvider for CustomHttpNotifyProvider {
    async fn send(&self, title: &str, content: &str, receiver: &str) -> AppResult<()> {
        let delivery = if let Some(record) = &self.record {
            super::http_delivery::HttpDelivery::from_record(record, self.allow_private)?
        } else {
            super::http_delivery::HttpDelivery::legacy(
                "Notification",
                &self.url,
                None,
                self.headers.as_deref(),
                self.allow_private,
            )?
        };
        let delivery = if let Some(pool) = &self.pool {
            delivery.with_pool(pool.clone())
        } else {
            delivery
        };
        delivery.notification(title, content, receiver).await
    }
    fn provider_type(&self) -> &str {
        "CustomHTTP"
    }
}
