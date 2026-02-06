use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Subscription {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub user_id: String,
    pub plan_id: String,
    pub pricing_id: Option<String>,
    pub start_date: DateTime<Utc>,
    pub end_date: Option<DateTime<Utc>>,
    pub period: Option<String>,
    pub state: String,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSubscriptionRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub user_id: String,
    pub plan_id: String,
    pub pricing_id: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub period: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSubscriptionRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub plan_id: Option<String>,
    pub pricing_id: Option<String>,
    pub end_date: Option<DateTime<Utc>>,
    pub period: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SubscriptionResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub user_id: String,
    pub plan_id: String,
    pub pricing_id: Option<String>,
    pub start_date: DateTime<Utc>,
    pub end_date: Option<DateTime<Utc>>,
    pub period: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Subscription> for SubscriptionResponse {
    fn from(s: Subscription) -> Self {
        Self {
            id: s.id,
            owner: s.owner,
            name: s.name,
            display_name: s.display_name,
            description: s.description,
            user_id: s.user_id,
            plan_id: s.plan_id,
            pricing_id: s.pricing_id,
            start_date: s.start_date,
            end_date: s.end_date,
            period: s.period,
            state: s.state,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SubscriptionListResponse {
    pub data: Vec<SubscriptionResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
