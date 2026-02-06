use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Pricing {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub plans: Option<String>,
    pub trial_duration: Option<i32>,
    pub application: Option<String>,
    pub is_enabled: bool,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePricingRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub plans: Option<String>,
    pub trial_duration: Option<i32>,
    pub application: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePricingRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub plans: Option<String>,
    pub trial_duration: Option<i32>,
    pub application: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PricingResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub plans: Option<String>,
    pub trial_duration: Option<i32>,
    pub application: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Pricing> for PricingResponse {
    fn from(p: Pricing) -> Self {
        Self {
            id: p.id,
            owner: p.owner,
            name: p.name,
            display_name: p.display_name,
            description: p.description,
            plans: p.plans,
            trial_duration: p.trial_duration,
            application: p.application,
            is_enabled: p.is_enabled,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PricingListResponse {
    pub data: Vec<PricingResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
