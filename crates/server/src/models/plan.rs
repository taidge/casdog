use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Plan {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub price_per_month: f64,
    pub price_per_year: f64,
    pub currency: Option<String>,
    pub role: Option<String>,
    pub options: Option<String>,
    pub is_enabled: bool,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePlanRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub price_per_month: Option<f64>,
    pub price_per_year: Option<f64>,
    pub currency: Option<String>,
    pub role: Option<String>,
    pub options: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePlanRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub price_per_month: Option<f64>,
    pub price_per_year: Option<f64>,
    pub currency: Option<String>,
    pub role: Option<String>,
    pub options: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PlanResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub price_per_month: f64,
    pub price_per_year: f64,
    pub currency: Option<String>,
    pub role: Option<String>,
    pub options: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Plan> for PlanResponse {
    fn from(p: Plan) -> Self {
        Self {
            id: p.id,
            owner: p.owner,
            name: p.name,
            display_name: p.display_name,
            description: p.description,
            price_per_month: p.price_per_month,
            price_per_year: p.price_per_year,
            currency: p.currency,
            role: p.role,
            options: p.options,
            is_enabled: p.is_enabled,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PlanListResponse {
    pub data: Vec<PlanResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
