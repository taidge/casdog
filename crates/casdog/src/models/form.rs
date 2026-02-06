use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Form {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub form_items: Option<serde_json::Value>,
    pub is_enabled: bool,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateFormRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub form_items: Option<serde_json::Value>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateFormRequest {
    pub display_name: Option<String>,
    pub form_items: Option<serde_json::Value>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FormResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub form_items: Option<serde_json::Value>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Form> for FormResponse {
    fn from(f: Form) -> Self {
        Self {
            id: f.id,
            owner: f.owner,
            name: f.name,
            display_name: f.display_name,
            form_items: f.form_items,
            is_enabled: f.is_enabled,
            created_at: f.created_at,
            updated_at: f.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FormListResponse {
    pub data: Vec<FormResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
