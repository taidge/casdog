use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// ==================== Casbin Model ====================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct CasbinModel {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub model_text: String,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCasbinModelRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub model_text: String,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCasbinModelRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub model_text: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CasbinModelResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub model_text: String,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<CasbinModel> for CasbinModelResponse {
    fn from(m: CasbinModel) -> Self {
        Self {
            id: m.id,
            owner: m.owner,
            name: m.name,
            display_name: m.display_name,
            description: m.description,
            model_text: m.model_text,
            is_enabled: m.is_enabled,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CasbinModelListResponse {
    pub data: Vec<CasbinModelResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ==================== Casbin Adapter ====================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct CasbinAdapter {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub adapter_type: String,
    pub host: Option<String>,
    pub database_type: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCasbinAdapterRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub adapter_type: Option<String>,
    pub host: Option<String>,
    pub database_type: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCasbinAdapterRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub adapter_type: Option<String>,
    pub host: Option<String>,
    pub database_type: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CasbinAdapterResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub adapter_type: String,
    pub host: Option<String>,
    pub database_type: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<CasbinAdapter> for CasbinAdapterResponse {
    fn from(a: CasbinAdapter) -> Self {
        Self {
            id: a.id,
            owner: a.owner,
            name: a.name,
            display_name: a.display_name,
            description: a.description,
            adapter_type: a.adapter_type,
            host: a.host,
            database_type: a.database_type,
            is_enabled: a.is_enabled,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CasbinAdapterListResponse {
    pub data: Vec<CasbinAdapterResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ==================== Casbin Enforcer ====================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct CasbinEnforcer {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub model_id: Option<String>,
    pub adapter_id: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCasbinEnforcerRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub model_id: Option<String>,
    pub adapter_id: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCasbinEnforcerRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub model_id: Option<String>,
    pub adapter_id: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CasbinEnforcerResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub model_id: Option<String>,
    pub adapter_id: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<CasbinEnforcer> for CasbinEnforcerResponse {
    fn from(e: CasbinEnforcer) -> Self {
        Self {
            id: e.id,
            owner: e.owner,
            name: e.name,
            display_name: e.display_name,
            description: e.description,
            model_id: e.model_id,
            adapter_id: e.adapter_id,
            is_enabled: e.is_enabled,
            created_at: e.created_at,
            updated_at: e.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CasbinEnforcerListResponse {
    pub data: Vec<CasbinEnforcerResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ==================== Batch Enforce types ====================

#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchEnforceRequest {
    pub requests: Vec<EnforceRequestItem>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EnforceRequestItem {
    pub sub: String,
    pub obj: String,
    pub act: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BatchEnforceResponse {
    pub results: Vec<EnforceResultItem>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EnforceResultItem {
    pub sub: String,
    pub obj: String,
    pub act: String,
    pub allowed: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StringListResponse {
    pub data: Vec<String>,
}
