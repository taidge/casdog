use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Permission {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub resources: String,
    pub actions: String,
    pub effect: String,
    pub is_enabled: bool,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePermissionRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub resources: String,
    pub actions: String,
    pub effect: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePermissionRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub resource_type: Option<String>,
    pub resources: Option<String>,
    pub actions: Option<String>,
    pub effect: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub resources: String,
    pub actions: String,
    pub effect: String,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Permission> for PermissionResponse {
    fn from(perm: Permission) -> Self {
        Self {
            id: perm.id,
            owner: perm.owner,
            name: perm.name,
            display_name: perm.display_name,
            description: perm.description,
            resource_type: perm.resource_type,
            resources: perm.resources,
            actions: perm.actions,
            effect: perm.effect,
            is_enabled: perm.is_enabled,
            created_at: perm.created_at,
            updated_at: perm.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionListResponse {
    pub data: Vec<PermissionResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PermissionQuery {
    pub owner: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl Default for PermissionQuery {
    fn default() -> Self {
        Self {
            owner: None,
            page: Some(1),
            page_size: Some(20),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct RolePermission {
    pub id: String,
    pub role_id: String,
    pub permission_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignPermissionRequest {
    pub role_id: String,
    pub permission_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EnforceRequest {
    pub sub: String,
    pub obj: String,
    pub act: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EnforceResponse {
    pub allowed: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PolicyRequest {
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: Option<String>,
    pub v4: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyResponse {
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: Option<String>,
    pub v4: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyListResponse {
    pub data: Vec<PolicyResponse>,
}
