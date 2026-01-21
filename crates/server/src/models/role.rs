use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Role {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub is_enabled: bool,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRoleRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Role> for RoleResponse {
    fn from(role: Role) -> Self {
        Self {
            id: role.id,
            owner: role.owner,
            name: role.name,
            display_name: role.display_name,
            description: role.description,
            is_enabled: role.is_enabled,
            created_at: role.created_at,
            updated_at: role.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleListResponse {
    pub data: Vec<RoleResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RoleQuery {
    pub owner: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl Default for RoleQuery {
    fn default() -> Self {
        Self {
            owner: None,
            page: Some(1),
            page_size: Some(20),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct UserRole {
    pub id: String,
    pub user_id: String,
    pub role_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignRoleRequest {
    pub user_id: String,
    pub role_id: String,
}
