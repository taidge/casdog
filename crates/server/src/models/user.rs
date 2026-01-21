use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct User {
    pub id: String,
    pub owner: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar: Option<String>,
    pub is_admin: bool,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub owner: String,
    pub name: String,
    pub password: String,
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar: Option<String>,
    pub is_admin: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar: Option<String>,
    pub is_admin: Option<bool>,
    pub password: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar: Option<String>,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            owner: user.owner,
            name: user.name,
            display_name: user.display_name,
            email: user.email,
            phone: user.phone,
            avatar: user.avatar,
            is_admin: user.is_admin,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListResponse {
    pub data: Vec<UserResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UserQuery {
    pub owner: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl Default for UserQuery {
    fn default() -> Self {
        Self {
            owner: None,
            page: Some(1),
            page_size: Some(20),
        }
    }
}
