use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Resource {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub user: String,
    pub provider: Option<String>,
    pub application: Option<String>,
    pub tag: Option<String>,
    pub parent: Option<String>,
    pub file_name: String,
    pub file_type: String,
    pub file_format: Option<String>,
    pub file_size: i64,
    pub url: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateResourceRequest {
    pub owner: String,
    pub name: String,
    pub user: String,
    pub provider: Option<String>,
    pub application: Option<String>,
    pub tag: Option<String>,
    pub parent: Option<String>,
    pub file_name: String,
    pub file_type: String,
    pub file_format: Option<String>,
    pub file_size: i64,
    pub url: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateResourceRequest {
    pub tag: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResourceResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub user: String,
    pub provider: Option<String>,
    pub application: Option<String>,
    pub tag: Option<String>,
    pub file_name: String,
    pub file_type: String,
    pub file_format: Option<String>,
    pub file_size: i64,
    pub url: String,
    pub description: Option<String>,
}

impl From<Resource> for ResourceResponse {
    fn from(r: Resource) -> Self {
        Self {
            id: r.id,
            owner: r.owner,
            name: r.name,
            created_at: r.created_at,
            user: r.user,
            provider: r.provider,
            application: r.application,
            tag: r.tag,
            file_name: r.file_name,
            file_type: r.file_type,
            file_format: r.file_format,
            file_size: r.file_size,
            url: r.url,
            description: r.description,
        }
    }
}
