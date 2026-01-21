use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Organization {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub website_url: Option<String>,
    pub favicon: Option<String>,
    pub password_type: String,
    pub default_avatar: Option<String>,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOrganizationRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub website_url: Option<String>,
    pub favicon: Option<String>,
    pub password_type: Option<String>,
    pub default_avatar: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOrganizationRequest {
    pub display_name: Option<String>,
    pub website_url: Option<String>,
    pub favicon: Option<String>,
    pub password_type: Option<String>,
    pub default_avatar: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub website_url: Option<String>,
    pub favicon: Option<String>,
    pub password_type: String,
    pub default_avatar: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Organization> for OrganizationResponse {
    fn from(org: Organization) -> Self {
        Self {
            id: org.id,
            owner: org.owner,
            name: org.name,
            display_name: org.display_name,
            website_url: org.website_url,
            favicon: org.favicon,
            password_type: org.password_type,
            default_avatar: org.default_avatar,
            created_at: org.created_at,
            updated_at: org.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationListResponse {
    pub data: Vec<OrganizationResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct OrganizationQuery {
    pub owner: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl Default for OrganizationQuery {
    fn default() -> Self {
        Self {
            owner: None,
            page: Some(1),
            page_size: Some(20),
        }
    }
}
