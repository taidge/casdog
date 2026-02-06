use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Application {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub logo: Option<String>,
    pub homepage_url: Option<String>,
    pub description: Option<String>,
    pub organization: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: String,
    pub token_format: String,
    pub expire_in_hours: i32,
    pub cert: Option<String>,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApplicationRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub logo: Option<String>,
    pub homepage_url: Option<String>,
    pub description: Option<String>,
    pub organization: String,
    pub redirect_uris: Option<String>,
    pub token_format: Option<String>,
    pub expire_in_hours: Option<i32>,
    pub cert: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateApplicationRequest {
    pub display_name: Option<String>,
    pub logo: Option<String>,
    pub homepage_url: Option<String>,
    pub description: Option<String>,
    pub redirect_uris: Option<String>,
    pub token_format: Option<String>,
    pub expire_in_hours: Option<i32>,
    pub cert: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub logo: Option<String>,
    pub homepage_url: Option<String>,
    pub description: Option<String>,
    pub organization: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: String,
    pub token_format: String,
    pub expire_in_hours: i32,
    pub cert: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Application> for ApplicationResponse {
    fn from(app: Application) -> Self {
        Self {
            id: app.id,
            owner: app.owner,
            name: app.name,
            display_name: app.display_name,
            logo: app.logo,
            homepage_url: app.homepage_url,
            description: app.description,
            organization: app.organization,
            client_id: app.client_id,
            client_secret: app.client_secret,
            redirect_uris: app.redirect_uris,
            token_format: app.token_format,
            expire_in_hours: app.expire_in_hours,
            cert: app.cert,
            created_at: app.created_at,
            updated_at: app.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationListResponse {
    pub data: Vec<ApplicationResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApplicationQuery {
    pub owner: Option<String>,
    pub organization: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl Default for ApplicationQuery {
    fn default() -> Self {
        Self {
            owner: None,
            organization: None,
            page: Some(1),
            page_size: Some(20),
        }
    }
}
