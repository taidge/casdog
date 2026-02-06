use crate::error::AppError;
use crate::services::UserService;
use salvo::oapi::extract::*;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

#[derive(Debug, Serialize, ToSchema)]
pub struct ScimListResponse<T: Serialize + ToSchema + Send> {
    #[serde(rename = "schemas")]
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: i64,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub active: bool,
    pub emails: Option<Vec<ScimEmail>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ScimEmail {
    pub value: String,
    pub primary: bool,
}

/// SCIM Users list endpoint
#[endpoint(
    tags("SCIM"),
    summary = "List SCIM users"
)]
pub async fn list_scim_users(
    depot: &mut Depot,
    start_index: QueryParam<i64, false>,
    count: QueryParam<i64, false>,
) -> Result<Json<ScimListResponse<ScimUser>>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let start = start_index.into_inner().unwrap_or(1);
    let page_size = count.into_inner().unwrap_or(20);
    let offset = (start - 1).max(0);

    let users: Vec<(String, String, String, Option<String>, bool)> = sqlx::query_as(
        "SELECT id, name, display_name, email, is_admin FROM users WHERE is_deleted = FALSE ORDER BY created_at LIMIT $1 OFFSET $2"
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(&pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_deleted = FALSE")
        .fetch_one(&pool)
        .await?;

    let resources: Vec<ScimUser> = users.into_iter().map(|(id, name, display_name, email, _)| {
        ScimUser {
            schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
            id,
            user_name: name,
            display_name: Some(display_name),
            active: true,
            emails: email.map(|e| vec![ScimEmail { value: e, primary: true }]),
        }
    }).collect();

    Ok(Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total.0,
        start_index: start,
        items_per_page: page_size,
        resources,
    }))
}

/// SCIM Get user by ID
#[endpoint(
    tags("SCIM"),
    summary = "Get SCIM user"
)]
pub async fn get_scim_user(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<Json<ScimUser>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let user: (String, String, String, Option<String>) = sqlx::query_as(
        "SELECT id, name, display_name, email FROM users WHERE id = $1 AND is_deleted = FALSE"
    )
    .bind(id.as_str())
    .fetch_one(&pool)
    .await
    .map_err(|_| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(ScimUser {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
        id: user.0,
        user_name: user.1,
        display_name: Some(user.2),
        active: true,
        emails: user.3.map(|e| vec![ScimEmail { value: e, primary: true }]),
    }))
}
