use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{Application, ApplicationResponse, User};

/// Get applications accessible to a specific user (matching user's organization)
#[endpoint(tags("Applications"), summary = "Get user application")]
pub async fn get_user_application(
    depot: &mut Depot,
    user_id: QueryParam<String, true>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id_val = user_id.into_inner();

    // First, look up the user to find their organization
    let user =
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND is_deleted = FALSE")
            .bind(&user_id_val)
            .fetch_optional(&pool)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!("User with id '{}' not found", user_id_val))
            })?;

    // Then, find applications that belong to the user's organization
    let apps = sqlx::query_as::<_, Application>(
        "SELECT * FROM applications WHERE organization = $1 AND is_deleted = FALSE ORDER BY created_at DESC",
    )
    .bind(&user.owner)
    .fetch_all(&pool)
    .await?;

    let data: Vec<ApplicationResponse> = apps.into_iter().map(ApplicationResponse::from).collect();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": data
    })))
}

/// Get applications filtered by organization/owner with pagination
#[endpoint(tags("Applications"), summary = "Get organization applications")]
pub async fn get_organization_applications(
    depot: &mut Depot,
    owner: QueryParam<String, true>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let owner_val = owner.into_inner();
    let page_val = page.into_inner().unwrap_or(1).max(1);
    let page_size_val = page_size.into_inner().unwrap_or(20).min(100);
    let offset = (page_val - 1) * page_size_val;

    let apps = sqlx::query_as::<_, Application>(
        "SELECT * FROM applications WHERE owner = $1 AND is_deleted = FALSE ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&owner_val)
    .bind(page_size_val)
    .bind(offset)
    .fetch_all(&pool)
    .await?;

    let total: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM applications WHERE owner = $1 AND is_deleted = FALSE")
            .bind(&owner_val)
            .fetch_one(&pool)
            .await?;

    let data: Vec<ApplicationResponse> = apps.into_iter().map(ApplicationResponse::from).collect();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": data,
        "total": total.0
    })))
}

/// Get the default (first) application for an organization
#[endpoint(tags("Applications"), summary = "Get default application")]
pub async fn get_default_application(
    depot: &mut Depot,
    owner: QueryParam<String, true>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let owner_val = owner.into_inner();

    let app = sqlx::query_as::<_, Application>(
        "SELECT * FROM applications WHERE owner = $1 AND is_deleted = FALSE ORDER BY created_at ASC LIMIT 1",
    )
    .bind(&owner_val)
    .fetch_optional(&pool)
    .await?;

    match app {
        Some(app) => {
            let data: ApplicationResponse = app.into();
            Ok(Json(serde_json::json!({
                "status": "ok",
                "data": data
            })))
        }
        None => Ok(Json(serde_json::json!({
            "status": "ok",
            "data": null
        }))),
    }
}
