use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{User, UserResponse};

/// Get all users globally across all organizations
#[endpoint(tags("Users"), summary = "Get all users globally")]
pub async fn get_global_users(
    depot: &mut Depot,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let page_val = page.into_inner().unwrap_or(1).max(1);
    let page_size_val = page_size.into_inner().unwrap_or(20).min(100);
    let offset = (page_val - 1) * page_size_val;

    let users = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE is_deleted = FALSE ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size_val)
    .bind(offset)
    .fetch_all(&pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_deleted = FALSE")
        .fetch_one(&pool)
        .await?;

    let data: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": data,
        "total": total.0
    })))
}

/// Get sorted users with configurable sort field and order
#[endpoint(tags("Users"), summary = "Get sorted users")]
pub async fn get_sorted_users(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    sort_field: QueryParam<String, false>,
    sort_order: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let page_val = page.into_inner().unwrap_or(1).max(1);
    let page_size_val = page_size.into_inner().unwrap_or(20).min(100);
    let offset = (page_val - 1) * page_size_val;
    let owner_val = owner.into_inner();

    // Validate sort_field against a whitelist to prevent SQL injection
    let sort_field_val = sort_field
        .into_inner()
        .unwrap_or_else(|| "created_at".to_string());
    let validated_sort_field = match sort_field_val.as_str() {
        "name" => "name",
        "created_at" => "created_at",
        "updated_at" => "updated_at",
        "display_name" => "display_name",
        "email" => "email",
        _ => {
            return Err(AppError::Validation(format!(
                "Invalid sort field '{}'. Allowed fields: name, created_at, updated_at, display_name, email",
                sort_field_val
            )));
        }
    };

    // Validate sort order
    let sort_order_val = sort_order
        .into_inner()
        .unwrap_or_else(|| "desc".to_string());
    let validated_sort_order = match sort_order_val.to_lowercase().as_str() {
        "asc" => "ASC",
        "desc" => "DESC",
        _ => {
            return Err(AppError::Validation(format!(
                "Invalid sort order '{}'. Allowed values: asc, desc",
                sort_order_val
            )));
        }
    };

    let (users, total) = if let Some(owner) = &owner_val {
        let query_str = format!(
            "SELECT * FROM users WHERE owner = $1 AND is_deleted = FALSE ORDER BY {} {} LIMIT $2 OFFSET $3",
            validated_sort_field, validated_sort_order
        );
        let users = sqlx::query_as::<_, User>(&query_str)
            .bind(owner)
            .bind(page_size_val)
            .bind(offset)
            .fetch_all(&pool)
            .await?;

        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE owner = $1 AND is_deleted = FALSE")
                .bind(owner)
                .fetch_one(&pool)
                .await?;

        (users, total.0)
    } else {
        let query_str = format!(
            "SELECT * FROM users WHERE is_deleted = FALSE ORDER BY {} {} LIMIT $1 OFFSET $2",
            validated_sort_field, validated_sort_order
        );
        let users = sqlx::query_as::<_, User>(&query_str)
            .bind(page_size_val)
            .bind(offset)
            .fetch_all(&pool)
            .await?;

        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_deleted = FALSE")
            .fetch_one(&pool)
            .await?;

        (users, total.0)
    };

    let data: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": data,
        "total": total
    })))
}

/// Get user count, optionally filtered by owner/organization
#[endpoint(tags("Users"), summary = "Get user count")]
pub async fn get_user_count(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let owner_val = owner.into_inner();

    let count = if let Some(owner) = &owner_val {
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE owner = $1 AND is_deleted = FALSE")
                .bind(owner)
                .fetch_one(&pool)
                .await?;
        total.0
    } else {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_deleted = FALSE")
            .fetch_one(&pool)
            .await?;
        total.0
    };

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": count
    })))
}
