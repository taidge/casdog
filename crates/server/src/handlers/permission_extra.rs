use crate::error::{AppError, AppResult};
use crate::models::{Permission, PermissionResponse};
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

/// Get permissions filtered by submitter (owner)
#[endpoint(tags("Permissions"), summary = "Get permissions by submitter")]
pub async fn get_permissions_by_submitter(
    depot: &mut Depot,
    submitter: QueryParam<String, true>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let submitter_val = submitter.into_inner();

    let permissions = sqlx::query_as::<_, Permission>(
        "SELECT * FROM permissions WHERE owner = $1 AND is_deleted = FALSE ORDER BY created_at DESC",
    )
    .bind(&submitter_val)
    .fetch_all(&pool)
    .await?;

    let data: Vec<PermissionResponse> = permissions.into_iter().map(PermissionResponse::from).collect();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": data
    })))
}

/// Get permissions associated with a specific role via role_permissions join table
#[endpoint(tags("Permissions"), summary = "Get permissions by role")]
pub async fn get_permissions_by_role(
    depot: &mut Depot,
    role_id: QueryParam<String, true>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let role_id_val = role_id.into_inner();

    let permissions = sqlx::query_as::<_, Permission>(
        r#"SELECT p.* FROM permissions p
           INNER JOIN role_permissions rp ON p.id = rp.permission_id
           WHERE rp.role_id = $1 AND p.is_deleted = FALSE
           ORDER BY p.created_at DESC"#,
    )
    .bind(&role_id_val)
    .fetch_all(&pool)
    .await?;

    let data: Vec<PermissionResponse> = permissions.into_iter().map(PermissionResponse::from).collect();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": data
    })))
}
