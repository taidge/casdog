use crate::error::{AppError, AppResult};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

#[endpoint(tags("Dashboard"), summary = "Get dashboard statistics")]
pub async fn get_dashboard(depot: &mut Depot) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_deleted = FALSE")
        .fetch_one(&pool).await?;
    let org_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM organizations WHERE is_deleted = FALSE")
        .fetch_one(&pool).await?;
    let app_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM applications WHERE is_deleted = FALSE")
        .fetch_one(&pool).await?;
    let provider_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM providers WHERE is_deleted = FALSE")
        .fetch_one(&pool).await?;
    let session_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": {
            "users": user_count.0,
            "organizations": org_count.0,
            "applications": app_count.0,
            "providers": provider_count.0,
            "active_sessions": session_count.0,
        }
    })))
}

#[endpoint(tags("Dashboard"), summary = "Get Prometheus-style metrics")]
pub async fn get_metrics(depot: &mut Depot) -> AppResult<String> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_deleted = FALSE")
        .fetch_one(&pool).await?;
    let org_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM organizations WHERE is_deleted = FALSE")
        .fetch_one(&pool).await?;
    let session_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool).await?;

    let metrics = format!(
        "# HELP casdog_users_total Total number of users\n\
         # TYPE casdog_users_total gauge\n\
         casdog_users_total {}\n\
         # HELP casdog_organizations_total Total number of organizations\n\
         # TYPE casdog_organizations_total gauge\n\
         casdog_organizations_total {}\n\
         # HELP casdog_sessions_active Active sessions\n\
         # TYPE casdog_sessions_active gauge\n\
         casdog_sessions_active {}\n",
        user_count.0, org_count.0, session_count.0,
    );

    Ok(metrics)
}
