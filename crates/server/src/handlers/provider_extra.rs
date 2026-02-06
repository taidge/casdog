use crate::error::{AppError, AppResult};
use crate::models::{Provider, ProviderResponse};
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

/// Get all providers globally across all organizations
#[endpoint(tags("Providers"), summary = "Get all providers globally")]
pub async fn get_global_providers(
    depot: &mut Depot,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let page_val = page.into_inner().unwrap_or(1).max(1);
    let page_size_val = page_size.into_inner().unwrap_or(20).min(100);
    let offset = (page_val - 1) * page_size_val;

    let providers = sqlx::query_as::<_, Provider>(
        "SELECT * FROM providers ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size_val)
    .bind(offset)
    .fetch_all(&pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM providers")
        .fetch_one(&pool)
        .await?;

    let data: Vec<ProviderResponse> = providers.into_iter().map(ProviderResponse::from).collect();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": data,
        "total": total.0
    })))
}
