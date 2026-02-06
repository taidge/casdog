use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{Certificate, CertificateResponse};

/// Get all certificates globally across all organizations
#[endpoint(tags("Certs"), summary = "Get all certs globally")]
pub async fn get_global_certs(
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

    let certs = sqlx::query_as::<_, Certificate>(
        "SELECT * FROM certificates ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size_val)
    .bind(offset)
    .fetch_all(&pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM certificates")
        .fetch_one(&pool)
        .await?;

    let data: Vec<CertificateResponse> = certs.into_iter().map(CertificateResponse::from).collect();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": data,
        "total": total.0
    })))
}
