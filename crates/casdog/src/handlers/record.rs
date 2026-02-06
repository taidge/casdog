use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{RecordFilterRequest, RecordResponse};
use crate::services::RecordService;

#[endpoint(tags("records"), summary = "List records")]
pub async fn list_records(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let owner_ref = owner.as_deref();
    let page_val = page.into_inner().unwrap_or(1);
    let page_size_val = page_size.into_inner().unwrap_or(10);

    let (records, total) = RecordService::list(&pool, owner_ref, page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": records,
        "total": total
    })))
}

#[endpoint(tags("records"), summary = "Filter records")]
pub async fn filter_records(
    depot: &mut Depot,
    body: JsonBody<RecordFilterRequest>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let page_val = page.into_inner().unwrap_or(1);
    let page_size_val = page_size.into_inner().unwrap_or(10);

    let (records, total) =
        RecordService::list_filtered(&pool, body.into_inner(), page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": records,
        "total": total
    })))
}

#[endpoint(tags("records"), summary = "Get record by ID")]
pub async fn get_record(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<RecordResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let record = RecordService::get_by_id(&pool, &id).await?;
    Ok(Json(record))
}

#[endpoint(tags("records"), summary = "Delete record")]
pub async fn delete_record(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    RecordService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Record deleted"
    })))
}
