use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateSyncerRequest, SyncerResponse, UpdateSyncerRequest};
use crate::services::SyncerService;

#[endpoint(tags("syncers"), summary = "List syncers")]
pub async fn list_syncers(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let page = page.into_inner().unwrap_or(1);
    let page_size = page_size.into_inner().unwrap_or(10);
    let owner = owner.into_inner();

    let (syncers, total) = SyncerService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": syncers,
        "total": total
    })))
}

#[endpoint(tags("syncers"), summary = "Get syncer by ID")]
pub async fn get_syncer(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<SyncerResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let syncer = SyncerService::get_by_id(&pool, &id).await?;
    Ok(Json(syncer))
}

#[endpoint(tags("syncers"), summary = "Create syncer")]
pub async fn create_syncer(
    depot: &mut Depot,
    body: JsonBody<CreateSyncerRequest>,
) -> AppResult<Json<SyncerResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let syncer = SyncerService::create(&pool, body.into_inner()).await?;
    Ok(Json(syncer))
}

#[endpoint(tags("syncers"), summary = "Update syncer")]
pub async fn update_syncer(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateSyncerRequest>,
) -> AppResult<Json<SyncerResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let syncer = SyncerService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(syncer))
}

#[endpoint(tags("syncers"), summary = "Delete syncer")]
pub async fn delete_syncer(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    SyncerService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[endpoint(tags("syncers"), summary = "Run syncer")]
pub async fn run_syncer(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    SyncerService::run_sync(&pool, &id).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Sync completed"
    })))
}
