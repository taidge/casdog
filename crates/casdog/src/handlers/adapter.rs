use crate::error::{AppError, AppResult};
use crate::models::{CasbinAdapterResponse, CreateCasbinAdapterRequest, UpdateCasbinAdapterRequest};
use crate::services::AdapterService;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

#[endpoint(tags("casbin-adapters"), summary = "List casbin adapters")]
pub async fn list_adapters(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let page = page.into_inner().unwrap_or(1);
    let page_size = page_size.into_inner().unwrap_or(10);
    let owner = owner.into_inner();

    let (adapters, total) = AdapterService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": adapters,
        "total": total
    })))
}

#[endpoint(tags("casbin-adapters"), summary = "Get casbin adapter by ID")]
pub async fn get_adapter(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<CasbinAdapterResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let adapter = AdapterService::get_by_id(&pool, &id).await?;
    Ok(Json(adapter))
}

#[endpoint(tags("casbin-adapters"), summary = "Create casbin adapter")]
pub async fn create_adapter(
    depot: &mut Depot,
    body: JsonBody<CreateCasbinAdapterRequest>,
) -> AppResult<Json<CasbinAdapterResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let adapter = AdapterService::create(&pool, body.into_inner()).await?;
    Ok(Json(adapter))
}

#[endpoint(tags("casbin-adapters"), summary = "Update casbin adapter")]
pub async fn update_adapter(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateCasbinAdapterRequest>,
) -> AppResult<Json<CasbinAdapterResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let adapter = AdapterService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(adapter))
}

#[endpoint(tags("casbin-adapters"), summary = "Delete casbin adapter")]
pub async fn delete_adapter(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    AdapterService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
