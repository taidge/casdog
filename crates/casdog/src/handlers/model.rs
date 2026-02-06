use crate::error::{AppError, AppResult};
use crate::models::{CasbinModelResponse, CreateCasbinModelRequest, UpdateCasbinModelRequest};
use crate::services::ModelService;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

#[endpoint(tags("casbin-models"), summary = "List casbin models")]
pub async fn list_models(
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

    let (models, total) = ModelService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": models,
        "total": total
    })))
}

#[endpoint(tags("casbin-models"), summary = "Get casbin model by ID")]
pub async fn get_model(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<CasbinModelResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let model = ModelService::get_by_id(&pool, &id).await?;
    Ok(Json(model))
}

#[endpoint(tags("casbin-models"), summary = "Create casbin model")]
pub async fn create_model(
    depot: &mut Depot,
    body: JsonBody<CreateCasbinModelRequest>,
) -> AppResult<Json<CasbinModelResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let model = ModelService::create(&pool, body.into_inner()).await?;
    Ok(Json(model))
}

#[endpoint(tags("casbin-models"), summary = "Update casbin model")]
pub async fn update_model(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateCasbinModelRequest>,
) -> AppResult<Json<CasbinModelResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let model = ModelService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(model))
}

#[endpoint(tags("casbin-models"), summary = "Delete casbin model")]
pub async fn delete_model(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    ModelService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
