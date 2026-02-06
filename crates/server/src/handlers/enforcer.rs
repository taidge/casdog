use crate::error::{AppError, AppResult};
use crate::models::{CasbinEnforcerResponse, CreateCasbinEnforcerRequest, UpdateCasbinEnforcerRequest};
use crate::services::EnforcerService;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

#[endpoint(tags("casbin-enforcers"), summary = "List casbin enforcers")]
pub async fn list_enforcers(
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

    let (enforcers, total) = EnforcerService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": enforcers,
        "total": total
    })))
}

#[endpoint(tags("casbin-enforcers"), summary = "Get casbin enforcer by ID")]
pub async fn get_enforcer(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<CasbinEnforcerResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let enforcer = EnforcerService::get_by_id(&pool, &id).await?;
    Ok(Json(enforcer))
}

#[endpoint(tags("casbin-enforcers"), summary = "Create casbin enforcer")]
pub async fn create_enforcer(
    depot: &mut Depot,
    body: JsonBody<CreateCasbinEnforcerRequest>,
) -> AppResult<Json<CasbinEnforcerResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let enforcer = EnforcerService::create(&pool, body.into_inner()).await?;
    Ok(Json(enforcer))
}

#[endpoint(tags("casbin-enforcers"), summary = "Update casbin enforcer")]
pub async fn update_enforcer(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateCasbinEnforcerRequest>,
) -> AppResult<Json<CasbinEnforcerResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let enforcer = EnforcerService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(enforcer))
}

#[endpoint(tags("casbin-enforcers"), summary = "Delete casbin enforcer")]
pub async fn delete_enforcer(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    EnforcerService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
