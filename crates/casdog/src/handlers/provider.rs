use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateProviderRequest, ProviderResponse, UpdateProviderRequest};
use crate::services::ProviderService;

#[endpoint(tags("providers"), summary = "List providers")]
pub async fn list_providers(
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

    let (providers, total) =
        ProviderService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": providers,
        "total": total
    })))
}

#[endpoint(tags("providers"), summary = "Get provider by ID")]
pub async fn get_provider(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<ProviderResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let provider = ProviderService::get_by_id(&pool, &id).await?;
    Ok(Json(provider))
}

#[endpoint(tags("providers"), summary = "Create provider")]
pub async fn create_provider(
    depot: &mut Depot,
    body: JsonBody<CreateProviderRequest>,
) -> AppResult<Json<ProviderResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let provider = ProviderService::create(&pool, body.into_inner()).await?;
    Ok(Json(provider))
}

#[endpoint(tags("providers"), summary = "Update provider")]
pub async fn update_provider(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateProviderRequest>,
) -> AppResult<Json<ProviderResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let provider = ProviderService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(provider))
}

#[endpoint(tags("providers"), summary = "Delete provider")]
pub async fn delete_provider(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    ProviderService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
