use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateResourceRequest, ResourceResponse, UpdateResourceRequest};
use crate::services::ResourceService;

#[endpoint(tags("resources"), summary = "List resources")]
pub async fn list_resources(
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

    let (resources, total) =
        ResourceService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": resources,
        "total": total
    })))
}

#[endpoint(tags("resources"), summary = "Get resource by ID")]
pub async fn get_resource(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<ResourceResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let resource = ResourceService::get_by_id(&pool, &id).await?;
    Ok(Json(resource))
}

#[endpoint(tags("resources"), summary = "Create resource")]
pub async fn create_resource(
    depot: &mut Depot,
    body: JsonBody<CreateResourceRequest>,
) -> AppResult<Json<ResourceResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let resource = ResourceService::create(&pool, body.into_inner()).await?;
    Ok(Json(resource))
}

#[endpoint(tags("resources"), summary = "Update resource")]
pub async fn update_resource(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateResourceRequest>,
) -> AppResult<Json<ResourceResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let resource = ResourceService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(resource))
}

#[endpoint(tags("resources"), summary = "Delete resource")]
pub async fn delete_resource(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    ResourceService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
