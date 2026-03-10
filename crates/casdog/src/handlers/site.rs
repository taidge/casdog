use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateSiteRequest, SiteListResponse, SiteResponse, UpdateSiteRequest};
use crate::services::SiteService;

#[endpoint(tags("Site"), summary = "List sites")]
pub async fn list_sites(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    include_global: QueryParam<bool, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<SiteListResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let response = SiteService::list(
        &pool,
        owner.as_deref(),
        include_global.into_inner().unwrap_or(false),
        page.into_inner().unwrap_or(1),
        page_size.into_inner().unwrap_or(20),
    )
    .await?;

    Ok(Json(response))
}

#[endpoint(tags("Site"), summary = "Get global sites")]
pub async fn get_global_sites(depot: &mut Depot) -> AppResult<Json<SiteListResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let response = SiteService::list(&pool, None, false, 1, 500).await?;
    Ok(Json(response))
}

#[endpoint(tags("Site"), summary = "Get site by ID")]
pub async fn get_site(depot: &mut Depot, id: PathParam<String>) -> AppResult<Json<SiteResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    Ok(Json(SiteService::get_by_id(&pool, &id).await?))
}

#[endpoint(tags("Site"), summary = "Create site")]
pub async fn create_site(
    depot: &mut Depot,
    body: JsonBody<CreateSiteRequest>,
) -> AppResult<Json<SiteResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    Ok(Json(SiteService::create(&pool, body.into_inner()).await?))
}

#[endpoint(tags("Site"), summary = "Update site")]
pub async fn update_site(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateSiteRequest>,
) -> AppResult<Json<SiteResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    Ok(Json(
        SiteService::update(&pool, &id, body.into_inner()).await?,
    ))
}

#[endpoint(tags("Site"), summary = "Delete site")]
pub async fn delete_site(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    SiteService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Site deleted"
    })))
}
