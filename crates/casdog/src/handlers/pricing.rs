use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreatePricingRequest, PricingResponse, UpdatePricingRequest};
use crate::services::PricingService;

#[endpoint(tags("pricings"), summary = "List pricings")]
pub async fn list_pricings(
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

    let (pricings, total) = PricingService::list(&pool, owner_ref, page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": pricings,
        "total": total
    })))
}

#[endpoint(tags("pricings"), summary = "Get pricing by ID")]
pub async fn get_pricing(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<PricingResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let pricing = PricingService::get_by_id(&pool, &id).await?;
    Ok(Json(pricing))
}

#[endpoint(tags("pricings"), summary = "Create pricing")]
pub async fn create_pricing(
    depot: &mut Depot,
    body: JsonBody<CreatePricingRequest>,
) -> AppResult<Json<PricingResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let pricing = PricingService::create(&pool, body.into_inner()).await?;
    Ok(Json(pricing))
}

#[endpoint(tags("pricings"), summary = "Update pricing")]
pub async fn update_pricing(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdatePricingRequest>,
) -> AppResult<Json<PricingResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let pricing = PricingService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(pricing))
}

#[endpoint(tags("pricings"), summary = "Delete pricing")]
pub async fn delete_pricing(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    PricingService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Pricing deleted"
    })))
}
