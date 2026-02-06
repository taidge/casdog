use crate::error::{AppError, AppResult};
use crate::models::{CreateSubscriptionRequest, SubscriptionResponse, UpdateSubscriptionRequest};
use crate::services::SubscriptionService;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

#[endpoint(tags("subscriptions"), summary = "List subscriptions")]
pub async fn list_subscriptions(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let owner_ref = owner.as_deref();
    let page_val = page.into_inner().unwrap_or(1);
    let page_size_val = page_size.into_inner().unwrap_or(10);

    let (subscriptions, total) =
        SubscriptionService::list(&pool, owner_ref, page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": subscriptions,
        "total": total
    })))
}

#[endpoint(tags("subscriptions"), summary = "Get subscription by ID")]
pub async fn get_subscription(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<SubscriptionResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let subscription = SubscriptionService::get_by_id(&pool, &id).await?;
    Ok(Json(subscription))
}

#[endpoint(tags("subscriptions"), summary = "Create subscription")]
pub async fn create_subscription(
    depot: &mut Depot,
    body: JsonBody<CreateSubscriptionRequest>,
) -> AppResult<Json<SubscriptionResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let subscription = SubscriptionService::create(&pool, body.into_inner()).await?;
    Ok(Json(subscription))
}

#[endpoint(tags("subscriptions"), summary = "Update subscription")]
pub async fn update_subscription(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateSubscriptionRequest>,
) -> AppResult<Json<SubscriptionResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let subscription = SubscriptionService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(subscription))
}

#[endpoint(tags("subscriptions"), summary = "Delete subscription")]
pub async fn delete_subscription(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    SubscriptionService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Subscription deleted"
    })))
}
