use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateOrderRequest, OrderResponse, UpdateOrderRequest};
use crate::services::OrderService;

#[endpoint(tags("Order"), summary = "List orders")]
pub async fn get_orders(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    state: QueryParam<String, false>,
    user: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let owner_ref = owner.as_deref();
    let state_ref = state.as_deref();
    let user_ref = user.as_deref();
    let page_val = page.into_inner().unwrap_or(1);
    let page_size_val = page_size.into_inner().unwrap_or(10);

    let (orders, total) = OrderService::list(
        &pool,
        owner_ref,
        state_ref,
        user_ref,
        page_val,
        page_size_val,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": orders,
        "total": total
    })))
}

#[endpoint(tags("Order"), summary = "Get order by ID")]
pub async fn get_order(depot: &mut Depot, id: PathParam<String>) -> AppResult<Json<OrderResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let order = OrderService::get_by_id(&pool, &id).await?;
    Ok(Json(order))
}

#[endpoint(tags("Order"), summary = "Create order")]
pub async fn add_order(
    depot: &mut Depot,
    body: JsonBody<CreateOrderRequest>,
) -> AppResult<Json<OrderResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let order = OrderService::create(&pool, body.into_inner()).await?;
    Ok(Json(order))
}

#[endpoint(tags("Order"), summary = "Update order")]
pub async fn update_order(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateOrderRequest>,
) -> AppResult<Json<OrderResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let order = OrderService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(order))
}

#[endpoint(tags("Order"), summary = "Delete order")]
pub async fn delete_order(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    OrderService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Order deleted"
    })))
}
