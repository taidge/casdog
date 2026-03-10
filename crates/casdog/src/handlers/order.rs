use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateOrderRequest, OrderResponse, UpdateOrderRequest};
use crate::services::{OrderService, PaymentFlowService};

fn request_origin(req: &Request) -> Option<String> {
    let origin = req
        .headers()
        .get("Origin")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    if origin.is_some() {
        return origin;
    }

    let host = req
        .headers()
        .get("Host")
        .and_then(|value| value.to_str().ok())?;
    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");
    Some(format!("{}://{}", scheme, host))
}

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

#[endpoint(tags("Order"), summary = "Pay order")]
pub async fn pay_order(
    depot: &mut Depot,
    req: &Request,
    id: QueryParam<String, false>,
    provider_name: QueryParam<String, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let order_id = id
        .into_inner()
        .or_else(|| req.param::<String>("id"))
        .ok_or_else(|| AppError::Validation("id is required".to_string()))?;
    let current_owner = depot
        .get::<String>("user_owner")
        .cloned()
        .map_err(|_| AppError::Authorization("Missing authenticated user".to_string()))?;
    let current_name = depot
        .get::<String>("user_name")
        .cloned()
        .map_err(|_| AppError::Authorization("Missing authenticated user".to_string()))?;
    let is_admin = depot.get::<bool>("is_admin").ok().copied().unwrap_or(false);
    let result = PaymentFlowService::start_order_payment(
        &pool,
        &order_id,
        provider_name.as_deref(),
        &current_owner,
        &current_name,
        is_admin,
        request_origin(req).as_deref(),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "order": result.order,
        "payment": result.payment,
        "payUrl": result.pay_url,
        "autoPaid": result.auto_paid,
        "attachInfo": result.attach_info,
    })))
}

#[endpoint(tags("Order"), summary = "Cancel order")]
pub async fn cancel_order(
    depot: &mut Depot,
    req: &Request,
    id: QueryParam<String, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let order_id = id
        .into_inner()
        .or_else(|| req.param::<String>("id"))
        .ok_or_else(|| AppError::Validation("id is required".to_string()))?;
    let current_owner = depot
        .get::<String>("user_owner")
        .cloned()
        .map_err(|_| AppError::Authorization("Missing authenticated user".to_string()))?;
    let current_name = depot
        .get::<String>("user_name")
        .cloned()
        .map_err(|_| AppError::Authorization("Missing authenticated user".to_string()))?;
    let is_admin = depot.get::<bool>("is_admin").ok().copied().unwrap_or(false);
    let order =
        PaymentFlowService::cancel_order(&pool, &order_id, &current_owner, &current_name, is_admin)
            .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": order,
    })))
}
