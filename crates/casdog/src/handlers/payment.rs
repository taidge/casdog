use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreatePaymentRequest, PaymentResponse, UpdatePaymentRequest};
use crate::services::PaymentService;

#[endpoint(tags("payments"), summary = "List payments")]
pub async fn list_payments(
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

    let (payments, total) = PaymentService::list(&pool, owner_ref, page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": payments,
        "total": total
    })))
}

#[endpoint(tags("payments"), summary = "Get payment by ID")]
pub async fn get_payment(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<PaymentResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let payment = PaymentService::get_by_id(&pool, &id).await?;
    Ok(Json(payment))
}

#[endpoint(tags("payments"), summary = "Create payment")]
pub async fn create_payment(
    depot: &mut Depot,
    body: JsonBody<CreatePaymentRequest>,
) -> AppResult<Json<PaymentResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let payment = PaymentService::create(&pool, body.into_inner()).await?;
    Ok(Json(payment))
}

#[endpoint(tags("payments"), summary = "Update payment")]
pub async fn update_payment(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdatePaymentRequest>,
) -> AppResult<Json<PaymentResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let payment = PaymentService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(payment))
}

#[endpoint(tags("payments"), summary = "Delete payment")]
pub async fn delete_payment(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    PaymentService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Payment deleted"
    })))
}
