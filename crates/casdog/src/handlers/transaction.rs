use crate::error::{AppError, AppResult};
use crate::models::{CreateTransactionRequest, TransactionResponse, UpdateTransactionRequest};
use crate::services::TransactionService;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

#[endpoint(tags("transactions"), summary = "List transactions")]
pub async fn list_transactions(
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

    let (transactions, total) =
        TransactionService::list(&pool, owner_ref, page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": transactions,
        "total": total
    })))
}

#[endpoint(tags("transactions"), summary = "Get transaction by ID")]
pub async fn get_transaction(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<TransactionResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let transaction = TransactionService::get_by_id(&pool, &id).await?;
    Ok(Json(transaction))
}

#[endpoint(tags("transactions"), summary = "Create transaction")]
pub async fn create_transaction(
    depot: &mut Depot,
    body: JsonBody<CreateTransactionRequest>,
) -> AppResult<Json<TransactionResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let transaction = TransactionService::create(&pool, body.into_inner()).await?;
    Ok(Json(transaction))
}

#[endpoint(tags("transactions"), summary = "Update transaction")]
pub async fn update_transaction(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateTransactionRequest>,
) -> AppResult<Json<TransactionResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let transaction = TransactionService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(transaction))
}

#[endpoint(tags("transactions"), summary = "Delete transaction")]
pub async fn delete_transaction(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    TransactionService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Transaction deleted"
    })))
}
