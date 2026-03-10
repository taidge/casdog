use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};
use std::collections::HashMap;

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{CreatePaymentRequest, PaymentResponse, UpdatePaymentRequest};
use crate::services::{PaymentFlowService, PaymentService};

#[derive(Debug, serde::Deserialize, salvo::oapi::ToSchema)]
pub struct NotifyPaymentRequest {
    pub id: Option<String>,
    pub owner: Option<String>,
    pub name: Option<String>,
    pub state: Option<String>,
    pub message: Option<String>,
    pub invoice_url: Option<String>,
}

#[derive(Debug, serde::Serialize, salvo::oapi::ToSchema)]
pub struct InvoicePaymentResponse {
    pub payment_id: String,
    pub invoice_url: String,
}

fn request_headers_lowercased(req: &Request) -> HashMap<String, String> {
    req.headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect()
}

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

#[endpoint(tags("payments"), summary = "Notify payment")]
pub async fn notify_payment(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<PaymentResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let raw_body = req
        .payload()
        .await
        .map_err(|e| AppError::Validation(format!("Failed to read request body: {}", e)))?
        .clone();
    let payload = serde_json::from_slice::<NotifyPaymentRequest>(&raw_body).ok();

    let payment_id = if let Some(id) = payload.as_ref().and_then(|value| value.id.clone()) {
        id
    } else {
        let owner = req
            .param::<String>("owner")
            .or_else(|| payload.as_ref().and_then(|value| value.owner.clone()))
            .ok_or_else(|| AppError::Validation("owner is required".to_string()))?;
        let name = req
            .param::<String>("payment")
            .or_else(|| payload.as_ref().and_then(|value| value.name.clone()))
            .ok_or_else(|| AppError::Validation("payment name is required".to_string()))?;

        sqlx::query_scalar::<_, String>(
            "SELECT id FROM payments WHERE owner = $1 AND name = $2 AND is_deleted = false",
        )
        .bind(&owner)
        .bind(&name)
        .fetch_optional(&pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Payment '{}/{}' not found", owner, name)))?
    };

    let manual_state = payload.as_ref().and_then(|value| value.state.as_deref());
    let manual_message = payload.as_ref().and_then(|value| value.message.as_deref());
    let manual_invoice = payload
        .as_ref()
        .and_then(|value| value.invoice_url.as_deref());

    let payment = if manual_state.is_some() || manual_message.is_some() || manual_invoice.is_some()
    {
        PaymentFlowService::manual_notify_payment(
            &pool,
            &payment_id,
            manual_state.unwrap_or("paid"),
            manual_message,
            manual_invoice,
        )
        .await?
        .payment
    } else {
        PaymentFlowService::notify_payment(
            &pool,
            &payment_id,
            &request_headers_lowercased(req),
            &raw_body,
        )
        .await?
        .payment
    };

    Ok(Json(payment))
}

#[endpoint(tags("payments"), summary = "Invoice payment")]
pub async fn invoice_payment(
    depot: &mut Depot,
    id: QueryParam<String, true>,
) -> AppResult<Json<InvoicePaymentResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let payment = PaymentFlowService::invoice_payment(&pool, id.as_str()).await?;
    let invoice_url = payment
        .invoice_url
        .clone()
        .or_else(|| {
            let config = AppConfig::get();
            Some(format!(
                "http://{}:{}/payments/{}/invoice",
                config.server.host, config.server.port, payment.id
            ))
        })
        .unwrap_or_default();

    Ok(Json(InvoicePaymentResponse {
        payment_id: payment.id,
        invoice_url,
    }))
}
