use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateWebhookRequest, UpdateWebhookRequest, WebhookResponse};
use crate::services::WebhookService;

#[endpoint(tags("webhooks"), summary = "List webhooks")]
pub async fn list_webhooks(
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

    let (webhooks, total) = WebhookService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": webhooks,
        "total": total
    })))
}

#[endpoint(tags("webhooks"), summary = "Get webhook by ID")]
pub async fn get_webhook(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<WebhookResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let webhook = WebhookService::get_by_id(&pool, &id).await?;
    Ok(Json(webhook))
}

#[endpoint(tags("webhooks"), summary = "Create webhook")]
pub async fn create_webhook(
    depot: &mut Depot,
    body: JsonBody<CreateWebhookRequest>,
) -> AppResult<Json<WebhookResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let webhook = WebhookService::create(&pool, body.into_inner()).await?;
    Ok(Json(webhook))
}

#[endpoint(tags("webhooks"), summary = "Update webhook")]
pub async fn update_webhook(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateWebhookRequest>,
) -> AppResult<Json<WebhookResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let webhook = WebhookService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(webhook))
}

#[endpoint(tags("webhooks"), summary = "Delete webhook")]
pub async fn delete_webhook(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    WebhookService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
