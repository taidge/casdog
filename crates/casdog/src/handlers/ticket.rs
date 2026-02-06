use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateTicketRequest, TicketResponse, UpdateTicketRequest};
use crate::services::TicketService;

#[endpoint(tags("Ticket"), summary = "List tickets")]
pub async fn get_tickets(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    status: QueryParam<String, false>,
    assignee: QueryParam<String, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let owner_ref = owner.as_deref();
    let status_ref = status.as_deref();
    let assignee_ref = assignee.as_deref();
    let page_val = page.into_inner().unwrap_or(1);
    let page_size_val = page_size.into_inner().unwrap_or(10);

    let (tickets, total) = TicketService::list(
        &pool,
        owner_ref,
        status_ref,
        assignee_ref,
        page_val,
        page_size_val,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": tickets,
        "total": total
    })))
}

#[endpoint(tags("Ticket"), summary = "Get ticket by ID")]
pub async fn get_ticket(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<TicketResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let ticket = TicketService::get_by_id(&pool, &id).await?;
    Ok(Json(ticket))
}

#[endpoint(tags("Ticket"), summary = "Create ticket")]
pub async fn add_ticket(
    depot: &mut Depot,
    body: JsonBody<CreateTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let ticket = TicketService::create(&pool, body.into_inner()).await?;
    Ok(Json(ticket))
}

#[endpoint(tags("Ticket"), summary = "Update ticket")]
pub async fn update_ticket(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let ticket = TicketService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(ticket))
}

#[endpoint(tags("Ticket"), summary = "Delete ticket")]
pub async fn delete_ticket(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    TicketService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Ticket deleted"
    })))
}
