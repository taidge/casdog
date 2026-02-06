use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{
    CreateInvitationRequest, InvitationResponse, SendInvitationRequest, UpdateInvitationRequest,
    VerifyInvitationRequest, VerifyInvitationResponse,
};
use crate::services::InvitationService;

#[endpoint(tags("invitations"), summary = "List invitations")]
pub async fn list_invitations(
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

    let (invitations, total) =
        InvitationService::list(&pool, owner_ref, page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": invitations,
        "total": total
    })))
}

#[endpoint(tags("invitations"), summary = "Get invitation by ID")]
pub async fn get_invitation(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<InvitationResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let invitation = InvitationService::get_by_id(&pool, &id).await?;
    Ok(Json(invitation))
}

#[endpoint(tags("invitations"), summary = "Create invitation")]
pub async fn create_invitation(
    depot: &mut Depot,
    body: JsonBody<CreateInvitationRequest>,
) -> AppResult<Json<InvitationResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let invitation = InvitationService::create(&pool, body.into_inner()).await?;
    Ok(Json(invitation))
}

#[endpoint(tags("invitations"), summary = "Update invitation")]
pub async fn update_invitation(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateInvitationRequest>,
) -> AppResult<Json<InvitationResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let invitation = InvitationService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(invitation))
}

#[endpoint(tags("invitations"), summary = "Delete invitation")]
pub async fn delete_invitation(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    InvitationService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Invitation deleted"
    })))
}

#[endpoint(tags("invitations"), summary = "Verify invitation code")]
pub async fn verify_invitation(
    depot: &mut Depot,
    body: JsonBody<VerifyInvitationRequest>,
) -> AppResult<Json<VerifyInvitationResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let result = InvitationService::verify(&pool, body.into_inner()).await?;
    Ok(Json(result))
}

#[endpoint(tags("invitations"), summary = "Send invitation via email or SMS")]
pub async fn send_invitation(
    depot: &mut Depot,
    body: JsonBody<SendInvitationRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let req = body.into_inner();

    // Verify the invitation exists
    let _invitation = InvitationService::get_by_id(&pool, &req.invitation_id).await?;

    // In production, send the invitation via email/SMS here
    // For now, return success

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": format!("Invitation sent via {} to {}", req.send_type, req.receiver)
    })))
}
