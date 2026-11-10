use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{
    CheckSessionDuplicatedRequest, CreateSessionRequest, SessionDuplicatedResponse,
    SessionResponse, UpdateSessionRequest,
};
use crate::services::SessionService;

#[endpoint(tags("sessions"), summary = "List sessions")]
pub async fn list_sessions(
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

    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    if !principal.admin {
        let limit = page_size.clamp(1, 100);
        let offset = page.max(1).saturating_sub(1).saturating_mul(limit);
        let sessions: Vec<crate::models::Session> = sqlx::query_as("SELECT * FROM sessions WHERE owner=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT $3 OFFSET $4")
            .bind(&principal.owner).bind(&principal.id).bind(limit).bind(offset).fetch_all(&pool).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE owner=$1 AND user_id=$2")
                .bind(&principal.owner)
                .bind(&principal.id)
                .fetch_one(&pool)
                .await?;
        return Ok(Json(
            serde_json::json!({"data": sessions.into_iter().map(SessionResponse::from).collect::<Vec<_>>(), "total": total}),
        ));
    }

    let (sessions, total) = SessionService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": sessions,
        "total": total
    })))
}

#[endpoint(tags("sessions"), summary = "Get session by ID")]
pub async fn get_session(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<SessionResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let session = SessionService::get_by_id(&pool, &id).await?;
    Ok(Json(session))
}

#[endpoint(tags("sessions"), summary = "Create session")]
pub async fn create_session(
    depot: &mut Depot,
    body: JsonBody<CreateSessionRequest>,
) -> AppResult<Json<SessionResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let session = SessionService::create(&pool, body.into_inner()).await?;
    Ok(Json(session))
}

#[endpoint(tags("sessions"), summary = "Update session")]
pub async fn update_session(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateSessionRequest>,
) -> AppResult<Json<SessionResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let session = SessionService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(session))
}

#[endpoint(tags("sessions"), summary = "Delete session")]
pub async fn delete_session(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    SessionService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[endpoint(tags("sessions"), summary = "Check if session is duplicated")]
pub async fn is_session_duplicated(
    depot: &mut Depot,
    body: JsonBody<CheckSessionDuplicatedRequest>,
) -> AppResult<Json<SessionDuplicatedResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let req = body.into_inner();
    let is_duplicated =
        SessionService::is_session_duplicated(&pool, &req.user_id, &req.session_id).await?;

    Ok(Json(SessionDuplicatedResponse { is_duplicated }))
}
