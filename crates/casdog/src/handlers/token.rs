use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateTokenRequest, TokenResponse, UpdateTokenRequest};
use crate::services::TokenService;

#[endpoint(tags("tokens"), summary = "List tokens")]
pub async fn list_tokens(
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

    let (tokens, total) = TokenService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": tokens,
        "total": total
    })))
}

#[endpoint(tags("tokens"), summary = "Get token by ID")]
pub async fn get_token(depot: &mut Depot, id: PathParam<String>) -> AppResult<Json<TokenResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let token = TokenService::get_by_id(&pool, &id).await?;
    Ok(Json(token))
}

#[endpoint(tags("tokens"), summary = "Create token")]
pub async fn create_token(
    depot: &mut Depot,
    body: JsonBody<CreateTokenRequest>,
) -> AppResult<Json<TokenResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let token = TokenService::create(&pool, body.into_inner()).await?;
    Ok(Json(token))
}

#[endpoint(tags("tokens"), summary = "Update token")]
pub async fn update_token(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateTokenRequest>,
) -> AppResult<Json<TokenResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let token = TokenService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(token))
}

#[endpoint(tags("tokens"), summary = "Delete token")]
pub async fn delete_token(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    TokenService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
