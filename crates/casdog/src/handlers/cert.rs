use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CertificateResponse, CreateCertificateRequest, UpdateCertificateRequest};
use crate::services::CertService;

#[endpoint(tags("certificates"), summary = "List certificates")]
pub async fn list_certs(
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

    let (certs, total) = CertService::list(&pool, owner.as_deref(), page, page_size).await?;

    Ok(Json(serde_json::json!({
        "data": certs,
        "total": total
    })))
}

#[endpoint(tags("certificates"), summary = "Get certificate by ID")]
pub async fn get_cert(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<CertificateResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let cert = CertService::get_by_id(&pool, &id).await?;
    Ok(Json(cert))
}

#[endpoint(tags("certificates"), summary = "Create certificate")]
pub async fn create_cert(
    depot: &mut Depot,
    body: JsonBody<CreateCertificateRequest>,
) -> AppResult<Json<CertificateResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let cert = CertService::create(&pool, body.into_inner()).await?;
    Ok(Json(cert))
}

#[endpoint(tags("certificates"), summary = "Update certificate")]
pub async fn update_cert(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateCertificateRequest>,
) -> AppResult<Json<CertificateResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let cert = CertService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(cert))
}

#[endpoint(tags("certificates"), summary = "Delete certificate")]
pub async fn delete_cert(depot: &mut Depot, id: PathParam<String>) -> AppResult<StatusCode> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    CertService::delete(&pool, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
