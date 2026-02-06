use crate::error::{AppError, AppResult};
use crate::models::{CreateFormRequest, FormResponse, UpdateFormRequest};
use crate::services::FormService;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

#[endpoint(tags("Form"), summary = "List forms")]
pub async fn get_forms(
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

    let (forms, total) = FormService::list(&pool, owner_ref, page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": forms,
        "total": total
    })))
}

#[endpoint(tags("Form"), summary = "Get form by ID")]
pub async fn get_form(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<FormResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let form = FormService::get_by_id(&pool, &id).await?;
    Ok(Json(form))
}

#[endpoint(tags("Form"), summary = "Create form")]
pub async fn add_form(
    depot: &mut Depot,
    body: JsonBody<CreateFormRequest>,
) -> AppResult<Json<FormResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let form = FormService::create(&pool, body.into_inner()).await?;
    Ok(Json(form))
}

#[endpoint(tags("Form"), summary = "Update form")]
pub async fn update_form(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateFormRequest>,
) -> AppResult<Json<FormResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let form = FormService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(form))
}

#[endpoint(tags("Form"), summary = "Delete form")]
pub async fn delete_form(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    FormService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Form deleted"
    })))
}
