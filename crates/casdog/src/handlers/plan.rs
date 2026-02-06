use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreatePlanRequest, PlanResponse, UpdatePlanRequest};
use crate::services::PlanService;

#[endpoint(tags("plans"), summary = "List plans")]
pub async fn list_plans(
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

    let (plans, total) = PlanService::list(&pool, owner_ref, page_val, page_size_val).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": plans,
        "total": total
    })))
}

#[endpoint(tags("plans"), summary = "Get plan by ID")]
pub async fn get_plan(depot: &mut Depot, id: PathParam<String>) -> AppResult<Json<PlanResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let plan = PlanService::get_by_id(&pool, &id).await?;
    Ok(Json(plan))
}

#[endpoint(tags("plans"), summary = "Create plan")]
pub async fn create_plan(
    depot: &mut Depot,
    body: JsonBody<CreatePlanRequest>,
) -> AppResult<Json<PlanResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let plan = PlanService::create(&pool, body.into_inner()).await?;
    Ok(Json(plan))
}

#[endpoint(tags("plans"), summary = "Update plan")]
pub async fn update_plan(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdatePlanRequest>,
) -> AppResult<Json<PlanResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let plan = PlanService::update(&pool, &id, body.into_inner()).await?;
    Ok(Json(plan))
}

#[endpoint(tags("plans"), summary = "Delete plan")]
pub async fn delete_plan(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    PlanService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Plan deleted"
    })))
}
