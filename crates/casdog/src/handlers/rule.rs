use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateRuleRequest, RuleListResponse, RuleResponse, UpdateRuleRequest};
use crate::services::RuleService;

#[endpoint(tags("Rule"), summary = "List rules")]
pub async fn list_rules(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    include_global: QueryParam<bool, false>,
    page: QueryParam<i64, false>,
    page_size: QueryParam<i64, false>,
) -> AppResult<Json<RuleListResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let response = RuleService::list(
        &pool,
        owner.as_deref(),
        include_global.into_inner().unwrap_or(false),
        page.into_inner().unwrap_or(1),
        page_size.into_inner().unwrap_or(20),
    )
    .await?;

    Ok(Json(response))
}

#[endpoint(tags("Rule"), summary = "Get global rules")]
pub async fn get_global_rules(depot: &mut Depot) -> AppResult<Json<RuleListResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let response = RuleService::list(&pool, None, false, 1, 500).await?;
    Ok(Json(response))
}

#[endpoint(tags("Rule"), summary = "Get rule by ID")]
pub async fn get_rule(depot: &mut Depot, id: PathParam<String>) -> AppResult<Json<RuleResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    Ok(Json(RuleService::get_by_id(&pool, &id).await?))
}

#[endpoint(tags("Rule"), summary = "Create rule")]
pub async fn create_rule(
    depot: &mut Depot,
    body: JsonBody<CreateRuleRequest>,
) -> AppResult<Json<RuleResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    Ok(Json(RuleService::create(&pool, body.into_inner()).await?))
}

#[endpoint(tags("Rule"), summary = "Update rule")]
pub async fn update_rule(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<UpdateRuleRequest>,
) -> AppResult<Json<RuleResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    Ok(Json(
        RuleService::update(&pool, &id, body.into_inner()).await?,
    ))
}

#[endpoint(tags("Rule"), summary = "Delete rule")]
pub async fn delete_rule(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    RuleService::delete(&pool, &id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Rule deleted"
    })))
}
