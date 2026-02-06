use crate::error::AppError;
use crate::models::{
    BatchEnforceRequest, BatchEnforceResponse, EnforceRequest, EnforceResponse,
    PolicyListResponse, PolicyRequest, StringListResponse,
};
use crate::services::CasbinService;
use salvo::oapi::extract::*;
use salvo::oapi::{endpoint, ToSchema};
use salvo::prelude::*;
use serde::Serialize;

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyActionResponse {
    pub success: bool,
}

/// Check permission (enforce)
#[endpoint(
    tags("Policies"),
    request_body(content = EnforceRequest, description = "Enforce request"),
    responses(
        (status_code = 200, description = "Enforcement result", body = EnforceResponse),
        (status_code = 500, description = "Casbin error")
    )
)]
pub async fn enforce(
    depot: &mut Depot,
    req: JsonBody<EnforceRequest>,
) -> Result<Json<EnforceResponse>, AppError> {
    let casbin_service = depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))?
        .clone();

    let response = casbin_service.enforce(req.into_inner()).await?;
    Ok(Json(response))
}

/// Get all policies
#[endpoint(
    tags("Policies"),
    responses(
        (status_code = 200, description = "List of policies", body = PolicyListResponse),
        (status_code = 500, description = "Casbin error")
    )
)]
pub async fn get_policies(depot: &mut Depot) -> Result<Json<PolicyListResponse>, AppError> {
    let casbin_service = depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))?
        .clone();

    let response = casbin_service.get_policies().await?;
    Ok(Json(response))
}

/// Add a policy
#[endpoint(
    tags("Policies"),
    request_body(content = PolicyRequest, description = "Policy to add"),
    responses(
        (status_code = 200, description = "Policy added", body = PolicyActionResponse),
        (status_code = 400, description = "Invalid policy"),
        (status_code = 500, description = "Casbin error")
    )
)]
pub async fn add_policy(
    depot: &mut Depot,
    req: JsonBody<PolicyRequest>,
) -> Result<Json<PolicyActionResponse>, AppError> {
    let casbin_service = depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))?
        .clone();

    let success = casbin_service.add_policy(req.into_inner()).await?;
    Ok(Json(PolicyActionResponse { success }))
}

/// Remove a policy
#[endpoint(
    tags("Policies"),
    request_body(content = PolicyRequest, description = "Policy to remove"),
    responses(
        (status_code = 200, description = "Policy removed", body = PolicyActionResponse),
        (status_code = 400, description = "Invalid policy"),
        (status_code = 500, description = "Casbin error")
    )
)]
pub async fn remove_policy(
    depot: &mut Depot,
    req: JsonBody<PolicyRequest>,
) -> Result<Json<PolicyActionResponse>, AppError> {
    let casbin_service = depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))?
        .clone();

    let success = casbin_service.remove_policy(req.into_inner()).await?;
    Ok(Json(PolicyActionResponse { success }))
}

/// Batch check permissions (enforce multiple requests)
#[endpoint(
    tags("Policies"),
    request_body(content = BatchEnforceRequest, description = "Batch enforce requests"),
    responses(
        (status_code = 200, description = "Batch enforcement results", body = BatchEnforceResponse),
        (status_code = 500, description = "Casbin error")
    )
)]
pub async fn batch_enforce(
    depot: &mut Depot,
    req: JsonBody<BatchEnforceRequest>,
) -> Result<Json<BatchEnforceResponse>, AppError> {
    let casbin_service = depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))?
        .clone();

    let response = casbin_service.batch_enforce(req.into_inner().requests).await?;
    Ok(Json(response))
}

/// Get all unique objects from policies
#[endpoint(
    tags("Policies"),
    responses(
        (status_code = 200, description = "List of all objects", body = StringListResponse),
        (status_code = 500, description = "Casbin error")
    )
)]
pub async fn get_all_objects(depot: &mut Depot) -> Result<Json<StringListResponse>, AppError> {
    let casbin_service = depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))?
        .clone();

    let data = casbin_service.get_all_objects().await?;
    Ok(Json(StringListResponse { data }))
}

/// Get all unique actions from policies
#[endpoint(
    tags("Policies"),
    responses(
        (status_code = 200, description = "List of all actions", body = StringListResponse),
        (status_code = 500, description = "Casbin error")
    )
)]
pub async fn get_all_actions(depot: &mut Depot) -> Result<Json<StringListResponse>, AppError> {
    let casbin_service = depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))?
        .clone();

    let data = casbin_service.get_all_actions().await?;
    Ok(Json(StringListResponse { data }))
}

/// Get all roles from grouping policies
#[endpoint(
    tags("Policies"),
    responses(
        (status_code = 200, description = "List of all roles", body = StringListResponse),
        (status_code = 500, description = "Casbin error")
    )
)]
pub async fn get_all_roles(depot: &mut Depot) -> Result<Json<StringListResponse>, AppError> {
    let casbin_service = depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))?
        .clone();

    let data = casbin_service.get_all_roles().await?;
    Ok(Json(StringListResponse { data }))
}
