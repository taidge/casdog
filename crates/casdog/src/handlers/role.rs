use crate::diesel_pool::DieselPool;
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;

use crate::error::AppError;
use crate::models::{
    AssignRoleRequest, CreateRoleRequest, RoleListResponse, RoleQuery, RoleResponse,
    UpdateRoleRequest,
};
use crate::services::RoleService;

/// List roles
#[endpoint(
    tags("Roles"),
    parameters(
        ("owner" = Option<String>, Query, description = "Filter by owner"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size")
    ),
    responses(
        (status_code = 200, description = "List of roles", body = RoleListResponse),
        (status_code = 401, description = "Not authenticated")
    )
)]
pub async fn list_roles(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<RoleListResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let role_service = RoleService::new(pool);

    let query = RoleQuery {
        owner: req.query("owner"),
        page: req.query("page"),
        page_size: req.query("page_size"),
    };

    let response = role_service.list(query).await?;
    Ok(Json(response))
}

/// Create a role
#[endpoint(
    tags("Roles"),
    request_body(content = CreateRoleRequest, description = "Role to create"),
    responses(
        (status_code = 200, description = "Role created", body = RoleResponse),
        (status_code = 400, description = "Invalid input"),
        (status_code = 409, description = "Role already exists")
    )
)]
pub async fn create_role(
    depot: &mut Depot,
    req: JsonBody<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let role_service = RoleService::new(pool);

    let response = role_service.create(req.into_inner()).await?;
    Ok(Json(response))
}

/// Get a role by ID
#[endpoint(
    tags("Roles"),
    parameters(
        ("id" = String, Path, description = "Role ID")
    ),
    responses(
        (status_code = 200, description = "Role details", body = RoleResponse),
        (status_code = 404, description = "Role not found")
    )
)]
pub async fn get_role(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<Json<RoleResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let role_service = RoleService::new(pool);

    let response = role_service.get_by_id(&id.into_inner()).await?;
    Ok(Json(response))
}

/// Update a role
#[endpoint(
    tags("Roles"),
    parameters(
        ("id" = String, Path, description = "Role ID")
    ),
    request_body(content = UpdateRoleRequest, description = "Role fields to update"),
    responses(
        (status_code = 200, description = "Role updated", body = RoleResponse),
        (status_code = 404, description = "Role not found")
    )
)]
pub async fn update_role(
    depot: &mut Depot,
    id: PathParam<String>,
    req: JsonBody<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let role_service = RoleService::new(pool);

    let response = role_service
        .update(&id.into_inner(), req.into_inner())
        .await?;
    Ok(Json(response))
}

/// Delete a role
#[endpoint(
    tags("Roles"),
    parameters(
        ("id" = String, Path, description = "Role ID")
    ),
    responses(
        (status_code = 200, description = "Role deleted"),
        (status_code = 404, description = "Role not found")
    )
)]
pub async fn delete_role(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let role_service = RoleService::new(pool);

    role_service.delete(&id.into_inner()).await?;
    Ok("Role deleted")
}

/// Assign a role to a user
#[endpoint(
    tags("Roles"),
    request_body(content = AssignRoleRequest, description = "Role assignment"),
    responses(
        (status_code = 200, description = "Role assigned"),
        (status_code = 404, description = "User or role not found")
    )
)]
pub async fn assign_role(
    depot: &mut Depot,
    req: JsonBody<AssignRoleRequest>,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let role_service = RoleService::new(pool);

    role_service.assign_role(req.into_inner()).await?;
    Ok("Role assigned")
}

/// Get roles for a user
#[endpoint(
    tags("Roles"),
    parameters(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status_code = 200, description = "User roles", body = Vec<RoleResponse>),
        (status_code = 404, description = "User not found")
    )
)]
pub async fn get_user_roles(
    depot: &mut Depot,
    user_id: PathParam<String>,
) -> Result<Json<Vec<RoleResponse>>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let role_service = RoleService::new(pool);

    let response = role_service.get_user_roles(&user_id.into_inner()).await?;
    Ok(Json(response))
}
