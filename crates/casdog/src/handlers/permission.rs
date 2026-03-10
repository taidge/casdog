use crate::diesel_pool::DieselPool;
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;

use crate::error::AppError;
use crate::models::{
    AssignPermissionRequest, CreatePermissionRequest, PermissionListResponse, PermissionQuery,
    PermissionResponse, UpdatePermissionRequest,
};
use crate::services::PermissionService;

/// List permissions
#[endpoint(
    tags("Permissions"),
    parameters(
        ("owner" = Option<String>, Query, description = "Filter by owner"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size")
    ),
    responses(
        (status_code = 200, description = "List of permissions", body = PermissionListResponse),
        (status_code = 401, description = "Not authenticated")
    )
)]
pub async fn list_permissions(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<PermissionListResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let permission_service = PermissionService::new(pool);

    let query = PermissionQuery {
        owner: req.query("owner"),
        page: req.query("page"),
        page_size: req.query("page_size"),
    };

    let response = permission_service.list(query).await?;
    Ok(Json(response))
}

/// Create a permission
#[endpoint(
    tags("Permissions"),
    request_body(content = CreatePermissionRequest, description = "Permission to create"),
    responses(
        (status_code = 200, description = "Permission created", body = PermissionResponse),
        (status_code = 400, description = "Invalid input"),
        (status_code = 409, description = "Permission already exists")
    )
)]
pub async fn create_permission(
    depot: &mut Depot,
    req: JsonBody<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let permission_service = PermissionService::new(pool);

    let response = permission_service.create(req.into_inner()).await?;
    Ok(Json(response))
}

/// Get a permission by ID
#[endpoint(
    tags("Permissions"),
    parameters(
        ("id" = String, Path, description = "Permission ID")
    ),
    responses(
        (status_code = 200, description = "Permission details", body = PermissionResponse),
        (status_code = 404, description = "Permission not found")
    )
)]
pub async fn get_permission(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<Json<PermissionResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let permission_service = PermissionService::new(pool);

    let response = permission_service.get_by_id(&id.into_inner()).await?;
    Ok(Json(response))
}

/// Update a permission
#[endpoint(
    tags("Permissions"),
    parameters(
        ("id" = String, Path, description = "Permission ID")
    ),
    request_body(content = UpdatePermissionRequest, description = "Permission fields to update"),
    responses(
        (status_code = 200, description = "Permission updated", body = PermissionResponse),
        (status_code = 404, description = "Permission not found")
    )
)]
pub async fn update_permission(
    depot: &mut Depot,
    id: PathParam<String>,
    req: JsonBody<UpdatePermissionRequest>,
) -> Result<Json<PermissionResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let permission_service = PermissionService::new(pool);

    let response = permission_service
        .update(&id.into_inner(), req.into_inner())
        .await?;
    Ok(Json(response))
}

/// Delete a permission
#[endpoint(
    tags("Permissions"),
    parameters(
        ("id" = String, Path, description = "Permission ID")
    ),
    responses(
        (status_code = 200, description = "Permission deleted"),
        (status_code = 404, description = "Permission not found")
    )
)]
pub async fn delete_permission(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let permission_service = PermissionService::new(pool);

    permission_service.delete(&id.into_inner()).await?;
    Ok("Permission deleted")
}

/// Assign a permission to a role
#[endpoint(
    tags("Permissions"),
    request_body(content = AssignPermissionRequest, description = "Permission assignment"),
    responses(
        (status_code = 200, description = "Permission assigned"),
        (status_code = 404, description = "Role or permission not found")
    )
)]
pub async fn assign_permission(
    depot: &mut Depot,
    req: JsonBody<AssignPermissionRequest>,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let permission_service = PermissionService::new(pool);

    permission_service
        .assign_permission(req.into_inner())
        .await?;
    Ok("Permission assigned")
}

/// Get permissions for a role
#[endpoint(
    tags("Permissions"),
    parameters(
        ("role_id" = String, Path, description = "Role ID")
    ),
    responses(
        (status_code = 200, description = "Role permissions", body = Vec<PermissionResponse>),
        (status_code = 404, description = "Role not found")
    )
)]
pub async fn get_role_permissions(
    depot: &mut Depot,
    role_id: PathParam<String>,
) -> Result<Json<Vec<PermissionResponse>>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let permission_service = PermissionService::new(pool);

    let response = permission_service
        .get_role_permissions(&role_id.into_inner())
        .await?;
    Ok(Json(response))
}
