use crate::diesel_pool::DieselPool;
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;

use crate::error::AppError;
use crate::models::{
    CreateUserRequest, UpdateUserRequest, UserListResponse, UserQuery, UserResponse,
};
use crate::services::UserService;

/// List users
#[endpoint(
    tags("Users"),
    parameters(
        ("owner" = Option<String>, Query, description = "Filter by owner/organization"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size")
    ),
    responses(
        (status_code = 200, description = "List of users", body = UserListResponse),
        (status_code = 401, description = "Not authenticated")
    )
)]
pub async fn list_users(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<UserListResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_service = UserService::new(pool);

    let query = UserQuery {
        owner: req.query("owner"),
        page: req.query("page"),
        page_size: req.query("page_size"),
    };

    let response = user_service.list(query).await?;
    Ok(Json(response))
}

/// Create a user
#[endpoint(
    tags("Users"),
    request_body(content = CreateUserRequest, description = "User to create"),
    responses(
        (status_code = 200, description = "User created", body = UserResponse),
        (status_code = 400, description = "Invalid input"),
        (status_code = 409, description = "User already exists")
    )
)]
pub async fn create_user(
    depot: &mut Depot,
    req: JsonBody<CreateUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_service = UserService::new(pool);

    let response = user_service.create(req.into_inner()).await?;
    Ok(Json(response))
}

/// Get a user by ID
#[endpoint(
    tags("Users"),
    parameters(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status_code = 200, description = "User details", body = UserResponse),
        (status_code = 404, description = "User not found")
    )
)]
pub async fn get_user(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<Json<UserResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_service = UserService::new(pool);

    let response = user_service.get_by_id(&id.into_inner()).await?;
    Ok(Json(response))
}

/// Update a user
#[endpoint(
    tags("Users"),
    parameters(
        ("id" = String, Path, description = "User ID")
    ),
    request_body(content = UpdateUserRequest, description = "User fields to update"),
    responses(
        (status_code = 200, description = "User updated", body = UserResponse),
        (status_code = 404, description = "User not found")
    )
)]
pub async fn update_user(
    depot: &mut Depot,
    id: PathParam<String>,
    req: JsonBody<UpdateUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_service = UserService::new(pool);

    let response = user_service
        .update(&id.into_inner(), req.into_inner())
        .await?;
    Ok(Json(response))
}

/// Delete a user
#[endpoint(
    tags("Users"),
    parameters(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status_code = 200, description = "User deleted"),
        (status_code = 404, description = "User not found")
    )
)]
pub async fn delete_user(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_service = UserService::new(pool);

    user_service.delete(&id.into_inner()).await?;
    Ok("User deleted")
}
