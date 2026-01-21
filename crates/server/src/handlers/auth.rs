use crate::error::AppError;
use crate::services::{AuthService, UserService};
use crate::services::auth_service::{LoginRequest, LoginResponse, SignupRequest};
use crate::models::UserResponse;
use salvo::oapi::extract::*;
use salvo::oapi::endpoint;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

/// User signup
#[endpoint(
    tags("Authentication"),
    request_body(content = SignupRequest, description = "Signup request"),
    responses(
        (status_code = 200, description = "Signup successful", body = LoginResponse),
        (status_code = 400, description = "Invalid input"),
        (status_code = 409, description = "User already exists")
    )
)]
pub async fn signup(
    depot: &mut Depot,
    req: JsonBody<SignupRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();
    let user_service = UserService::new(pool);
    let auth_service = AuthService::new(user_service);

    let response = auth_service.signup(req.into_inner()).await?;
    Ok(Json(response))
}

/// User login
#[endpoint(
    tags("Authentication"),
    request_body(content = LoginRequest, description = "Login credentials"),
    responses(
        (status_code = 200, description = "Login successful", body = LoginResponse),
        (status_code = 401, description = "Invalid credentials")
    )
)]
pub async fn login(
    depot: &mut Depot,
    req: JsonBody<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();
    let user_service = UserService::new(pool);
    let auth_service = AuthService::new(user_service);

    let response = auth_service.login(req.into_inner()).await?;
    Ok(Json(response))
}

/// User logout
#[endpoint(
    tags("Authentication"),
    responses(
        (status_code = 200, description = "Logout successful")
    )
)]
pub async fn logout() -> &'static str {
    "Logged out successfully"
}

/// Get current account
#[endpoint(
    tags("Authentication"),
    responses(
        (status_code = 200, description = "Current user info", body = UserResponse),
        (status_code = 401, description = "Not authenticated")
    )
)]
pub async fn get_account(depot: &mut Depot) -> Result<Json<UserResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let user_service = UserService::new(pool);
    let auth_service = AuthService::new(user_service);

    let user = auth_service.get_account(&user_id).await?;
    Ok(Json(user))
}
