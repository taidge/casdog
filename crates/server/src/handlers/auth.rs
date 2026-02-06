use crate::error::AppError;
use crate::models::{
    IntrospectRequest, IntrospectResponse, OAuthTokenRequest, OAuthTokenResponse, RevokeRequest,
};
use crate::services::auth_service::{
    CheckPasswordRequest, CheckPasswordResponse, LoginRequest, LoginResponse, SetPasswordRequest,
    SignupRequest,
};
use crate::services::token_service::TokenService;
use crate::services::{AppService, AuthService, UserService};
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
    let user_service = UserService::new(pool.clone());
    let auth_service = AuthService::new(user_service);

    let response = auth_service.login(&pool, req.into_inner()).await?;
    Ok(Json(response))
}

/// User logout - deletes tokens and sessions
#[endpoint(
    tags("Authentication"),
    responses(
        (status_code = 200, description = "Logout successful")
    )
)]
pub async fn logout(depot: &mut Depot) -> Result<&'static str, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    if let Ok(user_id) = depot.get::<String>("user_id").cloned() {
        // Delete user's tokens and sessions
        AuthService::sso_logout(&pool, &user_id).await?;
    }

    Ok("Logged out successfully")
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

/// OAuth 2.0 Token endpoint - handles all grant types
#[endpoint(
    tags("OAuth"),
    request_body(content = OAuthTokenRequest, description = "Token request"),
    responses(
        (status_code = 200, description = "Token response", body = OAuthTokenResponse),
        (status_code = 400, description = "Invalid request"),
        (status_code = 401, description = "Authentication failed")
    )
)]
pub async fn oauth_access_token(
    depot: &mut Depot,
    req: JsonBody<OAuthTokenRequest>,
) -> Result<Json<OAuthTokenResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let req = req.into_inner();

    // Authenticate the client
    let client_id = req.client_id.as_deref()
        .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;

    let app_service = AppService::new(pool.clone());
    let application = app_service.get_by_client_id(client_id).await
        .map_err(|_| AppError::Authentication("Invalid client_id".to_string()))?;

    // Verify client_secret for confidential clients
    if req.grant_type != "authorization_code" || req.code_verifier.is_none() {
        if let Some(ref secret) = req.client_secret {
            if secret != &application.client_secret {
                return Err(AppError::Authentication("Invalid client_secret".to_string()));
            }
        }
    }

    let response = match req.grant_type.as_str() {
        "authorization_code" => {
            let code = req.code.as_deref()
                .ok_or_else(|| AppError::Validation("code is required".to_string()))?;
            TokenService::exchange_authorization_code(
                &pool,
                &application,
                code,
                req.redirect_uri.as_deref(),
                req.code_verifier.as_deref(),
            )
            .await?
        }
        "refresh_token" => {
            let refresh_token = req.refresh_token.as_deref()
                .ok_or_else(|| AppError::Validation("refresh_token is required".to_string()))?;
            TokenService::refresh_access_token(&pool, &application, refresh_token).await?
        }
        "client_credentials" => {
            TokenService::exchange_client_credentials(&pool, &application, req.scope.as_deref())
                .await?
        }
        "password" => {
            let username = req.username.as_deref()
                .ok_or_else(|| AppError::Validation("username is required".to_string()))?;
            let password = req.password.as_deref()
                .ok_or_else(|| AppError::Validation("password is required".to_string()))?;
            TokenService::exchange_password(
                &pool,
                &application,
                username,
                password,
                req.scope.as_deref(),
            )
            .await?
        }
        _ => {
            return Err(AppError::Validation(format!(
                "Unsupported grant_type: {}",
                req.grant_type
            )));
        }
    };

    Ok(Json(response))
}

/// Refresh token endpoint
#[endpoint(
    tags("OAuth"),
    request_body(content = OAuthTokenRequest, description = "Refresh token request"),
    responses(
        (status_code = 200, description = "Token response", body = OAuthTokenResponse),
        (status_code = 401, description = "Invalid refresh token")
    )
)]
pub async fn oauth_refresh_token(
    depot: &mut Depot,
    req: JsonBody<OAuthTokenRequest>,
) -> Result<Json<OAuthTokenResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let req = req.into_inner();
    let client_id = req.client_id.as_deref()
        .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;
    let refresh_token = req.refresh_token.as_deref()
        .ok_or_else(|| AppError::Validation("refresh_token is required".to_string()))?;

    let app_service = AppService::new(pool.clone());
    let application = app_service.get_by_client_id(client_id).await
        .map_err(|_| AppError::Authentication("Invalid client_id".to_string()))?;

    let response = TokenService::refresh_access_token(&pool, &application, refresh_token).await?;
    Ok(Json(response))
}

/// Token introspection (RFC 7662)
#[endpoint(
    tags("OAuth"),
    request_body(content = IntrospectRequest, description = "Introspect request"),
    responses(
        (status_code = 200, description = "Introspection response", body = IntrospectResponse)
    )
)]
pub async fn oauth_introspect(
    depot: &mut Depot,
    req: JsonBody<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let req = req.into_inner();
    let response = TokenService::introspect_token(
        &pool,
        &req.token,
        req.token_type_hint.as_deref(),
    )
    .await?;

    Ok(Json(response))
}

/// Token revocation
#[endpoint(
    tags("OAuth"),
    request_body(content = RevokeRequest, description = "Revoke request"),
    responses(
        (status_code = 200, description = "Token revoked")
    )
)]
pub async fn oauth_revoke(
    depot: &mut Depot,
    req: JsonBody<RevokeRequest>,
) -> Result<&'static str, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let req = req.into_inner();
    TokenService::revoke_token(&pool, &req.token, req.token_type_hint.as_deref()).await?;

    Ok("Token revoked")
}

/// Set password (change password)
#[endpoint(
    tags("Authentication"),
    request_body(content = SetPasswordRequest, description = "Set password request"),
    responses(
        (status_code = 200, description = "Password changed"),
        (status_code = 401, description = "Invalid old password")
    )
)]
pub async fn set_password(
    depot: &mut Depot,
    req: JsonBody<SetPasswordRequest>,
) -> Result<&'static str, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let user_service = UserService::new(pool);
    let auth_service = AuthService::new(user_service);

    let req = req.into_inner();
    auth_service.set_password(&user_id, &req.old_password, &req.new_password).await?;

    Ok("Password changed successfully")
}

/// Check user password
#[endpoint(
    tags("Authentication"),
    request_body(content = CheckPasswordRequest, description = "Check password request"),
    responses(
        (status_code = 200, description = "Password check result", body = CheckPasswordResponse)
    )
)]
pub async fn check_user_password(
    depot: &mut Depot,
    req: JsonBody<CheckPasswordRequest>,
) -> Result<Json<CheckPasswordResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let user_service = UserService::new(pool);
    let auth_service = AuthService::new(user_service);

    let valid = auth_service.check_password(&user_id, &req.into_inner().password).await?;

    Ok(Json(CheckPasswordResponse { valid }))
}

/// SSO Logout - revoke all tokens for current user
#[endpoint(
    tags("Authentication"),
    responses(
        (status_code = 200, description = "SSO logout successful")
    )
)]
pub async fn sso_logout(depot: &mut Depot) -> Result<&'static str, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    AuthService::sso_logout(&pool, &user_id).await?;

    Ok("SSO logout successful")
}
