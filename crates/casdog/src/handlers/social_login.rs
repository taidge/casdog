use salvo::oapi::extract::JsonBody;
use salvo::oapi::{ToSchema, endpoint};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::UserResponse;
use crate::services::auth_service::LoginResponse;
use crate::services::providers::oauth_provider::{ProviderUserInfo, create_oauth_provider};
use crate::services::{AuthService, ProviderService, UserService};

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthUrlResponse {
    pub url: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UnlinkRequest {
    #[serde(rename = "providerType")]
    pub provider_type: String,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
}

/// Get OAuth provider auth URL for redirect
#[endpoint(
    tags("Social Login"),
    parameters(
        ("provider" = String, Path, description = "Provider name (e.g. github, google)"),
        ("redirect_uri" = String, Query, description = "Redirect URI after auth"),
        ("state" = Option<String>, Query, description = "State parameter"),
        ("application" = Option<String>, Query, description = "Application name"),
    ),
    responses(
        (status_code = 200, description = "Auth URL", body = AuthUrlResponse),
    )
)]
pub async fn get_provider_auth_url(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<AuthUrlResponse>, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let provider_name = req
        .param::<String>("provider")
        .ok_or_else(|| AppError::Validation("Provider name is required".to_string()))?;
    let redirect_uri = req
        .query::<String>("redirect_uri")
        .ok_or_else(|| AppError::Validation("redirect_uri is required".to_string()))?;
    let state = req
        .query::<String>("state")
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let application = req.query::<String>("application");

    // Get provider config from database (full Provider needed for secrets & custom URLs)
    let provider = ProviderService::get_by_name_internal(&pool, &provider_name)
        .await
        .map_err(|_| AppError::NotFound(format!("Provider '{}' not found", provider_name)))?;

    // Create OAuth provider instance
    let oauth_provider = create_oauth_provider(
        &provider.provider_type,
        provider.client_id.as_deref().unwrap_or(""),
        provider.client_secret.as_deref().unwrap_or(""),
        provider.custom_auth_url.as_deref(),
        provider.custom_token_url.as_deref(),
        provider.custom_user_info_url.as_deref(),
        provider.scopes.as_deref(),
    )
    .ok_or_else(|| {
        AppError::Internal(format!(
            "Unsupported provider type: {}",
            provider.provider_type
        ))
    })?;

    // Build state with application context
    let full_state = if let Some(app) = application {
        format!("{}:{}", state, app)
    } else {
        state
    };

    let url = oauth_provider.get_auth_url(&redirect_uri, &full_state, None);

    Ok(Json(AuthUrlResponse { url }))
}

/// OAuth provider callback - exchange code, get user, create/link, return JWT
#[endpoint(
    tags("Social Login"),
    parameters(
        ("provider" = String, Path, description = "Provider name"),
        ("code" = String, Query, description = "Authorization code"),
        ("state" = String, Query, description = "State parameter"),
    ),
    responses(
        (status_code = 200, description = "Login response", body = LoginResponse),
    )
)]
pub async fn provider_callback(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<LoginResponse>, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let provider_name = req
        .param::<String>("provider")
        .ok_or_else(|| AppError::Validation("Provider name is required".to_string()))?;
    let code = req
        .query::<String>("code")
        .ok_or_else(|| AppError::Validation("Authorization code is required".to_string()))?;
    let state = req.query::<String>("state").unwrap_or_default();

    // Parse application from state if present (format: "uuid:application_name")
    let (original_state, _application_name) = if let Some(idx) = state.rfind(':') {
        (state[..idx].to_string(), Some(state[idx + 1..].to_string()))
    } else {
        (state, None)
    };

    // Get provider config (full Provider needed for secrets & custom URLs)
    let provider = ProviderService::get_by_name_internal(&pool, &provider_name)
        .await
        .map_err(|_| AppError::NotFound(format!("Provider '{}' not found", provider_name)))?;

    // Create OAuth provider instance
    let oauth_provider = create_oauth_provider(
        &provider.provider_type,
        provider.client_id.as_deref().unwrap_or(""),
        provider.client_secret.as_deref().unwrap_or(""),
        provider.custom_auth_url.as_deref(),
        provider.custom_token_url.as_deref(),
        provider.custom_user_info_url.as_deref(),
        provider.scopes.as_deref(),
    )
    .ok_or_else(|| {
        AppError::Internal(format!(
            "Unsupported provider type: {}",
            provider.provider_type
        ))
    })?;

    // Build redirect_uri for code exchange (must match what was used in get_auth_url)
    let base_url = provider
        .domain
        .as_deref()
        .unwrap_or("http://localhost:8000");
    let redirect_uri = format!("{}/api/auth/{}/callback", base_url, provider_name);

    // Exchange code for access token
    let access_token = oauth_provider.exchange_code(&code, &redirect_uri).await?;

    // Get user info from provider
    let provider_user = oauth_provider.get_user_info(&access_token).await?;

    // Try to find existing user by provider link
    let existing_user =
        find_user_by_provider_link(&pool, &provider.provider_type, &provider_user.id).await?;

    let user_service = UserService::new(pool.clone());

    let user_response = if let Some(user) = existing_user {
        // Existing linked user - update last signin
        user_service
            .update_signin_tracking(&user.id, true, None)
            .await
            .ok();
        user
    } else {
        // Try to find by email
        let email_user = if let Some(ref email) = provider_user.email {
            user_service.get_by_email(email).await?
        } else {
            None
        };

        if let Some(user) = email_user {
            // Found user by email - link provider and convert to UserResponse
            let user_resp: UserResponse = user.into();
            user_service
                .link_provider(&user_resp.id, &provider.provider_type, &provider_user.id)
                .await?;
            user_service
                .update_signin_tracking(&user_resp.id, true, None)
                .await
                .ok();
            user_resp
        } else {
            // Create new user from provider info
            let username = generate_unique_username(&pool, &provider_user).await?;
            let owner = "built-in".to_string();

            let create_req = crate::models::CreateUserRequest {
                owner: owner.clone(),
                name: username.clone(),
                password: None, // No password for social login users
                display_name: if provider_user.display_name.is_empty() {
                    username.clone()
                } else {
                    provider_user.display_name.clone()
                },
                email: provider_user.email.clone(),
                phone: None,
                avatar: provider_user.avatar_url.clone(),
                is_admin: None,
                user_type: Some("normal-user".to_string()),
                first_name: None,
                last_name: None,
                country_code: None,
                region: None,
                location: None,
                affiliation: None,
                tag: None,
                language: None,
                gender: None,
                birthday: None,
                education: None,
                bio: None,
                homepage: None,
                signup_application: _application_name.clone(),
                id_card_type: None,
                id_card: None,
                real_name: None,
                properties: None,
            };

            let new_user = user_service.create(create_req).await?;

            // Link provider to new user
            user_service
                .link_provider(&new_user.id, &provider.provider_type, &provider_user.id)
                .await?;

            new_user
        }
    };

    // Generate JWT token
    let auth_service = AuthService::new(user_service);
    let token = auth_service.generate_token(&user_response)?;

    Ok(Json(LoginResponse {
        token,
        token_type: "Bearer".to_string(),
        expires_in: 24 * 3600, // Default 24h
        user: user_response,
        redirect_uri: None,
        code: None,
        state: Some(original_state),
        mfa_required: None,
        mfa_types: None,
        password_expired: None,
    }))
}

/// Unlink a provider from current user
#[endpoint(
    tags("Social Login"),
    parameters(
        ("provider" = String, Path, description = "Provider type to unlink"),
    ),
    responses(
        (status_code = 200, description = "Provider unlinked"),
    )
)]
pub async fn unlink_provider(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;
    let provider_type = req
        .param::<String>("provider")
        .ok_or_else(|| AppError::Validation("Provider type is required".to_string()))?;

    let user_service = UserService::new(pool);
    user_service
        .unlink_provider(&user_id, &provider_type)
        .await?;
    Ok("Provider unlinked successfully")
}

/// Casdoor-compatible unlink endpoint using a JSON body.
#[endpoint(tags("Social Login"), summary = "Unlink provider")]
pub async fn unlink_provider_compat(
    depot: &mut Depot,
    body: JsonBody<UnlinkRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let current_user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;
    let is_admin = depot.get::<bool>("is_admin").copied().unwrap_or(false);
    let req = body.into_inner();
    let target_user_id = req.user_id.unwrap_or_else(|| current_user_id.clone());

    if target_user_id != current_user_id && !is_admin {
        return Err(AppError::Authentication(
            "Only admins can unlink providers for another user".to_string(),
        ));
    }

    let user_service = UserService::new(pool);
    user_service
        .unlink_provider(&target_user_id, &req.provider_type)
        .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Provider unlinked successfully",
        "userId": target_user_id,
        "providerType": req.provider_type
    })))
}

/// Find user by provider ID stored in the JSONB `provider_ids` field
async fn find_user_by_provider_link(
    pool: &Pool<Postgres>,
    provider_type: &str,
    provider_id: &str,
) -> AppResult<Option<UserResponse>> {
    // provider_ids is a JSONB field like {"GitHub": "12345", "Google": "67890"}
    let user: Option<crate::models::User> = sqlx::query_as(
        "SELECT * FROM users WHERE provider_ids->>$1 = $2 AND is_deleted = false LIMIT 1",
    )
    .bind(provider_type)
    .bind(provider_id)
    .fetch_optional(pool)
    .await?;

    Ok(user.map(|u| u.into()))
}

/// Generate a unique username from provider user info
async fn generate_unique_username(
    pool: &Pool<Postgres>,
    provider_user: &ProviderUserInfo,
) -> AppResult<String> {
    // Try provider username first, then email prefix, then provider ID prefix
    let base = if !provider_user.username.is_empty() {
        // Sanitize: only allow alphanumeric + underscore
        provider_user
            .username
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect::<String>()
    } else if let Some(ref email) = provider_user.email {
        email.split('@').next().unwrap_or("user").to_string()
    } else {
        format!(
            "user_{}",
            &provider_user.id[..8.min(provider_user.id.len())]
        )
    };

    // Ensure username is not empty and starts with a letter
    let base = if base.is_empty() {
        "user".to_string()
    } else if base
        .chars()
        .next()
        .map(|c| c.is_alphabetic())
        .unwrap_or(false)
    {
        base
    } else {
        format!("u{}", base)
    };

    // Check uniqueness, append number if needed
    let mut username = base.clone();
    let mut counter = 1u32;
    loop {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE name = $1 AND is_deleted = false)",
        )
        .bind(&username)
        .fetch_one(pool)
        .await?;

        if !exists {
            return Ok(username);
        }
        username = format!("{}_{}", base, counter);
        counter += 1;
        if counter > 100 {
            // Fall back to UUID suffix to guarantee uniqueness
            let suffix = &uuid::Uuid::new_v4().to_string().replace('-', "")[..6];
            username = format!("{}_{}", base, suffix);
            break;
        }
    }

    Ok(username)
}
