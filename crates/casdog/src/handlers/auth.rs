use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use salvo::oapi::ToSchema;
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Pool, Postgres};

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{
    ApplicationResponse, CreateApplicationRequest, IntrospectRequest, IntrospectResponse,
    OAuthTokenRequest, OAuthTokenResponse, RevokeRequest, UserResponse,
};
use crate::services::auth_service::{
    CheckPasswordRequest, CheckPasswordResponse, Claims, LoginRequest, LoginResponse,
    SetPasswordRequest, SignupRequest,
};
use crate::services::session_service::SessionService;
use crate::services::token_service::TokenService;
use crate::services::{AppService, AuthService, OrgService, ProviderService, UserService};

#[derive(Debug, Clone)]
struct DeviceAuthCache {
    application_id: String,
    scope: String,
}

static DEVICE_AUTH_CODES: LazyLock<Mutex<HashMap<String, DeviceAuthCache>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static QR_TICKETS: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Serialize, ToSchema)]
pub struct CaptchaStatusResponse {
    pub enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: i32,
    pub interval: i32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QrCodeResponse {
    pub code: String,
    pub ticket: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookEventResponse {
    pub event: String,
    pub ticket: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DynamicClientRegistrationRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
    pub application_type: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DynamicClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: String,
    pub client_id_issued_at: i64,
    pub client_secret_expires_at: i64,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub application_type: String,
    pub contacts: Vec<String>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub scope: Option<String>,
}

fn redirect_uri_allowed(allowed_uris: &str, redirect_uri: &str) -> bool {
    allowed_uris
        .split(|c| c == ',' || c == '\n' || c == ' ')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .any(|value| value == redirect_uri)
}

fn mask_application(mut response: ApplicationResponse) -> ApplicationResponse {
    response.client_secret.clear();
    response
}

fn generate_user_code() -> String {
    let raw = uuid::Uuid::new_v4().simple().to_string().to_uppercase();
    format!("{}-{}", &raw[..4], &raw[4..8])
}

fn captcha_enabled_for_application(application: &crate::models::Application) -> bool {
    application
        .providers
        .as_ref()
        .and_then(serde_json::Value::as_array)
        .map(|providers| {
            providers.iter().any(|provider| {
                let is_captcha = provider
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(|name| name.to_ascii_lowercase().contains("captcha"))
                    .unwrap_or(false);
                let rule = provider
                    .get("rule")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                is_captcha && !rule.trim().is_empty() && !rule.eq_ignore_ascii_case("none")
            })
        })
        .unwrap_or(false)
}

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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_service = UserService::new(pool.clone());
    let auth_service = AuthService::new(user_service);

    let response = auth_service.login(&pool, req.into_inner()).await?;
    Ok(Json(response))
}

/// Get masked application login configuration for OAuth, CAS, or device flows.
#[endpoint(
    tags("Authentication"),
    parameters(
        ("clientId" = Option<String>, Query, description = "OAuth client ID"),
        ("responseType" = Option<String>, Query, description = "OAuth response type"),
        ("redirectUri" = Option<String>, Query, description = "OAuth redirect URI"),
        ("scope" = Option<String>, Query, description = "OAuth scope"),
        ("state" = Option<String>, Query, description = "OAuth state"),
        ("id" = Option<String>, Query, description = "Application ID for CAS flow"),
        ("type" = Option<String>, Query, description = "Login type: code, cas, device"),
        ("userCode" = Option<String>, Query, description = "Device user code"),
    )
)]
pub async fn get_app_login(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<ApplicationResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool.clone());
    let login_type = req
        .query::<String>("type")
        .unwrap_or_else(|| "code".to_string());

    let application = match login_type.as_str() {
        "cas" => {
            let id = req
                .query::<String>("id")
                .ok_or_else(|| AppError::Validation("id is required for CAS login".to_string()))?;
            app_service.get_by_id(&id).await?
        }
        "device" => {
            let user_code = req.query::<String>("userCode").ok_or_else(|| {
                AppError::Validation("userCode is required for device login".to_string())
            })?;

            let cache = DEVICE_AUTH_CODES
                .lock()
                .map_err(|_| AppError::Internal("Device auth cache unavailable".to_string()))?
                .get(&user_code)
                .cloned()
                .ok_or_else(|| AppError::Authentication("Invalid device user code".to_string()))?;

            let _ = cache.scope;
            app_service.get_by_id(&cache.application_id).await?
        }
        _ => {
            let client_id = req.query::<String>("clientId").ok_or_else(|| {
                AppError::Validation("clientId is required for OAuth login".to_string())
            })?;
            let response_type = req.query::<String>("responseType").ok_or_else(|| {
                AppError::Validation("responseType is required for OAuth login".to_string())
            })?;
            let redirect_uri = req.query::<String>("redirectUri").ok_or_else(|| {
                AppError::Validation("redirectUri is required for OAuth login".to_string())
            })?;

            if !matches!(response_type.as_str(), "code" | "token" | "id_token") {
                return Err(AppError::Validation(format!(
                    "Unsupported responseType: {}",
                    response_type
                )));
            }

            let application = app_service.get_by_client_id(&client_id).await?;
            if !application.redirect_uris.is_empty()
                && !redirect_uri_allowed(&application.redirect_uris, &redirect_uri)
            {
                return Err(AppError::Authentication(
                    "Redirect URI mismatch".to_string(),
                ));
            }

            mask_application(application.into())
        }
    };

    Ok(Json(mask_application(application)))
}

/// Returns whether the login page should show a captcha challenge.
#[endpoint(tags("Authentication"), summary = "Get captcha status")]
pub async fn get_captcha_status(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<CaptchaStatusResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let application_name = req
        .query::<String>("application")
        .ok_or_else(|| AppError::Validation("application is required".to_string()))?;
    let app_service = AppService::new(pool);
    let application = app_service.get_by_name("admin", &application_name).await?;

    Ok(Json(CaptchaStatusResponse {
        enabled: captcha_enabled_for_application(&application),
    }))
}

/// Provider callback relay for auth flows that expect a frontend redirect.
#[endpoint(tags("Authentication"), summary = "Callback relay")]
pub async fn callback(req: &mut Request, res: &mut Response) -> AppResult<()> {
    let code = req.query::<String>("code").unwrap_or_default();
    let state = req.query::<String>("state").unwrap_or_default();
    let redirect = format!(
        "/callback?code={}&state={}",
        urlencoding::encode(&code),
        urlencoding::encode(&state)
    );
    res.render(salvo::writing::Redirect::found(redirect));
    Ok(())
}

/// Device authorization endpoint (RFC 8628) initial step.
#[endpoint(tags("OAuth"), summary = "Device authorization")]
pub async fn device_auth(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<DeviceAuthResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let client_id = req
        .query::<String>("client_id")
        .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;
    let scope = req
        .query::<String>("scope")
        .unwrap_or_else(|| "openid".to_string());

    let app_service = AppService::new(pool);
    let application = app_service.get_by_client_id(&client_id).await?;
    let device_code = uuid::Uuid::new_v4().to_string();
    let user_code = generate_user_code();

    let mut cache = DEVICE_AUTH_CODES
        .lock()
        .map_err(|_| AppError::Internal("Device auth cache unavailable".to_string()))?;
    cache.insert(
        device_code.clone(),
        DeviceAuthCache {
            application_id: application.id.clone(),
            scope: scope.clone(),
        },
    );
    cache.insert(
        user_code.clone(),
        DeviceAuthCache {
            application_id: application.id,
            scope,
        },
    );
    drop(cache);

    let config = AppConfig::get();
    let base_url = format!("http://{}:{}", config.server.host, config.server.port);

    Ok(Json(DeviceAuthResponse {
        device_code,
        user_code: user_code.clone(),
        verification_uri: format!("{}/login/oauth/device/{}", base_url, user_code),
        expires_in: 120,
        interval: 5,
    }))
}

/// OAuth dynamic client registration endpoint (RFC 7591 compatible shape).
#[endpoint(tags("OAuth"), summary = "Dynamic client registration")]
pub async fn oauth_register(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DynamicClientRegistrationRequest>,
) -> AppResult<Json<DynamicClientRegistrationResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let organization = req
        .query::<String>("organization")
        .unwrap_or_else(|| "built-in".to_string());
    let org_service = OrgService::new(pool.clone());
    let _ = org_service.get_by_name(&organization).await?;

    let request = body.into_inner();
    if request.redirect_uris.is_empty() {
        return Err(AppError::Validation(
            "redirect_uris must contain at least one URI".to_string(),
        ));
    }

    let grant_types = request
        .grant_types
        .clone()
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    let response_types = request
        .response_types
        .clone()
        .unwrap_or_else(|| vec!["code".to_string()]);
    let client_name = request.client_name.clone().unwrap_or_else(|| {
        format!(
            "DCR Client {}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        )
    });

    let create_request = CreateApplicationRequest {
        owner: "admin".to_string(),
        name: format!("dcr_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        display_name: client_name.clone(),
        logo: request.logo_uri.clone(),
        homepage_url: request.client_uri.clone(),
        description: request.policy_uri.clone(),
        organization: organization.clone(),
        redirect_uris: Some(request.redirect_uris.join(",")),
        token_format: Some("JWT".to_string()),
        expire_in_hours: Some(168),
        cert: None,
        signup_items: None,
        signin_items: None,
        signin_methods: None,
        grant_types: Some(serde_json::json!(grant_types)),
        providers: None,
        enable_password: Some(false),
        enable_signin_session: Some(false),
        enable_code_signin: Some(true),
        enable_web_authn: Some(false),
        enable_internal_signup: Some(false),
        enable_idp_signup: Some(false),
    };

    let app_service = AppService::new(pool);
    let application = app_service.create(create_request).await?;

    Ok(Json(DynamicClientRegistrationResponse {
        client_id: application.client_id,
        client_secret: application.client_secret,
        client_id_issued_at: chrono::Utc::now().timestamp(),
        client_secret_expires_at: 0,
        client_name,
        redirect_uris: request.redirect_uris,
        grant_types,
        response_types,
        token_endpoint_auth_method: request
            .token_endpoint_auth_method
            .unwrap_or_else(|| "client_secret_basic".to_string()),
        application_type: request
            .application_type
            .unwrap_or_else(|| "web".to_string()),
        contacts: request.contacts.unwrap_or_default(),
        logo_uri: request.logo_uri,
        client_uri: request.client_uri,
        policy_uri: request.policy_uri,
        tos_uri: request.tos_uri,
        scope: request.scope,
    }))
}

/// Placeholder QR code endpoint for provider-based sign-in flows.
#[endpoint(tags("Authentication"), summary = "Get QR code")]
pub async fn get_qrcode(depot: &mut Depot, req: &mut Request) -> AppResult<Json<QrCodeResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let id = req
        .query::<String>("id")
        .ok_or_else(|| AppError::Validation("id is required".to_string()))?;
    let _provider = ProviderService::get_by_id(&pool, &id).await?;
    let ticket = uuid::Uuid::new_v4().to_string();
    QR_TICKETS
        .lock()
        .map_err(|_| AppError::Internal("QR ticket cache unavailable".to_string()))?
        .insert(ticket.clone(), "SCAN".to_string());

    Ok(Json(QrCodeResponse {
        code: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==".to_string(),
        ticket,
    }))
}

/// Query the current event state for a QR-code ticket.
#[endpoint(tags("Authentication"), summary = "Get webhook event")]
pub async fn get_webhook_event(req: &mut Request) -> AppResult<Json<WebhookEventResponse>> {
    let ticket = req
        .query::<String>("ticket")
        .ok_or_else(|| AppError::Validation("ticket is required".to_string()))?;

    let event = QR_TICKETS
        .lock()
        .map_err(|_| AppError::Internal("QR ticket cache unavailable".to_string()))?
        .get(&ticket)
        .cloned()
        .ok_or_else(|| AppError::NotFound("ticket not found".to_string()))?;

    Ok(Json(WebhookEventResponse { event, ticket }))
}

/// User logout - supports OIDC RP-initiated logout
///
/// Accepts optional query parameters per the OIDC RP-Initiated Logout spec:
/// - `id_token_hint`: the ID token previously issued to the RP
/// - `post_logout_redirect_uri`: where to redirect after logout
/// - `state`: opaque state value passed through to the redirect
#[endpoint(
    tags("Authentication"),
    parameters(
        ("id_token_hint" = Option<String>, Query, description = "ID token hint for RP-initiated logout"),
        ("post_logout_redirect_uri" = Option<String>, Query, description = "Redirect URI after logout"),
        ("state" = Option<String>, Query, description = "State parameter"),
    ),
    responses(
        (status_code = 200, description = "Logout successful"),
        (status_code = 302, description = "Redirect after logout")
    )
)]
pub async fn logout(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let id_token_hint = req.query::<String>("id_token_hint");
    let post_logout_redirect_uri = req.query::<String>("post_logout_redirect_uri");
    let state = req.query::<String>("state");

    // Get user from depot (JWT) or from id_token_hint
    let user_id = if let Ok(uid) = depot.get::<String>("user_id").cloned() {
        Some(uid)
    } else if let Some(ref token_hint) = id_token_hint {
        // Decode the id_token_hint to get user_id (don't validate expiry)
        extract_user_from_token_hint(token_hint)
    } else {
        None
    };

    if let Some(ref uid) = user_id {
        // Delete tokens and sessions
        AuthService::sso_logout(&pool, uid).await?;

        // Send SSO logout notifications asynchronously
        let pool_clone = pool.clone();
        let uid_clone = uid.clone();
        tokio::spawn(async move {
            if let Err(e) = send_sso_logout_notifications(&pool_clone, &uid_clone).await {
                tracing::warn!("SSO logout notification error: {:?}", e);
            }
        });
    }

    // Handle redirect
    if let Some(redirect_uri) = post_logout_redirect_uri {
        // Build the redirect URL, appending state if provided
        let mut redirect = redirect_uri;
        if let Some(s) = state {
            if redirect.contains('?') {
                redirect = format!("{}&state={}", redirect, urlencoding::encode(&s));
            } else {
                redirect = format!("{}?state={}", redirect, urlencoding::encode(&s));
            }
        }
        res.render(salvo::writing::Redirect::found(redirect));
    } else {
        res.render(Json(
            serde_json::json!({"status": "ok", "message": "Logged out successfully"}),
        ));
    }

    Ok(())
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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let req = req.into_inner();

    // Authenticate the client
    let client_id = req
        .client_id
        .as_deref()
        .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;

    let app_service = AppService::new(pool.clone());
    let application = app_service
        .get_by_client_id(client_id)
        .await
        .map_err(|_| AppError::Authentication("Invalid client_id".to_string()))?;

    // Verify client_secret for confidential clients
    if req.grant_type != "authorization_code" || req.code_verifier.is_none() {
        if let Some(ref secret) = req.client_secret {
            if secret != &application.client_secret {
                return Err(AppError::Authentication(
                    "Invalid client_secret".to_string(),
                ));
            }
        }
    }

    let response = match req.grant_type.as_str() {
        "authorization_code" => {
            let code = req
                .code
                .as_deref()
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
            let refresh_token = req
                .refresh_token
                .as_deref()
                .ok_or_else(|| AppError::Validation("refresh_token is required".to_string()))?;
            TokenService::refresh_access_token(&pool, &application, refresh_token).await?
        }
        "client_credentials" => {
            TokenService::exchange_client_credentials(&pool, &application, req.scope.as_deref())
                .await?
        }
        "password" => {
            let username = req
                .username
                .as_deref()
                .ok_or_else(|| AppError::Validation("username is required".to_string()))?;
            let password = req
                .password
                .as_deref()
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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let req = req.into_inner();
    let client_id = req
        .client_id
        .as_deref()
        .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;
    let refresh_token = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::Validation("refresh_token is required".to_string()))?;

    let app_service = AppService::new(pool.clone());
    let application = app_service
        .get_by_client_id(client_id)
        .await
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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let req = req.into_inner();
    let response =
        TokenService::introspect_token(&pool, &req.token, req.token_type_hint.as_deref()).await?;

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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let user_service = UserService::new(pool);
    let auth_service = AuthService::new(user_service);

    let req = req.into_inner();
    auth_service
        .set_password(&user_id, &req.old_password, &req.new_password)
        .await?;

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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let user_service = UserService::new(pool);
    let auth_service = AuthService::new(user_service);

    let valid = auth_service
        .check_password(&user_id, &req.into_inner().password)
        .await?;

    Ok(Json(CheckPasswordResponse { valid }))
}

/// SSO Logout - revoke tokens with notification support
///
/// Supports selective logout via query parameters:
/// - `application`: logout from a specific application only
/// - `logout_all`: if false, only logout from the specified application (defaults to true)
#[endpoint(
    tags("Authentication"),
    parameters(
        ("application" = Option<String>, Query, description = "Application to logout from"),
        ("logout_all" = Option<bool>, Query, description = "Logout from all apps"),
    ),
    responses(
        (status_code = 200, description = "SSO logout successful")
    )
)]
pub async fn sso_logout(depot: &mut Depot, req: &mut Request) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let application = req.query::<String>("application");
    let logout_all = req.query::<bool>("logout_all").unwrap_or(true);

    if logout_all {
        AuthService::sso_logout(&pool, &user_id).await?;
    } else if let Some(app) = application {
        // Only logout from the specified application
        TokenService::expire_tokens_by_application(&pool, &app).await?;
        SessionService::delete_by_application(&pool, &app).await?;
    } else {
        // No specific app and logout_all is false -- fall back to full logout
        AuthService::sso_logout(&pool, &user_id).await?;
    }

    // Send SSO logout notifications asynchronously
    let pool_clone = pool.clone();
    let uid_clone = user_id.clone();
    tokio::spawn(async move {
        let _ = send_sso_logout_notifications(&pool_clone, &uid_clone).await;
    });

    Ok("SSO logout successful")
}

// ---------------------------------------------------------------------------
// Helper functions for OIDC RP-Initiated Logout and SSO notifications
// ---------------------------------------------------------------------------

/// Extract the user ID (sub claim) from an id_token_hint without validating expiry.
///
/// This is used during RP-initiated logout where the token may already be expired
/// but still carries the subject identifier needed to locate the user's sessions.
fn extract_user_from_token_hint(token: &str) -> Option<String> {
    use jsonwebtoken::{Algorithm, DecodingKey, decode};

    let config = AppConfig::get();
    // Decode WITHOUT validating expiration (token may be expired)
    let mut validation = jsonwebtoken::Validation::new(Algorithm::HS256);
    validation.validate_exp = false;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt.secret.as_bytes()),
        &validation,
    )
    .ok()
    .map(|data| data.claims.sub)
}

/// Send SSO logout notifications to all applications the user has sessions with.
///
/// For each application that has a configured `logout_url`, an HTTP POST is sent
/// with a JSON payload describing the logout event. Notifications are best-effort;
/// failures are logged but do not prevent the logout from completing.
async fn send_sso_logout_notifications(pool: &PgPool, user_id: &str) -> AppResult<()> {
    // Get all distinct application names the user has tokens with
    let app_names: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT application FROM tokens WHERE user_id = $1 AND application IS NOT NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    if app_names.is_empty() {
        return Ok(());
    }

    // Build a shared HTTP client with a short timeout
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let timestamp = chrono::Utc::now().timestamp().to_string();

    for app_name in &app_names {
        // Look up the application to get its logout URL
        let logout_url: Option<String> =
            sqlx::query_scalar("SELECT logout_url FROM applications WHERE name = $1")
                .bind(app_name)
                .fetch_optional(pool)
                .await?
                .flatten();

        if let Some(url) = logout_url {
            if !url.is_empty() {
                // Build and send the notification payload
                let payload = serde_json::json!({
                    "event": "logout",
                    "user_id": user_id,
                    "application": app_name,
                    "timestamp": timestamp,
                });

                let _ = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Casdog-Event", "sso-logout")
                    .json(&payload)
                    .send()
                    .await;

                tracing::debug!("SSO logout notification sent to app: {}", app_name);
            }
        }
    }

    Ok(())
}
