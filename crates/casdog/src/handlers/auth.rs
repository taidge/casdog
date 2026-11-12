use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use salvo::oapi::ToSchema;
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sqlx::{PgPool, Pool, Postgres};

use crate::diesel_pool::DieselPool;

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
use crate::services::token_service::TokenService;
use crate::services::{AppService, AuthService, OrgService, ProviderService, UserService};

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

#[derive(Debug, Deserialize)]
struct OfficialAccountEvent {
    #[serde(rename = "Event")]
    event: Option<String>,
    #[serde(rename = "EventKey")]
    event_key: Option<String>,
    #[serde(rename = "FromUserName")]
    from_user_name: Option<String>,
    #[serde(rename = "Ticket")]
    ticket: Option<String>,
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
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_service = UserService::new(pool);
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let auth_service = AuthService::new(user_service).with_pg_pool(pg_pool);

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
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_service = UserService::new(pool.clone());
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let auth_service = AuthService::new(user_service).with_pg_pool(pg_pool);

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
        .obtain::<DieselPool>()
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

            let pg_pool = depot
                .obtain::<PgPool>()
                .map_err(|_| AppError::Internal("Database unavailable".into()))?;
            let application_id = crate::services::protocol_gap_service::application_for_user_code(
                pg_pool, &user_code,
            )
            .await?;
            app_service.get_by_id(&application_id).await?
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
        .obtain::<DieselPool>()
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
) -> AppResult<Json<serde_json::Value>> {
    let diesel = depot
        .obtain::<DieselPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let pg_pool = depot
        .obtain::<PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let mut value = if req
        .header::<String>("content-type")
        .is_some_and(|header| header.starts_with("application/json"))
    {
        req.parse_json::<serde_json::Value>()
            .await
            .map_err(|_| AppError::Validation("Invalid JSON".into()))?
    } else {
        serde_json::to_value(
            req.parse_form::<std::collections::HashMap<String, String>>()
                .await
                .unwrap_or_default(),
        )
        .map_err(|e| AppError::Validation(e.to_string()))?
    };
    if !value.is_object() {
        return Err(AppError::Validation("Object body required".into()));
    }
    for key in ["client_id", "client_secret", "scope"] {
        if let Some(query) = req.query::<String>(key) {
            value[key] = serde_json::json!(query);
        }
    }
    let mut client_id = value["client_id"].as_str().map(str::to_owned);
    let mut client_secret = value["client_secret"].as_str().map(str::to_owned);
    oauth_client_credentials(req, &mut client_id, &mut client_secret)?;
    let app = authenticate_oauth_client(
        &diesel,
        client_id.as_deref(),
        client_secret.as_deref(),
        false,
    )
    .await?;
    let origin = crate::config::AppConfig::get()
        .server
        .public_url
        .clone()
        .unwrap_or_else(|| {
            let c = crate::config::AppConfig::get();
            format!("http://{}:{}", c.server.host, c.server.port)
        });
    Ok(Json(
        crate::services::protocol_gap_service::begin_device(
            &pg_pool,
            &app,
            value["scope"].as_str().unwrap_or("openid profile"),
            &origin,
        )
        .await?,
    ))
}

/// OAuth dynamic client registration endpoint (RFC 7591 compatible shape).
#[endpoint(tags("OAuth"), summary = "Dynamic client registration")]
pub async fn oauth_register(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DynamicClientRegistrationRequest>,
) -> AppResult<Json<DynamicClientRegistrationResponse>> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    if !principal.admin {
        return Err(AppError::Authorization("Administrator required".into()));
    }
    let organization = req
        .query::<String>("organization")
        .unwrap_or_else(|| principal.owner.clone());
    if !principal.global_admin() && organization != principal.owner {
        return Err(AppError::Authorization("Tenant mismatch".into()));
    }
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
        owner: principal.owner.clone(),
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
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".into()))?;
    crate::services::key_credentials_service::mark_dynamic_application(pg_pool, &application.id)
        .await?;

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
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let id = req
        .query::<String>("id")
        .ok_or_else(|| AppError::Validation("id is required".to_string()))?;
    let _provider = ProviderService::get_by_id(&pg_pool, &id).await?;
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

#[endpoint(tags("Authentication"), summary = "Official account webhook echo")]
pub async fn official_account_webhook_echo(req: &mut Request) -> AppResult<String> {
    Ok(req
        .query::<String>("echostr")
        .or_else(|| req.query::<String>("echoStr"))
        .unwrap_or_default())
}

#[endpoint(
    tags("Authentication"),
    summary = "Handle official account webhook event"
)]
pub async fn handle_official_account_event(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<String> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let body = req
        .payload()
        .await
        .map_err(|e| AppError::Validation(format!("Failed to read webhook body: {}", e)))?;
    let body = String::from_utf8_lossy(body);
    let event = parse_official_account_event(&body)?;
    let event_name = event.event.unwrap_or_default().to_ascii_uppercase();
    if event_name != "SCAN" && event_name != "SUBSCRIBE" {
        return Ok(String::new());
    }

    let ticket = event
        .ticket
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Validation("empty ticket".to_string()))?;
    let provider_id = normalize_wechat_event_key(event.event_key.unwrap_or_default());
    if provider_id.is_empty() {
        return Err(AppError::Validation("empty provider id".to_string()));
    }

    let token: String = sqlx::query_scalar(
        r#"
        SELECT COALESCE(content, client_secret, '')
        FROM providers
        WHERE id = $1 OR name = $1 OR owner || '/' || name = $1
        LIMIT 1
        "#,
    )
    .bind(&provider_id)
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Provider '{}' not found", provider_id)))?;

    let signature = req.query::<String>("signature").unwrap_or_default();
    let timestamp = req.query::<String>("timestamp").unwrap_or_default();
    let nonce = req.query::<String>("nonce").unwrap_or_default();
    if !verify_wechat_signature(&token, &nonce, &timestamp, &signature) {
        return Err(AppError::Authentication(
            "invalid official account signature".to_string(),
        ));
    }

    let value = if let Some(open_id) = event.from_user_name.filter(|value| !value.is_empty()) {
        format!("{}:{}", event_name, open_id)
    } else {
        event_name
    };
    QR_TICKETS
        .lock()
        .map_err(|_| AppError::Internal("QR ticket cache unavailable".to_string()))?
        .insert(ticket, value);

    Ok(String::new())
}

fn parse_official_account_event(body: &str) -> AppResult<OfficialAccountEvent> {
    Ok(OfficialAccountEvent {
        event: xml_tag(body, "Event"),
        event_key: xml_tag(body, "EventKey"),
        from_user_name: xml_tag(body, "FromUserName"),
        ticket: xml_tag(body, "Ticket"),
    })
}

fn xml_tag(body: &str, tag: &str) -> Option<String> {
    let re = regex::Regex::new(&format!(
        r"(?s)<{tag}>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</{tag}>"
    ))
    .ok()?;
    re.captures(body)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_wechat_event_key(value: String) -> String {
    value
        .strip_prefix("qrscene_")
        .unwrap_or(&value)
        .trim()
        .to_string()
}

fn verify_wechat_signature(token: &str, nonce: &str, timestamp: &str, signature: &str) -> bool {
    if token.is_empty() || nonce.is_empty() || timestamp.is_empty() || signature.is_empty() {
        return false;
    }
    let mut parts = [token, timestamp, nonce];
    parts.sort_unstable();
    let mut hasher = Sha1::new();
    hasher.update(parts.concat().as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest.eq_ignore_ascii_case(signature)
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
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let post_logout_redirect_uri = req.query::<String>("post_logout_redirect_uri");
    let state = req.query::<String>("state");

    let user_id = depot.get::<String>("user_id").ok().cloned();
    // Protected logout revokes only the authenticated caller, never a token-hint subject.
    let revocation = req
        .header::<String>("Authorization")
        .and_then(|s| s.strip_prefix("Bearer ").map(str::to_owned))
        .zip(depot.get::<Claims>("claims").ok())
        .map(|(token, claims)| (crate::hoops::auth::session_fingerprint(&token), claims.exp));
    // Only application-registered redirect destinations are permitted.
    if let Some(uri) = post_logout_redirect_uri.as_deref() {
        let allowed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM applications WHERE is_deleted=false AND organization=$1 AND $2 = ANY(regexp_split_to_array(COALESCE(logout_redirect_uris, ''), '[,[:space:]]+')))")
            .bind(depot.get::<String>("user_owner").cloned().unwrap_or_default())
            .bind(uri).fetch_one(&pg_pool).await?;
        if !allowed {
            return Err(AppError::Validation("Unregistered logout redirect".into()));
        }
    }

    if let Some(ref uid) = user_id {
        // Delete tokens and sessions
        AuthService::logout_session(
            &pg_pool,
            uid,
            revocation.as_ref().map(|(hash, exp)| (hash.as_str(), *exp)),
        )
        .await?;

        // Send SSO logout notifications asynchronously
        let pg_pool_clone = pg_pool.clone();
        let uid_clone = uid.clone();
        tokio::spawn(async move {
            if let Err(e) = send_sso_logout_notifications(&pg_pool_clone, &uid_clone).await {
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
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let user_service = UserService::new(pool);
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let auth_service = AuthService::new(user_service).with_pg_pool(pg_pool);

    let user = auth_service.get_account(&user_id).await?;
    Ok(Json(user))
}

async fn oauth_request<T: serde::de::DeserializeOwned>(req: &mut Request) -> AppResult<T> {
    let json = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if json {
        req.parse_json::<T>().await
    } else {
        req.parse_form::<T>().await
    }
    .map_err(|_| AppError::Validation("Invalid OAuth request body".into()))
}

fn oauth_client_credentials(
    req: &Request,
    client_id: &mut Option<String>,
    client_secret: &mut Option<String>,
) -> AppResult<()> {
    use base64::Engine;
    if let Some(header) = req.headers().get("authorization") {
        let value = header
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Basic "))
            .ok_or_else(|| {
                AppError::Authentication("HTTP Basic client authentication required".into())
            })?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| AppError::Authentication("Invalid client credentials".into()))?;
        let (id, secret) = decoded
            .split_once(':')
            .ok_or_else(|| AppError::Authentication("Invalid client credentials".into()))?;
        let decode = |s: &str| {
            urlencoding::decode(&s.replace('+', " "))
                .map(|v| v.into_owned())
                .unwrap_or_default()
        };
        let (id, secret) = (decode(id), decode(secret));
        if client_id.as_ref().is_some_and(|v| v != &id)
            || client_secret.as_ref().is_some_and(|v| v != &secret)
        {
            return Err(AppError::Authentication(
                "Conflicting client credentials".into(),
            ));
        }
        *client_id = Some(id);
        *client_secret = Some(secret);
    }
    Ok(())
}

async fn authenticate_oauth_client(
    pool: &DieselPool,
    client_id: Option<&str>,
    secret: Option<&str>,
    confidential: bool,
) -> AppResult<crate::models::Application> {
    let id = client_id
        .ok_or_else(|| AppError::Authentication("Client authentication required".into()))?;
    let app = AppService::new(pool.clone())
        .get_by_client_id(id)
        .await
        .map_err(|_| AppError::Authentication("Invalid client credentials".into()))?;
    if app.is_deleted
        || (confidential && app.client_secret.is_empty())
        || (!app.client_secret.is_empty() && secret != Some(app.client_secret.as_str()))
    {
        return Err(AppError::Authentication(
            "Invalid client credentials".into(),
        ));
    }
    Ok(app)
}

async fn token_belongs_to_client(
    pool: &DieselPool,
    value: &str,
    app: &crate::models::Application,
) -> AppResult<bool> {
    let token = match TokenService::get_by_access_token(pool, value).await {
        Ok(t) => Some(t),
        Err(_) => TokenService::get_by_refresh_token(pool, value).await.ok(),
    };
    Ok(token.is_some_and(|t| {
        t.owner == app.owner && t.application == app.name && t.organization == app.organization
    }))
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
    request: &mut Request,
    res: &mut Response,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let mut req: OAuthTokenRequest = oauth_request(request).await?;
    oauth_client_credentials(request, &mut req.client_id, &mut req.client_secret)?;

    // Authenticate the client
    let client_id = req
        .client_id
        .as_deref()
        .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;

    let application =
        authenticate_oauth_client(&pool, Some(client_id), req.client_secret.as_deref(), false)
            .await?;
    if application.client_secret.is_empty() && req.grant_type == "client_credentials" {
        return Err(AppError::Authentication(
            "Confidential client required".into(),
        ));
    }

    if let Some(grants) = application.grant_types.as_ref().and_then(|v| v.as_array()) {
        if !grants
            .iter()
            .any(|v| v.as_str() == Some(req.grant_type.as_str()))
        {
            return Err(AppError::Authorization(
                "Grant type is not enabled for this application".into(),
            ));
        }
    }
    if req.grant_type == crate::services::protocol_gap_service::DEVICE_GRANT {
        let pg_pool = depot
            .obtain::<PgPool>()
            .cloned()
            .map_err(|_| AppError::Internal("Database unavailable".into()))?;
        let code = req
            .device_code
            .as_deref()
            .ok_or_else(|| AppError::Validation("device_code is required".into()))?;
        let value =
            crate::services::protocol_gap_service::poll_device(&pg_pool, &pool, &application, code)
                .await?;
        res.add_header("Cache-Control", "no-store", true).ok();
        res.add_header("Pragma", "no-cache", true).ok();
        if value.get("error").is_some() {
            res.status_code(StatusCode::BAD_REQUEST);
        }
        return Ok(Json(value));
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
            let pg_pool = depot
                .obtain::<PgPool>()
                .map_err(|_| AppError::Internal("Authentication database unavailable".into()))?
                .clone();
            let login_request: LoginRequest = serde_json::from_value(serde_json::json!({
                "owner":application.organization,"username":username,"password":password,"clientId":application.client_id
            })).map_err(|e| AppError::Validation(e.to_string()))?;
            let login_result = AuthService::new(UserService::new(pool.clone()))
                .with_pg_pool(pg_pool)
                .login(&pool, login_request)
                .await?;
            if login_result.mfa_required == Some(true)
                || login_result.password_expired == Some(true)
            {
                return Err(AppError::Authentication(
                    "Interactive sign-in required".into(),
                ));
            }
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

    Ok(Json(
        serde_json::to_value(response).map_err(|e| AppError::Internal(e.to_string()))?,
    ))
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
    request: &mut Request,
) -> Result<Json<OAuthTokenResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let mut req: OAuthTokenRequest = oauth_request(request).await?;
    oauth_client_credentials(request, &mut req.client_id, &mut req.client_secret)?;
    let client_id = req
        .client_id
        .as_deref()
        .ok_or_else(|| AppError::Validation("client_id is required".to_string()))?;
    let refresh_token = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::Validation("refresh_token is required".to_string()))?;

    let application =
        authenticate_oauth_client(&pool, Some(client_id), req.client_secret.as_deref(), false)
            .await?;
    if application.client_secret.is_empty() && req.grant_type == "client_credentials" {
        return Err(AppError::Authentication(
            "Confidential client required".into(),
        ));
    }

    if application
        .grant_types
        .as_ref()
        .and_then(|v| v.as_array())
        .is_some_and(|g| !g.iter().any(|v| v.as_str() == Some("refresh_token")))
    {
        return Err(AppError::Authorization(
            "Refresh grant is not enabled".into(),
        ));
    }
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
    request: &mut Request,
) -> Result<Json<IntrospectResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let mut req: IntrospectRequest = oauth_request(request).await?;
    oauth_client_credentials(request, &mut req.client_id, &mut req.client_secret)?;
    let app = authenticate_oauth_client(
        &pool,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        true,
    )
    .await?;
    if !token_belongs_to_client(&pool, &req.token, &app).await? {
        return Ok(Json(
            serde_json::from_value(serde_json::json!({"active":false}))
                .map_err(|e| AppError::Internal(e.to_string()))?,
        ));
    }

    let mut response =
        TokenService::introspect_token(&pool, &req.token, req.token_type_hint.as_deref()).await?;

    if response.active {
        response.client_id = Some(app.client_id.clone());
        response.aud = Some(app.client_id);
    }
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
    request: &mut Request,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let mut req: RevokeRequest = oauth_request(request).await?;
    oauth_client_credentials(request, &mut req.client_id, &mut req.client_secret)?;
    let app = authenticate_oauth_client(
        &pool,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        true,
    )
    .await?;
    if !token_belongs_to_client(&pool, &req.token, &app).await? {
        return Ok("Token revoked");
    }

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
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let user_service = UserService::new(pool);
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let auth_service = AuthService::new(user_service).with_pg_pool(pg_pool);

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
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let user_service = UserService::new(pool);
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let auth_service = AuthService::new(user_service).with_pg_pool(pg_pool);

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
    let pg_pool = depot
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
        AuthService::sso_logout(&pg_pool, &user_id).await?;
    } else if let Some(app) = application {
        let owner = depot
            .get::<String>("user_owner")
            .map_err(|_| AppError::Authentication("Missing tenant".into()))?;
        let apps: Vec<(String,String)> = sqlx::query_as("SELECT owner,name FROM applications WHERE organization=$1 AND NOT is_deleted AND (id=$2 OR name=$2 OR owner || '/' || name=$2) LIMIT 2")
            .bind(owner).bind(&app).fetch_all(&pg_pool).await?;
        if apps.len() != 1 {
            return Err(AppError::Authorization(
                "Application is unavailable in this tenant".into(),
            ));
        }
        let (app_owner, app_name) = &apps[0];
        let mut tx = pg_pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(&user_id)
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM tokens WHERE user_id=$1 AND owner=$2 AND organization=$3 AND application=$4")
            .bind(&user_id).bind(app_owner).bind(owner).bind(app_name).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM sessions WHERE user_id=$1 AND owner=$2 AND application=$3")
            .bind(&user_id)
            .bind(owner)
            .bind(app_name)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    } else {
        // No specific app and logout_all is false -- fall back to full logout
        AuthService::sso_logout(&pg_pool, &user_id).await?;
    }

    // Send SSO logout notifications asynchronously
    let pg_pool_clone = pg_pool.clone();
    let uid_clone = user_id.clone();
    tokio::spawn(async move {
        let _ = send_sso_logout_notifications(&pg_pool_clone, &uid_clone).await;
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
