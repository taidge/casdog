use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::Serialize;
use sqlx::{Pool, Postgres};
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url,
};

use crate::config::AppConfig;
use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::services::auth_service::LoginResponse;
use crate::services::webauthn_service::WebauthnService;
use crate::services::{AppService, AuthService, TokenService, UserService};

#[derive(Debug, Clone)]
struct RegistrationStateEntry {
    user_id: String,
    state: PasskeyRegistration,
}

#[derive(Debug, Clone)]
struct AuthenticationStateEntry {
    user_id: String,
    owner: String,
    name: String,
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state_param: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: PasskeyAuthentication,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebauthnBeginResponse {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebauthnCredentialResponse {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

static REGISTRATION_STATES: LazyLock<Mutex<HashMap<String, RegistrationStateEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static AUTHENTICATION_STATES: LazyLock<Mutex<HashMap<String, AuthenticationStateEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_request_host(req: &Request) -> String {
    req.headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            let config = AppConfig::get();
            format!("{}:{}", config.server.host, config.server.port)
        })
}

fn build_webauthn_service(req: &Request) -> AppResult<WebauthnService> {
    let host = get_request_host(req);
    let rp_id = host
        .split(':')
        .next()
        .filter(|value| !value.is_empty() && *value != "0.0.0.0")
        .unwrap_or("localhost");
    let origin = Url::parse(&format!("http://{}", host))
        .map_err(|e| AppError::Internal(format!("Invalid WebAuthn origin: {}", e)))?;

    WebauthnService::new(rp_id, &origin, "Casdog")
}

fn begin_response<T: Serialize>(
    options: T,
    request_id: String,
) -> AppResult<Json<WebauthnBeginResponse>> {
    let options = serde_json::to_value(options).map_err(|e| {
        AppError::Internal(format!("Failed to serialize WebAuthn challenge: {}", e))
    })?;
    Ok(Json(WebauthnBeginResponse {
        request_id,
        options,
    }))
}

fn parse_query(req: &Request, key: &str) -> Option<String> {
    req.query::<String>(key).filter(|value| !value.is_empty())
}

async fn load_passkey_rows(
    pool: &Pool<Postgres>,
    user_id: &str,
) -> AppResult<Vec<(String, String, DateTime<Utc>, Passkey)>> {
    let rows: Vec<(String, String, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT id, name, created_at, credential_data FROM user_webauthn_credentials WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|(id, name, created_at, credential_data)| {
            let passkey = serde_json::from_str::<Passkey>(&credential_data).map_err(|e| {
                AppError::Internal(format!("Failed to decode stored passkey '{}': {}", id, e))
            })?;
            Ok((id, name, created_at, passkey))
        })
        .collect()
}

async fn persist_passkey(
    pool: &Pool<Postgres>,
    credential_id: &str,
    passkey: &Passkey,
) -> AppResult<()> {
    let credential_data = serde_json::to_string(passkey)
        .map_err(|e| AppError::Internal(format!("Failed to encode updated passkey: {}", e)))?;
    sqlx::query("UPDATE user_webauthn_credentials SET credential_data = $1 WHERE id = $2")
        .bind(credential_data)
        .bind(credential_id)
        .execute(pool)
        .await?;
    Ok(())
}

fn take_registration_state(request_id: &str) -> AppResult<RegistrationStateEntry> {
    REGISTRATION_STATES
        .lock()
        .map_err(|_| AppError::Internal("WebAuthn registration state unavailable".to_string()))?
        .remove(request_id)
        .ok_or_else(|| AppError::Validation("Unknown or expired requestId".to_string()))
}

fn take_authentication_state(request_id: &str) -> AppResult<AuthenticationStateEntry> {
    AUTHENTICATION_STATES
        .lock()
        .map_err(|_| AppError::Internal("WebAuthn authentication state unavailable".to_string()))?
        .remove(request_id)
        .ok_or_else(|| AppError::Validation("Unknown or expired requestId".to_string()))
}

#[endpoint(tags("WebAuthn"), summary = "Begin WebAuthn registration")]
pub async fn signup_begin(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<WebauthnBeginResponse>> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let user_service = UserService::new(pool.clone());
    let user = user_service.get_by_id_internal(&user_id).await?;
    let passkeys = load_passkey_rows(&pg_pool, &user_id).await?;
    let existing_credentials = if passkeys.is_empty() {
        None
    } else {
        Some(
            passkeys
                .iter()
                .map(|(_, _, _, passkey)| passkey.cred_id().clone())
                .collect(),
        )
    };

    let webauthn = build_webauthn_service(req)?;
    let (options, state): (CreationChallengeResponse, PasskeyRegistration) = webauthn
        .start_registration(
            user.id.as_bytes(),
            &user.name,
            &user.display_name,
            existing_credentials,
        )?;
    let request_id = uuid::Uuid::new_v4().to_string();

    REGISTRATION_STATES
        .lock()
        .map_err(|_| AppError::Internal("WebAuthn registration state unavailable".to_string()))?
        .insert(
            request_id.clone(),
            RegistrationStateEntry { user_id, state },
        );

    begin_response(options, request_id)
}

#[endpoint(tags("WebAuthn"), summary = "Finish WebAuthn registration")]
pub async fn signup_finish(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let request_id = parse_query(req, "requestId")
        .ok_or_else(|| AppError::Validation("requestId is required".to_string()))?;
    let credential_name = parse_query(req, "name").unwrap_or_else(|| "Passkey".to_string());
    let state = take_registration_state(&request_id)?;
    let credential: RegisterPublicKeyCredential = serde_json::from_value(body.into_inner())
        .map_err(|e| AppError::Validation(format!("Invalid registration payload: {}", e)))?;

    let webauthn = build_webauthn_service(req)?;
    let passkey = webauthn.finish_registration(&credential, &state.state)?;
    WebauthnService::save_credential(&pool, &state.user_id, &passkey, &credential_name).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "WebAuthn credential registered",
        "requestId": request_id
    })))
}

#[endpoint(tags("WebAuthn"), summary = "Begin WebAuthn sign-in")]
pub async fn signin_begin(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<WebauthnBeginResponse>> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let owner = parse_query(req, "owner").unwrap_or_else(|| "built-in".to_string());
    let name = parse_query(req, "name")
        .ok_or_else(|| AppError::Validation("name is required for WebAuthn sign-in".to_string()))?;

    let user_service = UserService::new(pool.clone());
    let user = user_service.get_by_name(&owner, &name).await?;
    let passkey_rows = load_passkey_rows(&pg_pool, &user.id).await?;
    if passkey_rows.is_empty() {
        return Err(AppError::Validation(
            "Found no WebAuthn credentials for this user".to_string(),
        ));
    }

    let passkeys: Vec<Passkey> = passkey_rows
        .iter()
        .map(|(_, _, _, passkey)| passkey.clone())
        .collect();
    let webauthn = build_webauthn_service(req)?;
    let (options, state): (RequestChallengeResponse, PasskeyAuthentication) =
        webauthn.start_authentication(&passkeys)?;
    let request_id = uuid::Uuid::new_v4().to_string();

    AUTHENTICATION_STATES
        .lock()
        .map_err(|_| AppError::Internal("WebAuthn authentication state unavailable".to_string()))?
        .insert(
            request_id.clone(),
            AuthenticationStateEntry {
                user_id: user.id,
                owner,
                name,
                response_type: parse_query(req, "responseType"),
                client_id: parse_query(req, "clientId"),
                redirect_uri: parse_query(req, "redirectUri"),
                scope: parse_query(req, "scope"),
                state_param: parse_query(req, "state"),
                nonce: parse_query(req, "nonce"),
                code_challenge: parse_query(req, "codeChallenge"),
                code_challenge_method: parse_query(req, "codeChallengeMethod"),
                state,
            },
        );

    begin_response(options, request_id)
}

#[endpoint(tags("WebAuthn"), summary = "Finish WebAuthn sign-in")]
pub async fn signin_finish(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<serde_json::Value>,
) -> AppResult<Json<LoginResponse>> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let request_id = parse_query(req, "requestId")
        .ok_or_else(|| AppError::Validation("requestId is required".to_string()))?;
    let state = take_authentication_state(&request_id)?;
    let assertion: PublicKeyCredential = serde_json::from_value(body.into_inner())
        .map_err(|e| AppError::Validation(format!("Invalid authentication payload: {}", e)))?;

    let passkey_rows = load_passkey_rows(&pg_pool, &state.user_id).await?;
    let passkeys: Vec<Passkey> = passkey_rows
        .iter()
        .map(|(_, _, _, passkey)| passkey.clone())
        .collect();
    if passkeys.is_empty() {
        return Err(AppError::Validation(
            "Found no WebAuthn credentials for this user".to_string(),
        ));
    }

    let webauthn = build_webauthn_service(req)?;
    let auth_result = webauthn.finish_authentication(&assertion, &state.state)?;

    for (credential_row_id, _, _, mut passkey) in passkey_rows {
        if passkey.update_credential(&auth_result).unwrap_or(false) {
            persist_passkey(&pg_pool, &credential_row_id, &passkey).await?;
            break;
        }
    }

    let user_service = UserService::new(pool.clone());
    let user = user_service.get_by_id(&state.user_id).await?;
    user_service
        .update_signin_tracking(&state.user_id, true, None)
        .await?;

    let auth_service = AuthService::new(user_service);
    let token = auth_service.generate_token(&user)?;

    if let (Some(response_type), Some(client_id), Some(redirect_uri)) = (
        state.response_type.as_deref(),
        state.client_id.as_deref(),
        state.redirect_uri.as_deref(),
    ) {
        if response_type == "code" {
            let application = AppService::new(pool.clone())
                .get_by_client_id(client_id)
                .await?;
            let scope = state.scope.as_deref().unwrap_or("openid profile");
            let code = TokenService::create_authorization_code(
                &pool,
                &application,
                &state.user_id,
                scope,
                state.nonce.as_deref(),
                redirect_uri,
                state.code_challenge.as_deref(),
                state.code_challenge_method.as_deref(),
            )
            .await?;

            return Ok(Json(LoginResponse {
                token,
                token_type: "Bearer".to_string(),
                expires_in: AppConfig::get().jwt.expiration_hours * 3600,
                user,
                redirect_uri: Some(redirect_uri.to_string()),
                code: Some(code),
                state: state.state_param,
                mfa_required: None,
                mfa_types: None,
                password_expired: None,
            }));
        }
    }

    Ok(Json(LoginResponse {
        token,
        token_type: "Bearer".to_string(),
        expires_in: AppConfig::get().jwt.expiration_hours * 3600,
        user,
        redirect_uri: None,
        code: None,
        state: state.state_param,
        mfa_required: None,
        mfa_types: None,
        password_expired: None,
    }))
}

#[endpoint(tags("WebAuthn"), summary = "List current user's WebAuthn credentials")]
pub async fn list_credentials(
    depot: &mut Depot,
) -> AppResult<Json<Vec<WebauthnCredentialResponse>>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let credentials: Vec<(String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, name, created_at FROM user_webauthn_credentials WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await?;

    Ok(Json(
        credentials
            .into_iter()
            .map(|(id, name, created_at)| WebauthnCredentialResponse {
                id,
                name,
                created_at,
            })
            .collect(),
    ))
}

#[endpoint(tags("WebAuthn"), summary = "Delete a WebAuthn credential")]
pub async fn delete_credential(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;
    let credential_id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::Validation("Credential id is required".to_string()))?;

    let owner: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM user_webauthn_credentials WHERE id = $1")
            .bind(&credential_id)
            .fetch_optional(&pool)
            .await?;
    if owner.as_deref() != Some(user_id.as_str()) {
        return Err(AppError::Authentication(
            "You can only delete your own WebAuthn credentials".to_string(),
        ));
    }

    WebauthnService::delete_credential(&pool, &credential_id).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "WebAuthn credential deleted"
    })))
}
