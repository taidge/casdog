use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, Pool, Postgres};
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RequestChallengeResponse, Url,
};

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{Application, Organization, User};
use crate::services::auth_service::Claims;
use crate::services::social_state_service::proof_hash;
use crate::services::webauthn_service::WebauthnService;
use crate::services::{CheckService, UserService};

#[derive(Debug, Serialize, Deserialize)]
struct AuthenticationStateEntry {
    user_id: String,
    owner: String,
    state: PasskeyAuthentication,
    context: Value,
}

const AUTH_COOKIE: &str = "casdog_webauthn";

fn authentication_cookie(res: &mut Response, value: &str, seconds: u32, origin: &str) {
    let header = format!(
        "{AUTH_COOKIE}={value}; Path=/api/webauthn; HttpOnly; SameSite=Lax; Max-Age={seconds}{}",
        if origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        }
    );
    res.headers_mut()
        .append("set-cookie", header.parse().unwrap());
    res.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
}

fn check_origin(req: &Request, required: bool) -> AppResult<String> {
    let origin = super::social_login::public_origin()?;
    let supplied = req.header::<String>("origin");
    if supplied.as_deref().is_some_and(|value| value != origin) || required && supplied.is_none() {
        return Err(AppError::Authorization(
            "WebAuthn requires a same-origin browser request".into(),
        ));
    }
    Ok(origin)
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

fn build_webauthn_service(_req: &Request) -> AppResult<WebauthnService> {
    let origin = Url::parse(&super::social_login::public_origin()?)
        .map_err(|error| AppError::Config(format!("Invalid WebAuthn public origin: {error}")))?;
    let rp_id = origin
        .host_str()
        .ok_or_else(|| AppError::Config("WebAuthn public origin has no host".into()))?;
    WebauthnService::new(rp_id, &origin, "Casdog")
}

fn registration_proof(
    depot: &Depot,
    req: &Request,
    require_origin: bool,
) -> AppResult<(Claims, String, String)> {
    let origin = check_origin(req, require_origin)?;
    let claims = depot
        .get::<Claims>("claims")
        .cloned()
        .map_err(|_| AppError::Authentication("Authenticated session required".into()))?;
    let token = req
        .header::<String>("authorization")
        .and_then(|value| value.strip_prefix("Bearer ").map(str::to_owned))
        .ok_or_else(|| AppError::Authentication("Authenticated session required".into()))?;
    Ok((claims, token, origin))
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
    conn: &mut PgConnection,
    user_id: &str,
) -> AppResult<Vec<(String, String, DateTime<Utc>, Passkey)>> {
    let rows: Vec<(String, String, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT id, name, created_at, credential_data FROM user_webauthn_credentials WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(conn)
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
    conn: &mut PgConnection,
    credential_id: &str,
    passkey: &Passkey,
) -> AppResult<()> {
    let credential_data = serde_json::to_string(passkey)
        .map_err(|e| AppError::Internal(format!("Failed to encode updated passkey: {}", e)))?;
    sqlx::query("UPDATE user_webauthn_credentials SET credential_data = $1 WHERE id = $2")
        .bind(credential_data)
        .bind(credential_id)
        .execute(conn)
        .await?;
    Ok(())
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
    let passkeys = load_passkey_rows(&mut *pg_pool.acquire().await?, &user_id).await?;
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
    let (claims, token, origin) = registration_proof(depot, req, false)?;
    let request_id =
        WebauthnService::begin_registration_state(&pg_pool, &claims, &token, &origin, &state)
            .await?;

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
    let credential_name = parse_query(req, "name")
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Passkey".to_string());
    if credential_name.len() > 255 {
        return Err(AppError::Validation(
            "Credential name is limited to 255 bytes".into(),
        ));
    }
    let (claims, token, origin) = registration_proof(depot, req, true)?;
    let webauthn = build_webauthn_service(req)?;
    webauthn
        .complete_registration(
            &pool,
            &claims,
            &token,
            &origin,
            &request_id,
            body.into_inner(),
            &credential_name,
        )
        .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "WebAuthn credential registered",
        "requestId": request_id
    })))
}

fn signin_context(req: &Request) -> Value {
    let query =
        |camel: &str, snake: &str| parse_query(req, camel).or_else(|| parse_query(req, snake));
    json!({"response_type":query("responseType","response_type"),"client_id":query("clientId","client_id"),"redirect_uri":query("redirectUri","redirect_uri"),"scope":parse_query(req,"scope"),"state":parse_query(req,"state"),"nonce":parse_query(req,"nonce"),"code_challenge":query("codeChallenge","code_challenge"),"code_challenge_method":query("codeChallengeMethod","code_challenge_method")})
}

async fn signin_policy(
    conn: &mut PgConnection,
    user_id: &str,
    context: &Value,
    created: DateTime<Utc>,
) -> AppResult<(User, Organization, Option<Application>)> {
    let denied = || AppError::Authentication("Invalid or expired WebAuthn sign-in".into());
    let user: User = sqlx::query_as(
        "SELECT * FROM users WHERE id=$1 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(denied)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *conn)
        .await?;
    if created + chrono::Duration::minutes(5) <= now {
        return Err(denied());
    }
    if let Some(changed) = user
        .last_change_password_time
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        let changed = DateTime::parse_from_rfc3339(changed).map_err(|_| denied())?;
        if created <= changed {
            return Err(denied());
        }
    }
    let revoked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_session_epochs WHERE user_id=$1 AND invalid_before>=$2)",
    )
    .bind(user_id)
    .bind(created)
    .fetch_one(&mut *conn)
    .await?;
    if revoked {
        return Err(denied());
    }
    let org: Organization = sqlx::query_as(
        "SELECT * FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin",
    )
    .bind(&user.owner)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(denied)?;
    CheckService::check_signin_lockout(
        user.signin_wrong_times,
        user.last_signin_wrong_time.as_deref(),
        None,
        None,
    )?;
    let app = if let Some(id) = context["application_id"].as_str() {
        let app = super::social_login::application_conn(conn, id).await?;
        if app.organization != user.owner {
            return Err(denied());
        }
        CheckService::check_login_permission_conn(conn, &user.id, &app.id).await?;
        Some(app)
    } else {
        None
    };
    Ok((user, org, app))
}

#[endpoint(tags("WebAuthn"), summary = "Begin WebAuthn sign-in")]
pub async fn signin_begin(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<WebauthnBeginResponse>> {
    let origin = check_origin(req, false)?;
    let pg = super::social_login::pg_pool(depot)?;
    let owner = parse_query(req, "owner").unwrap_or_else(|| "built-in".into());
    let name = parse_query(req, "name")
        .ok_or_else(|| AppError::Validation("name is required for WebAuthn sign-in".into()))?;
    let mut tx = pg.begin().await?;
    let user_id: String = sqlx::query_scalar(
        "SELECT id FROM users WHERE owner=$1 AND name=$2 AND NOT is_deleted AND NOT is_forbidden",
    )
    .bind(&owner)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::Authentication("Account unavailable".into()))?;
    let issued: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let mut context = signin_context(req);
    if let Some(client_id) = context["client_id"].as_str() {
        let app: Application =
            sqlx::query_as("SELECT * FROM applications WHERE client_id=$1 AND NOT is_deleted")
                .bind(client_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| AppError::Authentication("Application unavailable".into()))?;
        if let Some(reference) = parse_query(req, "application") {
            if super::social_login::application_conn(&mut tx, &reference)
                .await?
                .id
                != app.id
            {
                return Err(AppError::Authorization(
                    "Application/client mismatch".into(),
                ));
            }
        }
        context["application_id"] = json!(app.id);
    } else if let Some(reference) = parse_query(req, "application") {
        context["application_id"] = json!(
            super::social_login::application_conn(&mut tx, &reference)
                .await?
                .id
        );
    }
    let (user, org, _) = signin_policy(&mut tx, &user_id, &context, issued).await?;
    let rows = load_passkey_rows(&mut tx, &user.id).await?;
    if rows.is_empty() {
        return Err(AppError::Validation(
            "No passkeys are registered for this account".into(),
        ));
    }
    context["master_stamp"] = json!(proof_hash(
        org.master_password.as_deref().unwrap_or_default()
    ));
    context["passkeys"] = json!(
        rows.iter()
            .map(|(id, _, _, passkey)| json!({"id":id,"stamp":proof_hash(&serde_json::to_string(passkey).unwrap())}))
            .collect::<Vec<_>>()
    );
    let passkeys = rows
        .into_iter()
        .map(|(_, _, _, passkey)| passkey)
        .collect::<Vec<_>>();
    let webauthn = build_webauthn_service(req)?;
    let (options, state): (RequestChallengeResponse, PasskeyAuthentication) =
        webauthn.start_authentication(&passkeys)?;
    sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at<=clock_timestamp()")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webauthn_challenges WHERE user_id=$1 AND purpose='authentication'",
    )
    .bind(&user.id)
    .fetch_one(&mut *tx)
    .await?;
    if count >= 20 {
        return Err(AppError::Validation(
            "Too many pending passkey sign-ins. Try again in five minutes.".into(),
        ));
    }
    let request_id = uuid::Uuid::new_v4().to_string();
    let browser = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let state = AuthenticationStateEntry {
        user_id: user.id.clone(),
        owner,
        state,
        context,
    };
    sqlx::query("INSERT INTO webauthn_challenges(request_id,user_id,owner,purpose,origin,session_hash,state,created_at,expires_at) VALUES($1,$2,$3,'authentication',$4,$5,$6,$7,$7+INTERVAL '5 minutes')")
        .bind(&request_id).bind(&user.id).bind(&state.owner).bind(&origin).bind(proof_hash(&browser))
        .bind(serde_json::to_value(&state).map_err(|error| AppError::Internal(error.to_string()))?).bind(issued)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    authentication_cookie(res, &browser, 300, &origin);
    begin_response(options, request_id)
}

#[endpoint(tags("WebAuthn"), summary = "Finish WebAuthn sign-in")]
pub async fn signin_finish(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<Value>,
) -> AppResult<Json<Value>> {
    let origin = check_origin(req, true)?;
    let request_id = parse_query(req, "requestId")
        .ok_or_else(|| AppError::Validation("requestId is required".into()))?;
    let browser = super::social_login::cookie(req, AUTH_COOKIE)
        .ok_or_else(|| AppError::Authentication("Passkey sign-in browser proof missing".into()))?;
    let pg = super::social_login::pg_pool(depot)?;
    let mut tx = pg.begin().await?;
    let binding: Option<(String, Value, DateTime<Utc>)> = sqlx::query_as("SELECT user_id,state,created_at FROM webauthn_challenges WHERE request_id=$1 AND purpose='authentication' AND origin=$2 AND session_hash=$3 AND expires_at>clock_timestamp()")
        .bind(&request_id).bind(&origin).bind(proof_hash(&browser)).fetch_optional(&mut *tx).await?;
    let (user_id, state_json, created) = binding
        .ok_or_else(|| AppError::Authentication("Unknown or expired WebAuthn sign-in".into()))?;
    let mut state: AuthenticationStateEntry = serde_json::from_value(state_json)
        .map_err(|error| AppError::Internal(format!("Invalid stored WebAuthn sign-in: {error}")))?;
    let (user, org, app) = signin_policy(&mut tx, &user_id, &state.context, created).await?;
    if state.user_id != user.id || state.owner != user.owner {
        return Err(AppError::Authentication(
            "Account organization changed".into(),
        ));
    }
    let consumed = sqlx::query("DELETE FROM webauthn_challenges WHERE request_id=$1 AND purpose='authentication' AND user_id=$2 AND expires_at>clock_timestamp()")
        .bind(&request_id).bind(&user.id).execute(&mut *tx).await?;
    if consumed.rows_affected() != 1 {
        return Err(AppError::Authentication(
            "Unknown or expired WebAuthn sign-in".into(),
        ));
    }
    let webauthn = build_webauthn_service(req)?;
    let verify = || -> AppResult<_> {
        let credential: PublicKeyCredential =
            serde_json::from_value(body.into_inner()).map_err(|error| {
                AppError::Validation(format!("Invalid authentication payload: {error}"))
            })?;
        webauthn.finish_authentication(&credential, &state.state)
    };
    let result = match verify() {
        Ok(result) => result,
        Err(error) => {
            tx.commit().await?;
            return Err(error);
        }
    };
    let rows = load_passkey_rows(&mut tx, &user.id).await?;
    let mut matched = None;
    for (id, _, _, mut passkey) in rows {
        if passkey.cred_id() != result.cred_id() {
            continue;
        }
        let stamp = proof_hash(
            &serde_json::to_string(&passkey)
                .map_err(|error| AppError::Internal(error.to_string()))?,
        );
        let unchanged = state.context["passkeys"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["id"].as_str() == Some(id.as_str())
                    && item["stamp"].as_str() == Some(stamp.as_str())
            })
        });
        if !unchanged {
            return Err(AppError::Authentication(
                "Passkey changed during sign-in".into(),
            ));
        }
        passkey.update_credential(&result);
        persist_passkey(&mut tx, &id, &passkey).await?;
        matched = Some(id);
        break;
    }
    let credential_id =
        matched.ok_or_else(|| AppError::Authentication("Passkey unavailable".into()))?;
    state.context["primary_factor"] = json!("webauthn");
    state.context["webauthn_credential_id"] = json!(credential_id);
    let additional: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_mfa WHERE user_id=$1 AND is_enabled)")
            .bind(&user.id)
            .fetch_one(&mut *tx)
            .await?;
    let response =
        if user.mfa_enabled || user.mfa_email_enabled || user.mfa_phone_enabled || additional {
            let (secret, methods) = super::password_mfa::create_primary_factor_challenge(
                &mut tx,
                &user,
                created,
                app.as_ref().map(|app| app.id.clone()),
                state.context,
            )
            .await?;
            super::social_login::set_cookie(
                res,
                "casdog_password_mfa",
                &secret,
                300,
                origin.starts_with("https://"),
            );
            json!({"mfa_required":true,"mfa_types":methods,"token":"","expires_in":0})
        } else {
            super::password_mfa::primary_login_result(
                depot,
                &mut tx,
                &user,
                &org,
                app.as_ref(),
                created,
                &state.context,
            )
            .await?
        };
    tx.commit().await?;
    authentication_cookie(res, "", 0, &origin);
    Ok(Json(response))
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
    let (claims, token, _) = registration_proof(depot, req, true)?;
    let credential_id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::Validation("Credential id is required".into()))?;
    let mut tx = pool.begin().await?;
    WebauthnService::validate_registration_session(&mut tx, &claims, &token).await?;
    let deleted = sqlx::query("DELETE FROM user_webauthn_credentials WHERE id=$1 AND user_id=$2")
        .bind(&credential_id)
        .bind(&claims.sub)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() != 1 {
        return Err(AppError::NotFound(
            "Passkey not found for this account".into(),
        ));
    }
    tx.commit().await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "WebAuthn credential deleted"
    })))
}
