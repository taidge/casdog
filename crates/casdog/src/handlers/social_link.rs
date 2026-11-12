use chrono::Utc;
use salvo::oapi::{ToSchema, endpoint, extract::JsonBody};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};

use super::social_login;
use crate::error::{AppError, AppResult};
use crate::hoops::auth::session_fingerprint;
use crate::models::{Application, Provider, User};
use crate::services::auth_service::Claims;
use crate::services::social_state_service::{self, NewOAuthFlow, OAuthFlow};
use crate::services::{CheckService, PasswordService};

#[derive(Deserialize, ToSchema)]
pub struct LinkRequest {
    pub application: String,
    #[serde(alias = "providerType")]
    pub provider: Option<String>,
    #[serde(alias = "userId")]
    pub user_id: Option<String>,
    pub password: Option<String>,
}

fn denied(message: &str) -> AppError {
    AppError::Authentication(message.into())
}

fn recent_proof(depot: &Depot, req: &Request) -> AppResult<Value> {
    if req.header::<String>("origin").as_deref() != Some(social_login::public_origin()?.as_str()) {
        return Err(denied(
            "Account linking requires a same-origin browser request",
        ));
    }
    let claims = depot
        .get::<Claims>("claims")
        .map_err(|_| denied("Sign in again to manage linked accounts"))?;
    let now = Utc::now().timestamp_millis();
    let issued = claims.issued_at_ms.unwrap_or(claims.iat * 1000);
    if issued > now
        || now - issued > 300_000
        || claims.exp <= Utc::now().timestamp()
        || claims.impersonator_user_id.is_some()
    {
        return Err(denied(
            "Sign in again before changing account links (within five minutes)",
        ));
    }
    let token = req
        .header::<String>("authorization")
        .and_then(|s| s.strip_prefix("Bearer ").map(str::to_owned))
        .ok_or_else(|| denied("Authenticated session required"))?;
    Ok(
        json!({"user_id":claims.sub,"owner":claims.owner,"token_hash":session_fingerprint(&token),"issued_at_ms":issued,"exp":claims.exp}),
    )
}

fn unlink_allowed(app: &Application, provider: &Provider) -> bool {
    app.providers
        .as_ref()
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                let reference = item.get("name").and_then(Value::as_str).unwrap_or_default();
                (reference == format!("{}/{}", provider.owner, provider.name)
                    || (reference == provider.name && provider.owner == app.owner))
                    && item
                        .get("canUnlink")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
            })
        })
}

/// The same identity lock is used by normal signin and explicit binding.
pub async fn lock_identity(
    tx: &mut Transaction<'_, Postgres>,
    owner: &str,
    provider_id: &str,
    subject: &str,
) -> AppResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("{owner}:oauth:{provider_id}:{subject}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Imported duplicate links must fail closed instead of choosing an arbitrary user.
pub async fn find_identity(
    tx: &mut Transaction<'_, Postgres>,
    owner: &str,
    provider_id: &str,
    subject: &str,
) -> AppResult<Option<User>> {
    let mut users: Vec<User> = sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND provider_ids->>$2=$3 AND is_deleted=false LIMIT 2 FOR UPDATE")
        .bind(owner).bind(format!("oauth:{provider_id}")).bind(subject).fetch_all(&mut **tx).await?;
    if users.len() > 1 {
        return Err(denied(
            "Conflicting social identity bindings require administrator repair",
        ));
    }
    Ok(users.pop())
}

async fn proof_user(
    tx: &mut Transaction<'_, Postgres>,
    proof: &Value,
    owner: &str,
) -> AppResult<User> {
    let id = proof
        .get("user_id")
        .and_then(Value::as_str)
        .ok_or_else(|| denied("Invalid account binding proof"))?;
    let token_hash = proof
        .get("token_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| denied("Invalid account binding proof"))?;
    let issued = proof
        .get("issued_at_ms")
        .and_then(Value::as_i64)
        .ok_or_else(|| denied("Invalid account binding proof"))?;
    let exp = proof
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| denied("Invalid account binding proof"))?;
    if proof.get("owner").and_then(Value::as_str) != Some(owner) || exp <= Utc::now().timestamp() {
        return Err(denied("Account binding session expired"));
    }
    let user: User = sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE")
        .bind(id).bind(owner).fetch_optional(&mut **tx).await?.ok_or_else(|| denied("Account unavailable"))?;
    // Row-lock waits may outlive the JWT even when it was current on entry.
    let checked_at: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    if exp <= checked_at.timestamp() {
        return Err(denied("Account binding session expired"));
    }
    if let Some(changed) = user
        .last_change_password_time
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        let changed = chrono::DateTime::parse_from_rfc3339(changed)
            .map_err(|_| denied("Invalid account credential state"))?;
        if issued <= changed.timestamp_millis() {
            return Err(denied("Credentials changed; sign in again"));
        }
    }
    let revoked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM revoked_session_tokens WHERE token_hash=$1 AND expires_at>NOW()) OR EXISTS(SELECT 1 FROM user_session_epochs WHERE user_id=$2 AND invalid_before>=to_timestamp($3::double precision/1000))")
        .bind(token_hash).bind(id).bind(issued as f64).fetch_one(&mut **tx).await?;
    if revoked {
        return Err(denied("Account binding session revoked"));
    }
    let enabled: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin)")
        .bind(owner).fetch_one(&mut **tx).await?;
    if !enabled {
        return Err(denied("Organization sign-in unavailable"));
    }
    Ok(user)
}

#[endpoint(tags("Social Login"))]
pub async fn begin_link(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<LinkRequest>,
) -> AppResult<Json<Value>> {
    let mut proof = recent_proof(depot, req)?;
    let payload = body.into_inner();
    let id = proof["user_id"].as_str().unwrap();
    if payload
        .user_id
        .as_deref()
        .is_some_and(|target| target != id)
    {
        return Err(AppError::Authorization(
            "Account linking only changes your own account".into(),
        ));
    }
    let pool = social_login::pg_pool(depot)?;
    let app = social_login::application(&pool, &payload.application).await?;
    if proof["owner"].as_str() != Some(app.organization.as_str()) {
        return Err(AppError::Authorization(
            "Application belongs to another organization".into(),
        ));
    }
    CheckService::check_login_permission(&pool, id, &app.id).await?;
    let name = req
        .param::<String>("provider")
        .or(payload.provider)
        .ok_or_else(|| AppError::Validation("Provider required".into()))?;
    let provider = social_login::provider_for_application(&pool, &app, &name).await?;
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let transport = depot
        .obtain::<std::sync::Arc<crate::services::wechat_flow::WeChatTestTransport>>()
        .ok()
        .cloned();
    let (oauth, context) =
        social_login::prepare_oauth(&pool, &provider, user_agent, transport.as_deref()).await?;
    proof
        .as_object_mut()
        .unwrap()
        .extend(context.as_object().unwrap().clone());
    let origin = social_login::public_origin()?;
    let redirect_uri = format!(
        "{origin}/api/auth/{}/callback",
        urlencoding::encode(&provider.name)
    );
    let flow = NewOAuthFlow {
        provider_id: provider.id.clone(),
        provider_name: provider.name.clone(),
        application_id: app.id,
        organization: app.organization,
        redirect_uri: redirect_uri.clone(),
        purpose: "link".into(),
        context: proof.clone(),
    };
    let (state, browser) = social_state_service::create_flow(&pool, &flow).await?;
    let url = social_login::authorization_url(oauth.as_ref(), &proof, &redirect_uri, &state)?;
    social_login::set_cookie(
        res,
        "casdog_oauth_browser",
        &browser,
        300,
        origin.starts_with("https://"),
    );
    Ok(Json(json!({"url":url})))
}

/// Called only after a one-use browser-bound OAuth flow and provider proof have been validated.
pub async fn finalize_link(
    pool: &PgPool,
    flow: &OAuthFlow,
    provider: &Provider,
    subject: &str,
) -> AppResult<()> {
    if flow.purpose != "link"
        || flow.provider_id != provider.id
        || subject.trim().is_empty()
        || subject == "unknown"
        || flow.expires_at <= Utc::now()
    {
        return Err(denied("Invalid account binding flow"));
    }
    let mut tx = pool.begin().await?;
    let app = social_login::application_conn(&mut tx, &flow.application_id).await?;
    if app.organization != flow.organization {
        return Err(denied("Application organization changed"));
    }
    let current =
        social_login::provider_for_application_conn(&mut tx, &app, &flow.provider_name).await?;
    if current.id != provider.id {
        return Err(denied("Provider configuration changed"));
    }
    social_login::lock_provider_stamp(&mut tx, &flow.context, &current).await?;
    let id = flow
        .context
        .get("user_id")
        .and_then(Value::as_str)
        .ok_or_else(|| denied("Invalid account binding proof"))?;
    CheckService::check_login_permission_conn(&mut tx, id, &app.id).await?;
    lock_identity(&mut tx, &flow.organization, &provider.id, subject).await?;
    let existing = find_identity(&mut tx, &flow.organization, &provider.id, subject).await?;
    if existing.as_ref().is_some_and(|user| user.id != id) {
        return Err(AppError::Conflict(
            "This external identity is already linked to another account".into(),
        ));
    }
    let user = proof_user(&mut tx, &flow.context, &flow.organization).await?;
    let checked_at: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    if flow.expires_at <= checked_at {
        return Err(denied("Account binding flow expired"));
    }
    let key = format!("oauth:{}", provider.id);
    if user
        .provider_ids
        .as_ref()
        .and_then(|v| v.get(&key))
        .and_then(Value::as_str)
        .is_some_and(|value| value != subject)
    {
        return Err(AppError::Conflict(
            "Unlink the existing identity for this provider before replacing it".into(),
        ));
    }
    sqlx::query("UPDATE users SET provider_ids=COALESCE(provider_ids,'{}'::jsonb) || jsonb_build_object($1::text,$2::text),updated_at=NOW() WHERE id=$3")
        .bind(key).bind(subject).bind(&user.id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[endpoint(tags("Social Login"))]
pub async fn list_links(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let pool = social_login::pg_pool(depot)?;
    let claims = depot
        .get::<Claims>("claims")
        .map_err(|_| denied("Authentication required"))?;
    let user: User = sqlx::query_as(
        "SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_forbidden",
    )
    .bind(&claims.sub)
    .bind(&claims.owner)
    .fetch_one(&pool)
    .await?;
    let app = if let Some(reference) = req.query::<String>("application").filter(|v| !v.is_empty())
    {
        let app = social_login::application(&pool, &reference).await?;
        if app.organization != user.owner {
            return Err(AppError::Authorization(
                "Application belongs to another organization".into(),
            ));
        }
        Some(app)
    } else {
        None
    };
    let providers: Vec<Provider> = sqlx::query_as("SELECT * FROM providers WHERE category='OAuth'")
        .fetch_all(&pool)
        .await?;
    let mut links = Vec::new();
    for provider in providers {
        if user
            .provider_ids
            .as_ref()
            .and_then(|v| v.get(format!("oauth:{}", provider.id)))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            links.push(json!({"provider":provider.name,"provider_id":provider.id,"display_name":provider.display_name,"can_unlink":app.as_ref().is_some_and(|a| unlink_allowed(a,&provider))}));
        }
    }
    Ok(Json(json!({"status":"ok","data":links})))
}

async fn unlink_impl(
    depot: &mut Depot,
    req: &mut Request,
    payload: LinkRequest,
) -> AppResult<Json<Value>> {
    let proof = recent_proof(depot, req)?;
    let id = proof["user_id"].as_str().unwrap();
    if payload
        .user_id
        .as_deref()
        .is_some_and(|target| target != id)
    {
        return Err(AppError::Authorization(
            "Account unlinking only changes your own account".into(),
        ));
    }
    let pool = social_login::pg_pool(depot)?;
    let mut tx = pool.begin().await?;
    let app = social_login::application_conn(&mut tx, &payload.application).await?;
    if proof["owner"].as_str() != Some(app.organization.as_str()) {
        return Err(AppError::Authorization(
            "Application belongs to another organization".into(),
        ));
    }
    let name = req
        .param::<String>("provider")
        .or(payload.provider)
        .ok_or_else(|| AppError::Validation("Provider required".into()))?;
    CheckService::check_login_permission_conn(&mut tx, id, &app.id).await?;
    let provider = social_login::provider_for_application_conn(&mut tx, &app, &name).await?;
    if !unlink_allowed(&app, &provider) {
        return Err(AppError::Authorization(
            "Unlinking is disabled for this provider/application".into(),
        ));
    }
    let user = proof_user(&mut tx, &proof, &app.organization).await?;
    let key = format!("oauth:{}", provider.id);
    if !user
        .provider_ids
        .as_ref()
        .is_some_and(|v| v.get(&key).is_some())
    {
        return Err(AppError::NotFound("Provider is not linked".into()));
    }
    let all: Vec<Provider> = sqlx::query_as("SELECT * FROM providers WHERE category='OAuth'")
        .fetch_all(&mut *tx)
        .await?;
    let alternative = all.iter().any(|other| {
        if other.id == provider.id
            || crate::services::providers::oauth_provider::validate_oauth_configuration(other)
                .is_err()
        {
            return false;
        }
        let configured = app
            .providers
            .as_ref()
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|item| {
                    let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
                    (name == format!("{}/{}", other.owner, other.name)
                        || (name == other.name && other.owner == app.owner))
                        && item
                            .get("canSignIn")
                            .and_then(Value::as_bool)
                            .unwrap_or(true)
                })
            });
        configured
            && user
                .provider_ids
                .as_ref()
                .and_then(|v| v.get(format!("oauth:{}", other.id)))
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
    });
    if !alternative {
        let valid_password = app.enable_password
            && !user.need_update_password
            && !user.password_hash.is_empty()
            && payload.password.as_deref().is_some_and(|password| {
                PasswordService::verify_password(
                    password,
                    &user.password_hash,
                    user.password_type.as_deref().unwrap_or("argon2"),
                    user.password_salt.as_deref(),
                )
                .unwrap_or(false)
            });
        if !valid_password {
            return Err(AppError::Validation("Keep another enabled sign-in method, or confirm your password before unlinking the final social account".into()));
        }
    }
    sqlx::query("UPDATE users SET provider_ids=COALESCE(provider_ids,'{}'::jsonb)-$1::text,updated_at=NOW() WHERE id=$2")
        .bind(key).bind(&user.id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"ok","msg":"Provider unlinked"})))
}

#[endpoint(tags("Social Login"))]
pub async fn unlink_link(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<LinkRequest>,
) -> AppResult<Json<Value>> {
    unlink_impl(depot, req, body.into_inner()).await
}
#[endpoint(tags("Social Login"))]
pub async fn unlink_compat(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<LinkRequest>,
) -> AppResult<Json<Value>> {
    unlink_impl(depot, req, body.into_inner()).await
}
