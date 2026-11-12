//! Shared OAuth completion and second-factor continuation. A completion row is a
//! short-lived proof, not a session. Its deletion and consumable factors commit together.
use chrono::{DateTime, Utc};
use rand::Rng;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgConnection;

use super::social_login::{
    application_conn, cookie, ensure_social_account_policy_conn, pg_pool,
    provider_for_application_conn, public_origin, set_cookie,
};
use crate::config::AppConfig;
use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{Application, Provider, User, UserResponse};
use crate::services::mfa_service::{MfaService, UserMfa};
use crate::services::social_state_service::{self as state, Completion};
use crate::services::{AuthService, CheckService, ProviderDispatchService, UserService};

const SESSION_COOKIE: &str = "casdog_oauth_completion";
#[derive(Default, Deserialize)]
struct FactorRequest {
    #[serde(alias = "mfaType")]
    mfa_type: Option<String>,
    passcode: Option<String>,
}
fn denied() -> AppError {
    AppError::Authentication("Invalid or expired social sign-in proof".into())
}
fn request_proof(req: &Request) -> AppResult<Option<String>> {
    let proof = cookie(req, SESSION_COOKIE);
    if proof.is_some()
        && req.header::<String>("origin").as_deref() != Some(public_origin()?.as_str())
    {
        return Err(AppError::Authentication(
            "OAuth session origin mismatch".into(),
        ));
    }
    Ok(proof)
}
async fn payload(req: &mut Request) -> AppResult<FactorRequest> {
    let bytes = req
        .payload()
        .await
        .map_err(|_| AppError::Validation("Invalid second-factor body".into()))?;
    if bytes.is_empty() {
        return Ok(FactorRequest::default());
    }
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::Validation("Invalid second-factor body".into()))
}
async fn policy(
    conn: &mut PgConnection,
    completion: &Completion,
) -> AppResult<(Application, User, Vec<UserMfa>, Vec<String>)> {
    let app = application_conn(conn, &completion.application_id).await?;
    if app.organization != completion.organization {
        return Err(denied());
    }
    let provider = provider_for_application_conn(conn, &app, &completion.provider_name).await?;
    if provider.id != completion.provider_id {
        return Err(denied());
    }
    super::social_login::lock_provider_stamp(conn, &completion.context, &provider).await?;
    let user: User=sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE")
        .bind(&completion.user_id).bind(&completion.organization).fetch_optional(&mut *conn).await?.ok_or_else(denied)?;
    ensure_social_account_policy_conn(conn, &user).await?;
    CheckService::check_login_permission_conn(conn, &user.id, &app.id).await?;
    CheckService::check_signin_lockout(
        user.signin_wrong_times,
        user.last_signin_wrong_time.as_deref(),
        None,
        None,
    )?;
    let subject = completion
        .context
        .get("subject")
        .and_then(Value::as_str)
        .ok_or_else(denied)?;
    let link_key = completion
        .context
        .get("link_key")
        .and_then(Value::as_str)
        .ok_or_else(denied)?;
    if link_key != format!("oauth:{}", completion.provider_id)
        || user
            .provider_ids
            .as_ref()
            .and_then(|v| v.get(link_key))
            .and_then(Value::as_str)
            != Some(subject)
    {
        return Err(denied());
    }
    if let Some(changed) = user
        .last_change_password_time
        .as_deref()
        .filter(|v| !v.is_empty())
    {
        let changed = DateTime::parse_from_rfc3339(changed).map_err(|_| denied())?;
        if completion.created_at <= changed {
            return Err(denied());
        }
    }
    let cutoff: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT invalid_before FROM user_session_epochs WHERE user_id=$1")
            .bind(&user.id)
            .fetch_optional(&mut *conn)
            .await?;
    if cutoff.is_some_and(|cutoff| completion.created_at <= cutoff) {
        return Err(denied());
    }
    let records: Vec<UserMfa> = sqlx::query_as(
        "SELECT * FROM user_mfa WHERE user_id=$1 AND is_enabled=true ORDER BY id FOR UPDATE",
    )
    .bind(&user.id)
    .fetch_all(&mut *conn)
    .await?;
    let mut methods = Vec::new();
    if (user.mfa_enabled && user.totp_secret.as_ref().is_some_and(|s| !s.is_empty()))
        || records
            .iter()
            .any(|r| matches!(r.mfa_type.as_str(), "totp" | "app"))
    {
        methods.push("app".to_string());
    }
    if user.mfa_phone_enabled {
        methods.push("sms".to_string());
    }
    if user.mfa_email_enabled {
        methods.push("email".to_string());
    }
    if records.iter().any(|r| {
        r.recovery_codes
            .as_ref()
            .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok())
            .is_some_and(|v| !v.is_empty())
    }) {
        methods.push("recovery".to_string());
    }
    Ok((app, user, records, methods))
}
async fn verify_factor(
    conn: &mut PgConnection,
    user: &User,
    records: &[UserMfa],
    proof: &str,
    method: &str,
    code: &str,
) -> AppResult<bool> {
    if code.is_empty() || code.len() > 256 {
        return Ok(false);
    }
    match method {
        "app" | "totp" => {
            let secret = records
                .iter()
                .find(|r| matches!(r.mfa_type.as_str(), "app" | "totp"))
                .and_then(|r| r.secret.as_deref())
                .or_else(|| {
                    user.mfa_enabled
                        .then_some(user.totp_secret.as_deref())
                        .flatten()
                });
            match secret {
                Some(secret) => MfaService::consume_totp(conn, &user.id, secret, code).await,
                None => Ok(false),
            }
        }
        "recovery" => {
            for record in records {
                if let Some(mut codes) = record
                    .recovery_codes
                    .as_ref()
                    .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok())
                {
                    if let Some(index) = codes.iter().position(|v| v == code) {
                        codes.remove(index);
                        sqlx::query(
                            "UPDATE user_mfa SET recovery_codes=$1,updated_at=NOW() WHERE id=$2",
                        )
                        .bind(
                            serde_json::to_string(&codes)
                                .map_err(|e| AppError::Internal(e.to_string()))?,
                        )
                        .bind(&record.id)
                        .execute(&mut *conn)
                        .await?;
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        "email" | "sms" => {
            let receiver = if method == "email" && user.mfa_email_enabled {
                user.email.as_deref()
            } else if method == "sms" && user.mfa_phone_enabled {
                user.phone.as_deref()
            } else {
                None
            };
            let Some(receiver) = receiver else {
                return Ok(false);
            };
            let result=sqlx::query("UPDATE verifications SET is_used=true WHERE id=(SELECT id FROM verifications WHERE owner=$1 AND user_id=$2 AND receiver=$3 AND code=$4 AND type=$5 AND name=$6 AND NOT is_used AND created_at>NOW()-INTERVAL '5 minutes' ORDER BY created_at DESC LIMIT 1) AND NOT is_used")
                .bind(&user.owner).bind(&user.id).bind(receiver).bind(code).bind(if method=="email"{"social:email"}else{"social:phone"}).bind(state::proof_hash(proof)).execute(&mut *conn).await?;
            Ok(result.rows_affected() == 1)
        }
        _ => Ok(false),
    }
}
#[endpoint(tags("Social Login"))]
pub async fn consume_social_session(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<Value>> {
    let Some(secret) = request_proof(req)? else {
        return Ok(Json(json!({"pending":false})));
    };
    let input = payload(req).await?;
    let pool = pg_pool(depot)?;
    let mut tx = pool.begin().await?;
    let completion = state::load_completion_for_update(&mut tx, &secret).await?;
    let (_, user, records, methods) = policy(&mut tx, &completion).await?;
    if user.mfa_enabled || !methods.is_empty() || !records.is_empty() {
        let code = input.passcode.as_deref().unwrap_or_default().trim();
        if code.is_empty() {
            tx.commit().await?;
            res.headers_mut()
                .insert("cache-control", "no-store".parse().unwrap());
            return Ok(Json(
                json!({"mfa_required":true,"mfa_types":methods,"token":"","expires_in":0}),
            ));
        }
        let method = input
            .mfa_type
            .as_deref()
            .or(user.preferred_mfa_type.as_deref())
            .unwrap_or("app");
        let normalized = if method == "totp" { "app" } else { method };
        let valid = methods.iter().any(|m| m == normalized)
            && verify_factor(&mut tx, &user, &records, &secret, method, code).await?;
        if !valid {
            state::record_failure_conn(&mut tx, &secret).await?;
            sqlx::query("UPDATE users SET signin_wrong_times=signin_wrong_times+1,last_signin_wrong_time=$1 WHERE id=$2")
                .bind(Utc::now().to_rfc3339()).bind(&user.id).execute(&mut *tx).await?;
            tx.commit().await?;
            return Err(AppError::Authentication(
                "Invalid second-factor proof; restart sign-in after five attempts".into(),
            ));
        }
    }
    let diesel = depot
        .obtain::<DieselPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let auth = AuthService::new(UserService::new(diesel));
    let response: UserResponse = user.clone().into();
    let mut claims = auth.claims_for_user(&response);
    claims.issued_at_ms = Some(completion.created_at.timestamp_millis());
    claims.iat = completion.created_at.timestamp();
    let token = auth.generate_token_from_claims(&claims)?;
    state::consume_completion_conn(&mut tx, &secret).await?;
    sqlx::query("UPDATE users SET signin_wrong_times=0,last_signin_wrong_time=NULL,last_signin_time=$1,updated_at=NOW() WHERE id=$2")
        .bind(Utc::now().to_rfc3339()).bind(&user.id).execute(&mut *tx).await?;
    tx.commit().await?;
    set_cookie(
        res,
        SESSION_COOKIE,
        "",
        0,
        public_origin()?.starts_with("https://"),
    );
    Ok(Json(
        json!({"token":token,"token_type":"Bearer","expires_in":AppConfig::get().jwt.expiration_hours*3600,"user":response}),
    ))
}

#[endpoint(tags("Social Login"))]
pub async fn send_social_mfa_code(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<Value>> {
    let secret = request_proof(req)?.ok_or_else(denied)?;
    let input = payload(req).await?;
    let method = input.mfa_type.as_deref().unwrap_or_default();
    if !matches!(method, "email" | "sms") {
        return Err(AppError::Validation(
            "Select an enrolled email or SMS factor".into(),
        ));
    }
    let pool = pg_pool(depot)?;
    let initial = state::load_completion(&pool, &secret).await?;
    let diesel = depot
        .obtain::<DieselPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let dispatch = ProviderDispatchService::new(pool.clone()).with_diesel_pool(diesel);
    let resolved = dispatch
        .resolve_provider(
            if method == "email" { "Email" } else { "SMS" },
            None,
            Some(&initial.application_id),
            Some("mfa"),
            None,
        )
        .await?;
    let mut tx = pool.begin().await?;
    let completion = state::load_completion_for_update(&mut tx, &secret).await?;
    let (app, user, _, methods) = policy(&mut tx, &completion).await?;
    if !methods.iter().any(|m| m == method) {
        return Err(denied());
    }
    let receiver = if method == "email" {
        user.email.as_deref()
    } else {
        user.phone.as_deref()
    }
    .filter(|v| !v.is_empty())
    .ok_or_else(denied)?
    .to_string();
    let recent: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM verifications WHERE user_id=$1 AND created_at>NOW()-INTERVAL '60 seconds')")
        .bind(&user.id).fetch_one(&mut *tx).await?;
    if recent {
        return Err(AppError::Validation(
            "Wait before requesting another verification code".into(),
        ));
    }
    let provider: Provider = sqlx::query_as("SELECT * FROM providers WHERE id=$1 AND category=$2")
        .bind(&resolved.provider.id)
        .bind(if method == "email" { "Email" } else { "SMS" })
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(denied)?;
    let full_name = format!("{}/{}", provider.owner, provider.name);
    if !configured_provider(&app, &provider, false) {
        return Err(AppError::Authorization(
            "MFA delivery provider is not configured for this application".into(),
        ));
    }
    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("UPDATE verifications SET is_used=true WHERE user_id=$1 AND type=$2 AND name=$3")
        .bind(&user.id)
        .bind(if method == "email" {
            "social:email"
        } else {
            "social:phone"
        })
        .bind(state::proof_hash(&secret))
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO verifications(id,owner,name,type,user_id,provider,receiver,code,is_used) VALUES($1,$2,$3,$4,$5,$6,$7,$8,false)")
        .bind(&id).bind(&user.owner).bind(state::proof_hash(&secret)).bind(if method=="email"{"social:email"}else{"social:phone"}).bind(&user.id).bind(&full_name).bind(&receiver).bind(&code).execute(&mut *tx).await?;
    tx.commit().await?;
    let message =
        format!("Your social sign-in verification code is {code}. It expires in five minutes.");
    let delivery = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        if method == "email" {
            dispatch
                .send_email_with_provider(
                    &provider,
                    &[receiver],
                    "Sign-in verification",
                    &message,
                    None,
                )
                .await
                .map(|_| ())
        } else {
            dispatch
                .send_sms_with_provider(&provider, &[receiver], &message)
                .await
                .map(|_| ())
        }
    })
    .await;
    if !matches!(delivery, Ok(Ok(()))) {
        sqlx::query("UPDATE verifications SET is_used=true WHERE id=$1")
            .bind(id)
            .execute(&pool)
            .await?;
        return Err(AppError::Internal(
            "Verification delivery failed; request a new code".into(),
        ));
    }
    res.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    Ok(Json(
        json!({"status":"ok","msg":"Verification code sent to your enrolled contact"}),
    ))
}

fn configured_provider(app: &Application, provider: &Provider, signin: bool) -> bool {
    app.providers
        .as_ref()
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
                let rule = item
                    .get("rule")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim();
                let matches = name == format!("{}/{}", provider.owner, provider.name)
                    || (name == provider.name && provider.owner == app.owner);
                matches
                    && if signin {
                        item.get("canSignIn")
                            .and_then(Value::as_bool)
                            .unwrap_or(true)
                    } else {
                        // Do not let a default or a signup/reset-only provider send MFA secrets.
                        rule.is_empty()
                            || rule.eq_ignore_ascii_case("all")
                            || rule.eq_ignore_ascii_case("mfa")
                    }
            })
        })
}

#[endpoint(tags("Social Login"))]
pub async fn cancel_social_session(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<Value>> {
    if let Some(secret) = request_proof(req)? {
        sqlx::query("DELETE FROM social_oauth_completions WHERE secret_hash=$1")
            .bind(state::proof_hash(&secret))
            .execute(&pg_pool(depot)?)
            .await?;
    }
    set_cookie(
        res,
        SESSION_COOKIE,
        "",
        0,
        public_origin()?.starts_with("https://"),
    );
    Ok(Json(json!({"pending":false})))
}
