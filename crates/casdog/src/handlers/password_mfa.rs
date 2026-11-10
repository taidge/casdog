//! Password-first, browser-bound MFA. Account, factor and completion consumption
//! share one PostgreSQL transaction; delivery never accepts a receiver from callers.
use super::social_login::{application_conn, cookie, pg_pool, public_origin, set_cookie};
use crate::{
    config::AppConfig,
    diesel_pool::DieselPool,
    error::{AppError, AppResult},
    models::{Application, Organization, Provider, User, UserResponse},
    services::{
        AuthService, CheckService, ProviderDispatchService, UserService,
        auth_service::LoginRequest,
        mfa_service::{MfaService, UserMfa},
        social_state_service::proof_hash,
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::{Rng, RngCore, rngs::OsRng};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgConnection;

const COOKIE: &str = "casdog_password_mfa";
#[derive(sqlx::FromRow)]
struct Challenge {
    secret_hash: String,
    user_id: String,
    organization: String,
    application_id: Option<String>,
    credential_stamp: String,
    context: Value,
    attempts: i32,
    code_hash: Option<String>,
    code_method: Option<String>,
    receiver: Option<String>,
    sent_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}
#[derive(Default, Deserialize)]
struct Factor {
    #[serde(alias = "mfaType")]
    mfa_type: Option<String>,
    passcode: Option<String>,
}
fn denied() -> AppError {
    AppError::Authentication("Invalid or expired password MFA challenge".into())
}
fn nonce() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn stamp(user: &User) -> String {
    proof_hash(&format!(
        "{}\0{}\0{}",
        user.password_hash,
        user.password_type.as_deref().unwrap_or_default(),
        user.password_salt.as_deref().unwrap_or_default()
    ))
}
fn origin(req: &Request) -> AppResult<()> {
    if req.header::<String>("origin").as_deref() != Some(public_origin()?.as_str()) {
        return Err(denied());
    }
    Ok(())
}
fn proof(req: &Request) -> AppResult<String> {
    origin(req)?;
    let secret = cookie(req, COOKIE).ok_or_else(denied)?;
    if secret.len() != 43 {
        return Err(denied());
    }
    Ok(secret)
}
async fn input(req: &mut Request) -> AppResult<Factor> {
    let bytes = req.payload().await.map_err(|_| denied())?;
    if bytes.is_empty() {
        return Ok(Factor::default());
    }
    serde_json::from_slice(bytes).map_err(|_| AppError::Validation("Invalid factor request".into()))
}
async fn load(conn: &mut PgConnection, secret: &str) -> AppResult<Challenge> {
    sqlx::query_as("SELECT * FROM password_mfa_challenges WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND attempts<5 FOR UPDATE")
        .bind(proof_hash(secret)).fetch_optional(conn).await?.ok_or_else(denied)
}
async fn policy(
    conn: &mut PgConnection,
    c: &Challenge,
) -> AppResult<(
    User,
    Organization,
    Option<Application>,
    Vec<UserMfa>,
    Vec<String>,
)> {
    let user:User=sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE")
        .bind(&c.user_id).bind(&c.organization).fetch_optional(&mut *conn).await?.ok_or_else(denied)?;
    let live: bool = sqlx::query_scalar("SELECT $1::timestamptz>clock_timestamp()")
        .bind(c.expires_at)
        .fetch_one(&mut *conn)
        .await?;
    if !live || c.attempts >= 5 || stamp(&user) != c.credential_stamp {
        return Err(denied());
    }
    let org: Organization = sqlx::query_as(
        "SELECT * FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin",
    )
    .bind(&user.owner)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(denied)?;
    if c.context.get("master_stamp").and_then(Value::as_str)
        != Some(proof_hash(org.master_password.as_deref().unwrap_or_default()).as_str())
    {
        return Err(denied());
    }
    if let Some(changed) = user
        .last_change_password_time
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        if c.created_at <= DateTime::parse_from_rfc3339(changed).map_err(|_| denied())? {
            return Err(denied());
        }
    }
    let invalid_before: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT invalid_before FROM user_session_epochs WHERE user_id=$1")
            .bind(&user.id)
            .fetch_optional(&mut *conn)
            .await?;
    if invalid_before.is_some_and(|t| c.created_at <= t) {
        return Err(denied());
    }
    CheckService::check_signin_lockout(
        user.signin_wrong_times,
        user.last_signin_wrong_time.as_deref(),
        None,
        None,
    )?;
    let app = if let Some(id) = &c.application_id {
        let app = application_conn(conn, id).await?;
        if app.organization != user.owner || !app.enable_password {
            return Err(denied());
        }
        CheckService::check_login_permission_conn(conn, &user.id, &app.id).await?;
        Some(app)
    } else {
        None
    };
    let factors: Vec<UserMfa> = sqlx::query_as(
        "SELECT * FROM user_mfa WHERE user_id=$1 AND is_enabled ORDER BY id FOR UPDATE",
    )
    .bind(&user.id)
    .fetch_all(&mut *conn)
    .await?;
    let mut methods = Vec::new();
    if user.mfa_enabled && user.totp_secret.as_ref().is_some_and(|s| !s.is_empty())
        || factors
            .iter()
            .any(|f| matches!(f.mfa_type.as_str(), "app" | "totp"))
    {
        methods.push("app".to_string());
    }
    if user.mfa_email_enabled {
        methods.push("email".to_string());
    }
    if user.mfa_phone_enabled {
        methods.push("sms".to_string());
    }
    if factors.iter().any(|f| {
        f.recovery_codes
            .as_ref()
            .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok())
            .is_some_and(|v| !v.is_empty())
    }) {
        methods.push("recovery".to_string());
    }
    Ok((user, org, app, factors, methods))
}

/// Initial password login. The service verifies the password before any browser
/// proof exists; the response never contains the proof cookie's raw secret.
#[endpoint(tags("Authentication"))]
pub async fn login(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<Value>> {
    let mut request: LoginRequest = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("Invalid login request".into()))?;
    let pg = pg_pool(depot)?;
    let before: Option<User> =
        sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND name=$2 AND NOT is_deleted")
            .bind(&request.owner)
            .bind(&request.name)
            .fetch_optional(&pg)
            .await?;
    let issued: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pg)
        .await?;
    let org_master: Option<String> = sqlx::query_scalar(
        "SELECT master_password FROM organizations WHERE name=$1 AND NOT is_deleted",
    )
    .bind(&request.owner)
    .fetch_optional(&pg)
    .await?
    .flatten();
    let application = request.application.as_ref().map(|reference| {
        if reference.contains('/') {
            reference.clone()
        } else {
            format!("{}/{}", request.owner, reference)
        }
    });
    let client_id = request.client_id.clone();
    let context = json!({"response_type":request.response_type,"redirect_uri":request.redirect_uri,"scope":request.scope,"state":request.state,"nonce":request.nonce,"code_challenge":request.code_challenge,"code_challenge_method":request.code_challenge_method,"master_stamp":proof_hash(org_master.as_deref().unwrap_or_default()),"client_id":client_id});
    request.passcode = None;
    let diesel = depot
        .obtain::<DieselPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let auth = AuthService::new(UserService::new(diesel.clone())).with_pg_pool(pg.clone());
    let result = auth.login(&diesel, request).await?;
    if result.mfa_required != Some(true) {
        set_cookie(res, COOKIE, "", 0, public_origin()?.starts_with("https://"));
        return Ok(Json(
            serde_json::to_value(result).map_err(|e| AppError::Internal(e.to_string()))?,
        ));
    }
    origin(req)?;
    let before = before.ok_or_else(denied)?;
    let mut tx = pg.begin().await?;
    let app_id: Option<String> = if let Some(client) = client_id {
        let id: String =
            sqlx::query_scalar("SELECT id FROM applications WHERE client_id=$1 AND NOT is_deleted")
                .bind(client)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(denied)?;
        if let Some(reference) = application {
            if application_conn(&mut tx, &reference).await?.id != id {
                return Err(denied());
            }
        }
        Some(id)
    } else if let Some(reference) = application {
        Some(application_conn(&mut tx, &reference).await?.id)
    } else {
        None
    };
    let secret = nonce();
    let hash = proof_hash(&secret);
    let c = Challenge {
        secret_hash: hash.clone(),
        user_id: before.id.clone(),
        organization: before.owner.clone(),
        application_id: app_id,
        credential_stamp: stamp(&before),
        context,
        attempts: 0,
        code_hash: None,
        code_method: None,
        receiver: None,
        sent_at: None,
        created_at: issued,
        expires_at: issued + chrono::Duration::minutes(5),
    };
    let (_, _, _, _, methods) = policy(&mut tx, &c).await?;
    // Account lock serializes creation/rate checks across application instances.
    sqlx::query(
        "DELETE FROM password_mfa_challenges WHERE secret_hash IN (SELECT secret_hash FROM password_mfa_challenges WHERE expires_at<clock_timestamp()-INTERVAL '1 hour' LIMIT 100 FOR UPDATE SKIP LOCKED)",
    )
    .execute(&mut *tx)
    .await?;
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM password_mfa_challenges WHERE user_id=$1 AND created_at>clock_timestamp()-INTERVAL '1 minute'")
        .bind(&before.id).fetch_one(&mut *tx).await?;
    if count >= 5 {
        return Err(AppError::Validation(
            "Wait before starting another MFA challenge".into(),
        ));
    }
    sqlx::query("INSERT INTO password_mfa_challenges(secret_hash,user_id,organization,application_id,credential_stamp,context,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(&hash).bind(&c.user_id).bind(&c.organization).bind(&c.application_id).bind(&c.credential_stamp).bind(&c.context).bind(c.created_at).bind(c.expires_at).execute(&mut *tx).await?;
    tx.commit().await?;
    set_cookie(
        res,
        COOKIE,
        &secret,
        300,
        public_origin()?.starts_with("https://"),
    );
    Ok(Json(
        json!({"mfa_required":true,"mfa_types":methods,"token":"","expires_in":0}),
    ))
}
async fn verify(
    conn: &mut PgConnection,
    c: &Challenge,
    user: &User,
    factors: &[UserMfa],
    secret: &str,
    method: &str,
    code: &str,
) -> AppResult<bool> {
    if code.is_empty() || code.len() > 256 {
        return Ok(false);
    }
    match method {
        "app" | "totp" => {
            let secret = factors
                .iter()
                .find(|f| matches!(f.mfa_type.as_str(), "app" | "totp"))
                .and_then(|f| f.secret.as_deref())
                .or_else(|| {
                    if user.mfa_enabled {
                        user.totp_secret.as_deref()
                    } else {
                        None
                    }
                });
            match secret {
                Some(s) => MfaService::verify_totp(s, code),
                None => Ok(false),
            }
        }
        "recovery" => {
            for factor in factors {
                if let Some(mut codes) = factor
                    .recovery_codes
                    .as_ref()
                    .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok())
                {
                    if let Some(i) = codes.iter().position(|v| v == code) {
                        codes.remove(i);
                        sqlx::query(
                            "UPDATE user_mfa SET recovery_codes=$1,updated_at=NOW() WHERE id=$2",
                        )
                        .bind(json!(codes).to_string())
                        .bind(&factor.id)
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
            Ok(receiver.is_some()
                && receiver == c.receiver.as_deref()
                && c.code_method.as_deref() == Some(method)
                && c.code_hash.as_deref() == Some(proof_hash(&format!("{secret}:{code}")).as_str())
                && c.sent_at
                    .is_some_and(|t| Utc::now() - t < chrono::Duration::minutes(5)))
        }
        _ => Ok(false),
    }
}
#[endpoint(tags("Authentication"))]
pub async fn consume_password_session(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<Value>> {
    if cookie(req, COOKIE).is_none() {
        return Ok(Json(json!({"pending":false})));
    }
    let secret = proof(req)?;
    let input = input(req).await?;
    let pg = pg_pool(depot)?;
    let mut tx = pg.begin().await?;
    let c = load(&mut tx, &secret).await?;
    let (user, org, app, factors, methods) = policy(&mut tx, &c).await?;
    let code = input.passcode.as_deref().unwrap_or_default().trim();
    if code.is_empty() {
        tx.commit().await?;
        res.headers_mut()
            .insert("cache-control", "no-store".parse().unwrap());
        return Ok(Json(
            json!({"mfa_required":true,"mfa_types":methods,"token":"","expires_in":0}),
        ));
    }
    let method = input.mfa_type.as_deref().unwrap_or("app");
    let normalized = if method == "totp" { "app" } else { method };
    if !methods.iter().any(|m| m == normalized)
        || !verify(&mut tx, &c, &user, &factors, &secret, method, code).await?
    {
        sqlx::query("UPDATE password_mfa_challenges SET attempts=attempts+1 WHERE secret_hash=$1 AND attempts<5").bind(&c.secret_hash).execute(&mut *tx).await?;
        sqlx::query("UPDATE users SET signin_wrong_times=signin_wrong_times+1,last_signin_wrong_time=$1 WHERE id=$2").bind(Utc::now().to_rfc3339()).bind(&user.id).execute(&mut *tx).await?;
        tx.commit().await?;
        return Err(AppError::Authentication(
            "Invalid second-factor proof".into(),
        ));
    }
    let expired = user.need_update_password
        || CheckService::check_password_expired(
            user.last_change_password_time.as_deref(),
            (org.password_expire_days > 0).then_some(org.password_expire_days),
        )?;
    let diesel = depot
        .obtain::<DieselPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let auth = AuthService::new(UserService::new(diesel));
    let response: UserResponse = user.clone().into();
    let mut claims = auth.claims_for_user(&response);
    claims.issued_at_ms = Some(c.created_at.timestamp_millis());
    claims.iat = c.created_at.timestamp();
    let token = auth.generate_token_from_claims(&claims)?;
    let mut result = json!({"token":token,"token_type":"Bearer","expires_in":AppConfig::get().jwt.expiration_hours*3600,"user":response,"password_expired":expired});
    if !expired && c.context["response_type"].as_str() == Some("code") {
        let app = app.as_ref().ok_or_else(denied)?;
        let redirect = c.context["redirect_uri"].as_str().ok_or_else(denied)?;
        if c.context["client_id"].as_str() != Some(app.client_id.as_str()) {
            return Err(denied());
        }
        if app.grant_types.as_ref().is_some_and(|v| {
            !v.as_array().is_some_and(|types| {
                types
                    .iter()
                    .any(|g| g.as_str() == Some("authorization_code"))
            })
        }) {
            return Err(AppError::Authorization(
                "Authorization code grant is disabled".into(),
            ));
        }
        if !app
            .redirect_uris
            .split(|ch: char| ch == ',' || ch.is_whitespace())
            .any(|uri| !uri.is_empty() && uri == redirect)
        {
            return Err(denied());
        }
        let pkce = c.context["code_challenge"].as_str();
        let pkce_method = c.context["code_challenge_method"].as_str();
        if pkce.is_some() && !matches!(pkce_method.unwrap_or("plain"), "plain" | "S256") {
            return Err(denied());
        }
        if app.client_secret.is_empty() && pkce.is_none() {
            return Err(AppError::Validation("Public clients require PKCE".into()));
        }
        if let Some(challenge) = pkce {
            let valid = if pkce_method.unwrap_or("plain") == "S256" {
                challenge.len() == 43
                    && challenge
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            } else {
                (43..=128).contains(&challenge.len())
                    && challenge.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
                    })
            };
            if !valid {
                return Err(AppError::Validation("Invalid PKCE challenge".into()));
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let auth_code = nonce();
        sqlx::query("INSERT INTO tokens(id,owner,name,application,organization,user_id,code,access_token,expires_in,scope,token_type,code_challenge,code_challenge_method,code_is_used,code_expire_in,nonce,redirect_uri) VALUES($1,$2,$3,$4,$5,$6,$7,'',0,$8,'Bearer',$9,$10,false,300,$11,$12)")
            .bind(&id).bind(&app.owner).bind(format!("code_{id}")).bind(&app.name).bind(&app.organization).bind(&user.id).bind(&auth_code).bind(c.context["scope"].as_str().unwrap_or("openid profile")).bind(pkce).bind(pkce_method).bind(c.context["nonce"].as_str()).bind(redirect).execute(&mut *tx).await?;
        result["code"] = json!(auth_code);
        result["redirect_uri"] = json!(redirect);
        result["state"] = c.context["state"].clone();
    }
    let consumed=sqlx::query("DELETE FROM password_mfa_challenges WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND attempts<5").bind(&c.secret_hash).execute(&mut *tx).await?;
    if consumed.rows_affected() != 1 {
        return Err(denied());
    }
    sqlx::query("UPDATE users SET signin_wrong_times=0,last_signin_wrong_time=NULL,last_signin_time=$1,updated_at=NOW() WHERE id=$2").bind(Utc::now().to_rfc3339()).bind(&user.id).execute(&mut *tx).await?;
    tx.commit().await?;
    set_cookie(res, COOKIE, "", 0, public_origin()?.starts_with("https://"));
    Ok(Json(result))
}
async fn delivery_provider(
    conn: &mut PgConnection,
    user: &User,
    app: Option<&Application>,
    category: &str,
) -> AppResult<Provider> {
    if let Some(app) = app {
        for item in app
            .providers
            .as_ref()
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(reference) = item["name"].as_str() else {
                continue;
            };
            let rule = item["rule"].as_str().unwrap_or_default().trim();
            if !rule.is_empty()
                && !rule.eq_ignore_ascii_case("all")
                && !rule.eq_ignore_ascii_case("mfa")
            {
                continue;
            }
            if category == "SMS"
                && item["countryCodes"].as_array().is_some_and(|codes| {
                    !codes.is_empty()
                        && !codes
                            .iter()
                            .any(|code| code.as_str() == user.country_code.as_deref())
                })
            {
                continue;
            }
            let provider:Option<Provider>=sqlx::query_as("SELECT * FROM providers WHERE category=$1 AND (owner||'/'||name=$2 OR (owner=$3 AND name=$2))")
                .bind(category).bind(reference).bind(&app.owner).fetch_optional(&mut *conn).await?;
            if let Some(provider) = provider {
                return Ok(provider);
            }
        }
    } else {
        // No application context means only an unambiguous provider owned by
        // this organization is eligible; never fall back to another tenant.
        let mut providers: Vec<Provider> = sqlx::query_as(
            "SELECT * FROM providers WHERE owner=$1 AND category=$2 ORDER BY name LIMIT 2",
        )
        .bind(&user.owner)
        .bind(category)
        .fetch_all(&mut *conn)
        .await?;
        if providers.len() == 1 {
            return Ok(providers.remove(0));
        }
    }
    Err(AppError::Authorization(
        "Configure an MFA delivery provider for this application".into(),
    ))
}
#[endpoint(tags("Authentication"))]
pub async fn send_password_mfa_code(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<Value>> {
    let secret = proof(req)?;
    let input = input(req).await?;
    let method = input.mfa_type.as_deref().unwrap_or_default();
    if !matches!(method, "email" | "sms") {
        return Err(AppError::Validation(
            "Select an enrolled email or SMS factor".into(),
        ));
    }
    let pg = pg_pool(depot)?;
    let mut tx = pg.begin().await?;
    let c = load(&mut tx, &secret).await?;
    let (user, _, app, _, methods) = policy(&mut tx, &c).await?;
    if !methods.iter().any(|m| m == method) {
        return Err(denied());
    }
    let receiver = if method == "email" {
        user.email.as_deref()
    } else {
        user.phone.as_deref()
    }
    .filter(|s| !s.is_empty())
    .ok_or_else(denied)?
    .to_owned();
    let recent:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM password_mfa_challenges WHERE user_id=$1 AND sent_at>clock_timestamp()-INTERVAL '60 seconds')")
        .bind(&user.id).fetch_one(&mut *tx).await?;
    if recent {
        return Err(AppError::Validation(
            "Wait before requesting another verification code".into(),
        ));
    }
    let provider = delivery_provider(
        &mut tx,
        &user,
        app.as_ref(),
        if method == "email" { "Email" } else { "SMS" },
    )
    .await?;
    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
    let code_hash = proof_hash(&format!("{secret}:{code}"));
    let updated=sqlx::query("UPDATE password_mfa_challenges SET code_hash=$1,code_method=$2,receiver=$3,sent_at=clock_timestamp() WHERE secret_hash=$4 AND expires_at>clock_timestamp() AND attempts<5")
        .bind(&code_hash).bind(method).bind(&receiver).bind(&c.secret_hash).execute(&mut *tx).await?;
    if updated.rows_affected() != 1 {
        return Err(denied());
    }
    tx.commit().await?;
    let dispatch = ProviderDispatchService::new(pg.clone());
    let message = format!("Your sign-in verification code is {code}. It expires in five minutes.");
    let sent = tokio::time::timeout(std::time::Duration::from_secs(20), async {
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
    if !matches!(sent, Ok(Ok(()))) {
        sqlx::query("UPDATE password_mfa_challenges SET code_hash=NULL WHERE secret_hash=$1 AND code_hash=$2").bind(&c.secret_hash).bind(code_hash).execute(&pg).await?;
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
#[endpoint(tags("Authentication"))]
pub async fn cancel_password_session(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<Value>> {
    let secret = proof(req)?;
    sqlx::query("DELETE FROM password_mfa_challenges WHERE secret_hash=$1")
        .bind(proof_hash(&secret))
        .execute(&pg_pool(depot)?)
        .await?;
    set_cookie(res, COOKIE, "", 0, public_origin()?.starts_with("https://"));
    Ok(Json(json!({"pending":false})))
}
