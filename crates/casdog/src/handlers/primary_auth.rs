//! Browser-bound email/SMS and directory first factors. These proofs never use
//! the generic verification, account recovery or second-factor code stores.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::{Rng, RngCore, rngs::OsRng};
use salvo::prelude::*;
use serde_json::{Value, json};
use sqlx::{PgConnection, Postgres, Transaction};

use super::social_login::{application_conn, cookie, pg_pool, public_origin, set_cookie};
use crate::{
    error::{AppError, AppResult},
    models::{Application, Organization, User},
    services::{
        ProviderDispatchService, auth_service::LoginRequest, ldap_service::LdapService,
        primary_auth_service::PrimaryAuthService as Policy, social_state_service::proof_hash,
    },
};

const COOKIE: &str = "casdog_primary_auth";
fn primary_cookie(res: &mut Response, value: &str, seconds: u32, secure: bool) {
    // Completion is /api/login, outside the narrower /api/auth MFA cookie path.
    res.headers_mut().append(
        "set-cookie",
        format!(
            "{COOKIE}={value}; Path=/api; HttpOnly; SameSite=Lax; Max-Age={seconds}{}",
            if secure { "; Secure" } else { "" }
        )
        .parse()
        .unwrap(),
    );
}
#[derive(sqlx::FromRow)]
struct CodeProof {
    secret_hash: String,
    user_id: String,
    organization: String,
    application_id: String,
    credential_stamp: String,
    login_identifier: String,
    method: String,
    receiver: String,
    code_hash: Option<String>,
    context: Value,
    attempts: i32,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}
fn nonce() -> String {
    let mut value = [0u8; 32];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}
fn origin(req: &Request) -> AppResult<String> {
    let expected = public_origin()?;
    if req.header::<String>("origin").as_deref() != Some(expected.as_str()) {
        return Err(Policy::denied());
    }
    Ok(expected)
}
async fn application(conn: &mut PgConnection, input: &LoginRequest) -> AppResult<Application> {
    let app = if let Some(client) = input.client_id.as_deref().filter(|s| !s.is_empty()) {
        let app: Application =
            sqlx::query_as("SELECT * FROM applications WHERE client_id=$1 AND NOT is_deleted")
                .bind(client)
                .fetch_optional(&mut *conn)
                .await?
                .ok_or_else(Policy::denied)?;
        if let Some(reference) = input.application.as_deref().filter(|s| !s.is_empty()) {
            let reference = if reference.contains('/') {
                reference.to_owned()
            } else {
                format!("{}/{reference}", input.owner)
            };
            if application_conn(conn, &reference).await?.id != app.id {
                return Err(Policy::denied());
            }
        }
        app
    } else {
        let reference = input
            .application
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(Policy::denied)?;
        // Preserve explicit owner/name and opaque IDs, while resolving local bare names.
        let app:Option<Application>=sqlx::query_as("SELECT * FROM applications WHERE NOT is_deleted AND organization=$1 AND (id=$2 OR owner||'/'||name=$2 OR (owner=$1 AND name=$2) OR (owner='admin' AND name=$2))")
            .bind(&input.owner).bind(reference).fetch_optional(&mut *conn).await?;
        app.ok_or_else(Policy::denied)?
    };
    if app.organization != input.owner {
        return Err(Policy::denied());
    }
    Ok(app)
}
fn context(input: &LoginRequest, org: &Organization) -> Value {
    json!({"response_type":input.response_type,"redirect_uri":input.redirect_uri,
        "scope":input.scope,"state":input.state,"nonce":input.nonce,
        "code_challenge":input.code_challenge,"code_challenge_method":input.code_challenge_method,
        "client_id":input.client_id,"master_stamp":proof_hash(org.master_password.as_deref().unwrap_or_default())})
}
async fn fail(conn: &mut PgConnection, user: &str, proof: Option<&str>) -> AppResult<()> {
    if let Some(hash) = proof {
        sqlx::query("UPDATE primary_auth_challenges SET attempts=attempts+1 WHERE secret_hash=$1 AND attempts<5")
            .bind(hash).execute(&mut *conn).await?;
    }
    sqlx::query("UPDATE users SET signin_wrong_times=signin_wrong_times+1,last_signin_wrong_time=$1 WHERE id=$2")
        .bind(Utc::now().to_rfc3339()).bind(user).execute(&mut *conn).await?;
    Ok(())
}
async fn complete(
    depot: &Depot,
    tx: &mut Transaction<'_, Postgres>,
    user: &User,
    org: &Organization,
    app: &Application,
    created: DateTime<Utc>,
    context: Value,
) -> AppResult<(Value, Option<String>)> {
    let additional: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_mfa WHERE user_id=$1 AND is_enabled)")
            .bind(&user.id)
            .fetch_one(&mut **tx)
            .await?;
    if user.mfa_enabled || user.mfa_email_enabled || user.mfa_phone_enabled || additional {
        let (secret, methods) = super::password_mfa::create_primary_factor_challenge(
            tx,
            user,
            created,
            Some(app.id.clone()),
            context,
        )
        .await?;
        Ok((
            json!({"mfa_required":true,"mfa_types":methods,"token":"","expires_in":0}),
            Some(secret),
        ))
    } else {
        Ok((
            super::password_mfa::primary_login_result(
                depot,
                tx,
                user,
                org,
                Some(app),
                created,
                &context,
            )
            .await?,
            None,
        ))
    }
}

/// Send a code only to the account's registered channel using its application's
/// configured sign-in provider. Caller-supplied receiver/provider are ignored.
#[handler]
pub async fn start_code(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<Json<Value>> {
    let origin = origin(req)?;
    res.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    let body: Value = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("Invalid code sign-in request".into()))?;
    let mut login_body = body.clone();
    if ["type", "login_type", "signinMethod", "signin_method"]
        .iter()
        .all(|key| login_body.get(*key).is_none())
    {
        login_body["type"] = json!("code");
    }
    let input: LoginRequest = serde_json::from_value(login_body)
        .map_err(|_| AppError::Validation("Invalid code sign-in request".into()))?;
    let method = match body["method"].as_str() {
        Some("email") => "email",
        Some("sms" | "phone") => "sms",
        _ => return Err(AppError::Validation("Select email or sms".into())),
    };
    let factor = format!("code_{method}");
    let pg = pg_pool(depot)?;
    let mut tx = pg.begin().await?;
    let user = Policy::account(&mut tx, &input.owner, &input.name).await?;
    let app = application(&mut tx, &input).await?;
    let org = Policy::policy(&mut tx, &user, &app, &factor).await?;
    let receiver = if method == "email" {
        user.email.as_deref()
    } else {
        user.phone.as_deref()
    }
    .filter(|s| !s.is_empty())
    .ok_or_else(Policy::denied)?
    .to_owned();
    let recent:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM primary_auth_challenges WHERE user_id=$1 AND created_at>clock_timestamp()-INTERVAL '60 seconds')")
        .bind(&user.id).fetch_one(&mut *tx).await?;
    if recent {
        return Err(AppError::Validation(
            "Wait before requesting another sign-in code".into(),
        ));
    }
    let provider = Policy::delivery_provider(&mut tx, &app, &user, method).await?;
    let secret = nonce();
    let hash = proof_hash(&secret);
    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
    let code_hash = proof_hash(&format!("{secret}:{code}"));
    let mut context = context(&input, &org);
    context["primary_factor"] = json!(factor);
    context["primary_receiver"] = json!(receiver);
    sqlx::query("DELETE FROM primary_auth_challenges WHERE secret_hash IN (SELECT secret_hash FROM primary_auth_challenges WHERE expires_at<clock_timestamp()-INTERVAL '1 hour' LIMIT 100 FOR UPDATE SKIP LOCKED)").execute(&mut *tx).await?;
    sqlx::query("INSERT INTO primary_auth_challenges(secret_hash,user_id,organization,application_id,credential_stamp,login_identifier,method,receiver,code_hash,context) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(&hash).bind(&user.id).bind(&user.owner).bind(&app.id).bind(Policy::credential_stamp(&user))
        .bind(&input.name).bind(method).bind(&receiver).bind(&code_hash).bind(context).execute(&mut *tx).await?;
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
        sqlx::query("UPDATE primary_auth_challenges SET code_hash=NULL WHERE secret_hash=$1 AND code_hash=$2")
            .bind(&hash).bind(&code_hash).execute(&pg).await?;
        return Err(AppError::Internal("Sign-in code delivery failed".into()));
    }
    primary_cookie(res, &secret, 300, origin.starts_with("https://"));
    Ok(Json(
        json!({"pending":true,"method":method,"expires_in":300}),
    ))
}

pub(crate) async fn login(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    input: LoginRequest,
) -> AppResult<Json<Value>> {
    let origin = origin(req)?;
    res.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    let pg = pg_pool(depot)?;
    let mut tx = pg.begin().await?;
    let (user, app, org, created, context) = if input.login_type.as_deref() == Some("code") {
        let secret = cookie(req, COOKIE)
            .filter(|s| s.len() == 43)
            .ok_or_else(Policy::denied)?;
        let proof:CodeProof=sqlx::query_as("SELECT * FROM primary_auth_challenges WHERE secret_hash=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp() AND attempts<5 FOR UPDATE")
            .bind(proof_hash(&secret)).fetch_optional(&mut *tx).await?.ok_or_else(Policy::denied)?;
        if input
            .code_method
            .as_deref()
            .is_some_and(|method| method != proof.method)
        {
            return Err(Policy::denied());
        }
        let user:User=sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE")
            .bind(&proof.user_id).bind(&proof.organization).fetch_optional(&mut *tx).await?.ok_or_else(Policy::denied)?;
        if input.owner != proof.organization || input.name != proof.login_identifier {
            return Err(Policy::denied());
        }
        let app = application(&mut tx, &input).await?;
        if app.id != proof.application_id {
            return Err(Policy::denied());
        }
        let factor = format!("code_{}", proof.method);
        let org = Policy::policy(&mut tx, &user, &app, &factor).await?;
        let receiver = if proof.method == "email" {
            user.email.as_deref()
        } else {
            user.phone.as_deref()
        };
        let epoch: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT invalid_before FROM user_session_epochs WHERE user_id=$1")
                .bind(&user.id)
                .fetch_optional(&mut *tx)
                .await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        if now >= proof.expires_at
            || proof.attempts >= 5
            || epoch.is_some_and(|e| proof.created_at <= e)
            || receiver != Some(proof.receiver.as_str())
            || Policy::credential_stamp(&user) != proof.credential_stamp
            || proof.context["master_stamp"].as_str()
                != Some(proof_hash(org.master_password.as_deref().unwrap_or_default()).as_str())
        {
            return Err(Policy::denied());
        }
        let code = input.code.as_deref().unwrap_or_default();
        let expected = proof_hash(&format!("{secret}:{code}"));
        use subtle::ConstantTimeEq;
        let accepted = code.len() == 6
            && code.bytes().all(|b| b.is_ascii_digit())
            && proof
                .code_hash
                .as_deref()
                .is_some_and(|hash| bool::from(hash.as_bytes().ct_eq(expected.as_bytes())));
        if !accepted {
            fail(&mut tx, &user.id, Some(&proof.secret_hash)).await?;
            tx.commit().await?;
            return Err(Policy::denied());
        }
        sqlx::query("UPDATE primary_auth_challenges SET consumed_at=clock_timestamp() WHERE secret_hash=$1 AND consumed_at IS NULL")
            .bind(&proof.secret_hash)
            .execute(&mut *tx)
            .await?;
        (user, app, org, proof.created_at, proof.context)
    } else {
        let user = Policy::account(&mut tx, &input.owner, &input.name).await?;
        let app = application(&mut tx, &input).await?;
        Policy::policy(&mut tx, &user, &app, "ldap").await?;
        let provider = Policy::ldap_provider(&mut tx, &user).await?;
        if input.provider.as_deref().is_some_and(|p| {
            p != provider.id
                && p != provider.name
                && p != format!("{}/{}", provider.owner, provider.name)
        }) {
            return Err(Policy::denied());
        }
        let valid = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            LdapService::authenticate(&provider, &user, &input.password),
        )
        .await;
        match valid {
            Ok(Ok(true)) => (),
            Ok(Ok(false)) | Ok(Err(AppError::Authentication(_))) => {
                fail(&mut tx, &user.id, None).await?;
                tx.commit().await?;
                return Err(Policy::denied());
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(AppError::Internal("LDAP authentication timed out".into())),
        }
        // Directory I/O can outlast an administrator's policy/config change.
        // Re-read policy after the bind before accepting this credential proof.
        let app = application(&mut tx, &input).await?;
        let org = Policy::policy(&mut tx, &user, &app, "ldap").await?;
        let current_provider = Policy::ldap_provider(&mut tx, &user).await?;
        if Policy::ldap_stamp(&current_provider, &user) != Policy::ldap_stamp(&provider, &user) {
            return Err(Policy::denied());
        }
        let created = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let mut context = context(&input, &org);
        context["primary_factor"] = json!("ldap");
        context["ldap_stamp"] = json!(Policy::ldap_stamp(&provider, &user));
        (user, app, org, created, context)
    };
    let (result, proof) = complete(depot, &mut tx, &user, &org, &app, created, context).await?;
    tx.commit().await?;
    primary_cookie(res, "", 0, origin.starts_with("https://"));
    set_cookie(
        res,
        "casdog_password_mfa",
        proof.as_deref().unwrap_or_default(),
        if proof.is_some() { 300 } else { 0 },
        origin.starts_with("https://"),
    );
    Ok(Json(result))
}
