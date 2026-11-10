use crate::diesel_pool::DieselPool;
use crate::models::{Application, User};
use crate::services::ProviderDispatchService;
use rand::Rng;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{
    CaptchaResponse, EmailAndPhoneResponse, GetEmailAndPhoneRequest, ResetEmailOrPhoneRequest,
    SendVerificationCodeRequest, VerificationResponse, VerifyCaptchaRequest, VerifyCodeRequest,
    VerifyCodeResponse,
};
use crate::services::VerificationService;

async fn current_user(depot: &Depot, pool: &Pool<Postgres>) -> AppResult<Option<User>> {
    let Ok(id) = depot.get::<String>("user_id") else {
        return Ok(None);
    };
    let user: User = sqlx::query_as(
        "SELECT * FROM users WHERE id=$1 AND is_deleted=false AND is_forbidden=false",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::Authentication("Account unavailable".into()))?;
    if depot
        .get::<String>("user_owner")
        .is_ok_and(|owner| owner != &user.owner)
    {
        return Err(AppError::Authentication(
            "Account organization changed".into(),
        ));
    }
    Ok(Some(user))
}

fn validate_contact(kind: &str, value: &str) -> AppResult<()> {
    let valid = value.len() <= 254
        && match kind {
            "email" => value.contains('@') && !value.chars().any(char::is_whitespace),
            "phone" => {
                (5..=24).contains(&value.len())
                    && value.chars().all(|ch| ch.is_ascii_digit() || ch == '+')
            }
            _ => false,
        };
    if !valid {
        return Err(AppError::Validation(
            "Invalid contact type or destination".into(),
        ));
    }
    Ok(())
}

fn signup_cookie(req: &Request) -> Option<String> {
    req.headers()
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == "casdog_signup_proof"
                && value.len() == 64
                && value.chars().all(|ch| ch.is_ascii_hexdigit()))
            .then(|| value.to_string())
        })
}

#[endpoint(tags("verification"), summary = "List verifications")]
pub async fn list_verifications(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
    user: QueryParam<String, false>,
) -> AppResult<Json<Vec<VerificationResponse>>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let records = VerificationService::list(&pool, owner.as_deref(), user.as_deref()).await?;
    Ok(Json(records))
}

#[endpoint(tags("verification"), summary = "Get verification by ID")]
pub async fn get_verification(
    depot: &mut Depot,
    id: PathParam<String>,
) -> AppResult<Json<VerificationResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let verification = VerificationService::get_by_id(&pool, &id).await?;
    Ok(Json(verification))
}

#[endpoint(
    tags("verification"),
    summary = "Get verification by ID (query compatibility)"
)]
pub async fn get_verification_by_query(
    depot: &mut Depot,
    id: QueryParam<String, true>,
) -> AppResult<Json<VerificationResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let verification = VerificationService::get_by_id(&pool, id.as_str()).await?;
    Ok(Json(verification))
}

#[endpoint(tags("verification"), summary = "Send verification code")]
pub async fn send_verification_code(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<SendVerificationCodeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let payload = body.into_inner();
    validate_contact(&payload.verification_type, &payload.dest)?;
    let reference = payload
        .application
        .as_deref()
        .ok_or_else(|| AppError::Validation("application is required".into()))?;
    let app: Application = sqlx::query_as("SELECT * FROM applications WHERE is_deleted=false AND (id=$1 OR owner || '/' || name=$1 OR (owner='admin' AND name=$1))")
        .bind(reference).fetch_optional(&pool).await?.ok_or_else(|| AppError::NotFound("Application not found".into()))?;
    let current = current_user(depot, &pool).await?;
    if current
        .as_ref()
        .is_some_and(|user| user.owner != app.organization)
    {
        return Err(AppError::Authorization(
            "Application belongs to another organization".into(),
        ));
    }
    let method = payload.method.as_deref().unwrap_or(if current.is_some() {
        "contact"
    } else {
        "signup"
    });
    let (subject, purpose, browser_nonce) = match method {
        "contact" | "reset-email" | "reset-phone" | "resetEmail" | "resetPhone" => {
            let user = current.ok_or_else(|| {
                AppError::Authentication("Sign in before changing contact information".into())
            })?;
            (
                user.id,
                format!("contact:{}", payload.verification_type),
                None,
            )
        }
        "signup" => {
            if !app.enable_internal_signup {
                return Err(AppError::Authorization("Signup is disabled".into()));
            }
            let nonce = format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            (
                format!("signup:{nonce}"),
                format!("signup:{}", payload.verification_type),
                Some(nonce),
            )
        }
        "mfa" => {
            let users: Vec<User> = sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND is_deleted=false AND is_forbidden=false AND (($2='email' AND email=$3 AND mfa_email_enabled=true) OR ($2='phone' AND phone=$3 AND mfa_phone_enabled=true))")
                .bind(&app.organization).bind(&payload.verification_type).bind(&payload.dest).fetch_all(&pool).await?;
            if users.len() != 1 {
                return Err(AppError::Validation(
                    "No unique enrolled contact available".into(),
                ));
            }
            if current
                .as_ref()
                .is_some_and(|current| current.id != users[0].id)
            {
                return Err(AppError::Authorization(
                    "Cannot send another account's MFA challenge".into(),
                ));
            }
            (users[0].id.clone(), payload.verification_type.clone(), None)
        }
        _ => {
            return Err(AppError::Validation(
                "Unsupported verification purpose".into(),
            ));
        }
    };
    let recent: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM verifications WHERE owner=$1 AND receiver=$2 AND created_at>NOW()-INTERVAL '60 seconds')")
        .bind(&app.organization).bind(&payload.dest).fetch_one(&pool).await?;
    if recent {
        return Err(AppError::Validation(
            "Wait before requesting another verification code".into(),
        ));
    }
    let diesel = depot
        .obtain::<DieselPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let dispatch = ProviderDispatchService::new(pool.clone()).with_diesel_pool(diesel);
    let resolved = dispatch
        .resolve_provider(
            if payload.verification_type == "email" {
                "Email"
            } else {
                "SMS"
            },
            payload.provider.as_deref(),
            Some(reference),
            Some(method),
            payload.country_code.as_deref(),
        )
        .await?;
    let provider_ref = format!("{}/{}", resolved.provider.owner, resolved.provider.name);
    let configured = app
        .providers
        .as_ref()
        .and_then(|v| v.as_array())
        .is_some_and(|items| {
            items.iter().any(|item| {
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                name == provider_ref
                    || (name == resolved.provider.name
                        && (resolved.provider.owner == app.organization
                            || resolved.provider.owner == app.owner))
            })
        });
    if !configured {
        return Err(AppError::Authorization(
            "Delivery provider is not configured for this application".into(),
        ));
    }
    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
    let content = format!("Your {method} verification code is {code}. It expires in 5 minutes.");
    if payload.verification_type == "email" {
        dispatch
            .send_email_with_provider(
                &resolved.provider,
                &[payload.dest.clone()],
                "Verification code",
                &content,
                None,
            )
            .await?;
    } else {
        dispatch
            .send_sms_with_provider(&resolved.provider, &[payload.dest.clone()], &content)
            .await?;
    }
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO verifications(id,owner,name,type,user_id,provider,receiver,code,is_used,remote_addr) VALUES($1,$2,$1,$3,$4,$5,$6,$7,false,$8)")
        .bind(&id).bind(&app.organization).bind(&purpose).bind(&subject).bind(&provider_ref).bind(&payload.dest).bind(&code).bind(req.remote_addr().to_string()).execute(&pool).await?;
    if let Some(nonce) = browser_nonce {
        let secure = crate::config::AppConfig::get()
            .server
            .public_url
            .as_deref()
            .is_some_and(|url| url.starts_with("https://"));
        let header = format!(
            "casdog_signup_proof={nonce}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=300{}",
            if secure { "; Secure" } else { "" }
        );
        res.headers_mut()
            .append("set-cookie", header.parse().unwrap());
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Verification code sent",
        "data": {"id": id}
    })))
}

#[endpoint(tags("verification"), summary = "Verify code")]
pub async fn verify_code(
    depot: &mut Depot,
    request: &mut Request,
    body: JsonBody<VerifyCodeRequest>,
) -> AppResult<Json<VerifyCodeResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let req = body.into_inner();
    validate_contact(&req.verification_type, &req.dest)?;
    let (owner, subject, purpose) = if let Some(user) = current_user(depot, &pool).await? {
        (
            Some(user.owner),
            user.id,
            format!("contact:{}", req.verification_type),
        )
    } else {
        let nonce = signup_cookie(request)
            .ok_or_else(|| AppError::Authentication("Signup browser proof missing".into()))?;
        (
            None,
            format!("signup:{nonce}"),
            format!("signup:{}", req.verification_type),
        )
    };
    let changed = sqlx::query("UPDATE verifications SET is_used=true WHERE id=(SELECT id FROM verifications WHERE ($1::text IS NULL OR owner=$1) AND user_id=$2 AND type=$3 AND receiver=$4 AND code=$5 AND is_used=false AND created_at>NOW()-INTERVAL '5 minutes' ORDER BY created_at DESC LIMIT 1) AND is_used=false")
        .bind(owner).bind(subject).bind(purpose).bind(&req.dest).bind(&req.code).execute(&pool).await?.rows_affected()==1;
    let response = VerifyCodeResponse {
        success: changed,
        message: if changed {
            "Code verified successfully"
        } else {
            "Invalid or expired verification code"
        }
        .into(),
    };

    Ok(Json(response))
}

#[endpoint(tags("verification"), summary = "Get captcha")]
pub async fn get_captcha(depot: &mut Depot, req: &mut Request) -> AppResult<Json<CaptchaResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let application = req.query::<String>("application");
    let provider = req.query::<String>("provider");
    let response =
        VerificationService::generate_captcha(&pool, application.as_deref(), provider.as_deref())
            .await?;
    Ok(Json(response))
}

#[endpoint(tags("verification"), summary = "Verify captcha")]
pub async fn verify_captcha(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<VerifyCaptchaRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let payload = body.into_inner();
    let is_valid = VerificationService::verify_captcha(
        &pool,
        &payload.captcha_id,
        payload.captcha_code.as_deref(),
        payload.captcha_token.as_deref(),
        payload.application.as_deref(),
        payload.provider.as_deref(),
        Some(&req.remote_addr().to_string()),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "status": if is_valid { "ok" } else { "error" },
        "msg": if is_valid { "Captcha verified" } else { "Invalid captcha" }
    })))
}

#[endpoint(
    tags("verification"),
    summary = "Get email and phone for password reset"
)]
pub async fn get_email_and_phone(
    depot: &mut Depot,
    body: JsonBody<GetEmailAndPhoneRequest>,
) -> AppResult<Json<EmailAndPhoneResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let req = body.into_inner();
    let (email, phone) =
        VerificationService::get_email_and_phone(&pool, &req.username, &req.organization).await?;

    // Mask the email and phone for privacy
    let masked_email = email.map(|e| {
        if let Some(at_pos) = e.find('@') {
            let local = &e[..at_pos];
            let domain = &e[at_pos..];
            if local.len() > 2 {
                format!("{}***{}", &local[..2], domain)
            } else {
                format!("{}***{}", local, domain)
            }
        } else {
            e
        }
    });

    let masked_phone = phone.map(|p| {
        if p.len() > 4 {
            format!("***{}", &p[p.len() - 4..])
        } else {
            p
        }
    });

    Ok(Json(EmailAndPhoneResponse {
        email: masked_email,
        phone: masked_phone,
    }))
}

#[endpoint(
    tags("verification"),
    summary = "Reset current user's email or phone with a verification code"
)]
pub async fn reset_email_or_phone(
    depot: &mut Depot,
    body: JsonBody<ResetEmailOrPhoneRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let user = current_user(depot, &pool)
        .await?
        .ok_or_else(|| AppError::Authentication("Not authenticated".into()))?;
    let user_id = user.id;
    let req = body.into_inner();
    validate_contact(&req.reset_type, &req.dest)?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "contact:{}:{}:{}",
            user.owner, req.reset_type, req.dest
        ))
        .execute(&mut *transaction)
        .await?;
    // Lock the account and atomically consume only this user's contact-change
    // challenge. Signup, login-MFA and password-recovery codes cannot authorize it.
    sqlx::query("SELECT id FROM users WHERE id=$1 AND owner=$2 AND is_deleted=false AND is_forbidden=false FOR UPDATE")
        .bind(&user_id).bind(&user.owner).fetch_one(&mut *transaction).await?;
    let consumed = sqlx::query("UPDATE verifications SET is_used=true WHERE id=(SELECT id FROM verifications WHERE owner=$1 AND user_id=$2 AND type=$3 AND receiver=$4 AND code=$5 AND is_used=false AND created_at>NOW()-INTERVAL '5 minutes' ORDER BY created_at DESC LIMIT 1) AND is_used=false")
        .bind(&user.owner).bind(&user_id).bind(format!("contact:{}", req.reset_type)).bind(&req.dest).bind(&req.code).execute(&mut *transaction).await?.rows_affected();
    if consumed != 1 {
        return Err(AppError::Validation(
            "Invalid or expired contact-change code".into(),
        ));
    }

    match req.reset_type.as_str() {
        "email" => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND id <> $2 AND owner=$3 AND is_deleted = FALSE)",
            )
            .bind(&req.dest)
            .bind(&user_id)
            .bind(&user.owner)
            .fetch_one(&mut *transaction)
            .await?;
            if exists {
                return Err(AppError::Conflict("Email already exists".to_string()));
            }

            sqlx::query("UPDATE users SET email = $1, email_verified = TRUE, updated_at = NOW() WHERE id = $2")
                .bind(&req.dest)
                .bind(&user_id)
                .execute(&mut *transaction)
                .await?;
        }
        "phone" => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM users WHERE phone = $1 AND id <> $2 AND owner=$3 AND is_deleted = FALSE)",
            )
            .bind(&req.dest)
            .bind(&user_id)
            .bind(&user.owner)
            .fetch_one(&mut *transaction)
            .await?;
            if exists {
                return Err(AppError::Conflict("Phone already exists".to_string()));
            }

            sqlx::query("UPDATE users SET phone = $1, updated_at = NOW() WHERE id = $2")
                .bind(&req.dest)
                .bind(&user_id)
                .execute(&mut *transaction)
                .await?;
        }
        other => {
            return Err(AppError::Validation(format!(
                "Unsupported reset type: {}",
                other
            )));
        }
    }

    transaction.commit().await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "User contact information updated"
    })))
}
