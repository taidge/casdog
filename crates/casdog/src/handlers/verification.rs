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
    body: JsonBody<SendVerificationCodeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let payload = body.into_inner();
    let user_id = depot.get::<String>("user_id").ok().cloned();
    let response = VerificationService::send_verification_code(
        &pool,
        "built-in",
        user_id.as_deref(),
        &payload.dest,
        &payload.verification_type,
        payload.application.as_deref(),
        payload.provider.as_deref(),
        payload.method.as_deref(),
        payload.country_code.as_deref(),
        Some(&req.remote_addr().to_string()),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Verification code sent",
        "data": response
    })))
}

#[endpoint(tags("verification"), summary = "Verify code")]
pub async fn verify_code(
    depot: &mut Depot,
    body: JsonBody<VerifyCodeRequest>,
) -> AppResult<Json<VerifyCodeResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let req = body.into_inner();
    let response = VerificationService::verify_code(&pool, &req.dest, &req.code).await?;

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
    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let req = body.into_inner();
    let verification = VerificationService::verify_code(&pool, &req.dest, &req.code).await?;
    if !verification.success {
        return Err(AppError::Validation(verification.message));
    }

    match req.reset_type.as_str() {
        "email" => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND id <> $2 AND is_deleted = FALSE)",
            )
            .bind(&req.dest)
            .bind(&user_id)
            .fetch_one(&pool)
            .await?;
            if exists {
                return Err(AppError::Conflict("Email already exists".to_string()));
            }

            sqlx::query("UPDATE users SET email = $1, email_verified = TRUE, updated_at = NOW() WHERE id = $2")
                .bind(&req.dest)
                .bind(&user_id)
                .execute(&pool)
                .await?;
        }
        "phone" => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM users WHERE phone = $1 AND id <> $2 AND is_deleted = FALSE)",
            )
            .bind(&req.dest)
            .bind(&user_id)
            .fetch_one(&pool)
            .await?;
            if exists {
                return Err(AppError::Conflict("Phone already exists".to_string()));
            }

            sqlx::query("UPDATE users SET phone = $1, updated_at = NOW() WHERE id = $2")
                .bind(&req.dest)
                .bind(&user_id)
                .execute(&pool)
                .await?;
        }
        other => {
            return Err(AppError::Validation(format!(
                "Unsupported reset type: {}",
                other
            )));
        }
    }

    VerificationService::disable_verification_code(&pool, &req.dest).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "User contact information updated"
    })))
}
