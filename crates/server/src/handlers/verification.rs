use crate::error::{AppError, AppResult};
use crate::models::{
    CaptchaResponse, EmailAndPhoneResponse, GetEmailAndPhoneRequest, SendVerificationCodeRequest,
    VerifyCaptchaRequest, VerifyCodeRequest, VerifyCodeResponse,
};
use crate::services::VerificationService;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

#[endpoint(tags("verification"), summary = "Send verification code")]
pub async fn send_verification_code(
    depot: &mut Depot,
    body: JsonBody<SendVerificationCodeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let req = body.into_inner();
    let response = VerificationService::send_verification_code(
        &pool,
        "default", // owner
        &req.dest,
        &req.verification_type,
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
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

    let req = body.into_inner();
    let response =
        VerificationService::verify_code(&pool, &req.dest, &req.code).await?;

    Ok(Json(response))
}

#[endpoint(tags("verification"), summary = "Get captcha")]
pub async fn get_captcha() -> AppResult<Json<CaptchaResponse>> {
    let response = VerificationService::generate_captcha()?;
    Ok(Json(response))
}

#[endpoint(tags("verification"), summary = "Verify captcha")]
pub async fn verify_captcha(
    body: JsonBody<VerifyCaptchaRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let req = body.into_inner();
    let is_valid = VerificationService::verify_captcha(&req.captcha_id, &req.captcha_code)?;

    Ok(Json(serde_json::json!({
        "status": if is_valid { "ok" } else { "error" },
        "msg": if is_valid { "Captcha verified" } else { "Invalid captcha" }
    })))
}

#[endpoint(tags("verification"), summary = "Get email and phone for password reset")]
pub async fn get_email_and_phone(
    depot: &mut Depot,
    body: JsonBody<GetEmailAndPhoneRequest>,
) -> AppResult<Json<EmailAndPhoneResponse>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not found".to_string())
    })?.clone();

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
