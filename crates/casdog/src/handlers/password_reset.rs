use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use sqlx::PgPool;

use crate::error::{AppError, AppResult};
use crate::services::password_reset_service::{
    CompletePasswordReset, PasswordResetReceipt, PasswordResetService, RequestPasswordReset,
};

#[endpoint(tags("Authentication"), summary = "Request a password recovery code")]
pub async fn request_password_reset(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RequestPasswordReset>,
) -> AppResult<Json<PasswordResetReceipt>> {
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("Database unavailable".into()))?;
    // Ignore caller-supplied forwarding headers. A trusted proxy integration may
    // supply its verified client address separately in a future deployment policy.
    let source = req
        .remote_addr()
        .ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    Ok(Json(
        PasswordResetService::request(pool, body.into_inner(), &source).await?,
    ))
}

#[endpoint(tags("Authentication"), summary = "Consume a password recovery code")]
pub async fn reset_password(
    depot: &mut Depot,
    body: JsonBody<CompletePasswordReset>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("Database unavailable".into()))?;
    PasswordResetService::complete(pool, body.into_inner()).await?;
    Ok(Json(
        serde_json::json!({"status":"ok", "msg":"Password reset. Sign in with your new password."}),
    ))
}
