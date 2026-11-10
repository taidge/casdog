use salvo::oapi::ToSchema;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

use crate::config::AppConfig;
use crate::error::AppError;
use crate::services::mfa_service::MfaService;

#[derive(Debug, Serialize, ToSchema)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub qr_url: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MfaVerifyRequest {
    pub code: String,
    pub mfa_type: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MfaVerifyResponse {
    pub success: bool,
    pub recovery_codes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MfaDeleteRequest {
    pub mfa_type: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetPreferredMfaRequest {
    pub mfa_type: String,
}

/// Initiate MFA setup (TOTP)
#[endpoint(
    tags("MFA"),
    responses(
        (status_code = 200, description = "MFA setup initiated", body = MfaSetupResponse)
    )
)]
pub async fn initiate_mfa_setup(depot: &mut Depot) -> Result<Json<MfaSetupResponse>, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;
    let user_name = depot
        .get::<String>("user_name")
        .cloned()
        .unwrap_or_else(|_| "user".to_string());

    let config = AppConfig::get();
    let issuer = &config.jwt.issuer;

    let (secret, qr_url) = MfaService::initiate_totp_setup(&user_name, issuer)?;

    // Save the secret to DB (not yet enabled)
    MfaService::save_mfa(&pool, &user_id, "totp", Some(&secret)).await?;

    Ok(Json(MfaSetupResponse { secret, qr_url }))
}

/// Verify MFA setup code to confirm setup
#[endpoint(
    tags("MFA"),
    request_body(content = MfaVerifyRequest, description = "Verify MFA code"),
    responses(
        (status_code = 200, description = "MFA verified", body = MfaVerifyResponse)
    )
)]
pub async fn verify_mfa_setup(
    depot: &mut Depot,
    req: JsonBody<MfaVerifyRequest>,
) -> Result<Json<MfaVerifyResponse>, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let mfa_type = req.mfa_type.as_deref().unwrap_or("totp");
    let Some(mfa) = MfaService::confirm_setup(&pool, &user_id, mfa_type, &req.code).await? else {
        return Ok(Json(MfaVerifyResponse {
            success: false,
            recovery_codes: None,
        }));
    };

    // Parse recovery codes to return them
    let recovery_codes = mfa
        .recovery_codes
        .and_then(|c| serde_json::from_str::<Vec<String>>(&c).ok());

    Ok(Json(MfaVerifyResponse {
        success: true,
        recovery_codes,
    }))
}

/// Enable MFA after verification
#[endpoint(
    tags("MFA"),
    responses(
        (status_code = 200, description = "MFA enabled")
    )
)]
pub async fn enable_mfa(depot: &mut Depot) -> Result<Json<serde_json::Value>, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let verified = MfaService::get_user_mfa(&pool, &user_id, "totp")
        .await?
        .is_some_and(|mfa| mfa.is_enabled);
    if !verified {
        return Err(AppError::Validation(
            "Verify the MFA setup code before enabling MFA".to_string(),
        ));
    }

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// Delete MFA
#[endpoint(
    tags("MFA"),
    request_body(content = MfaDeleteRequest, description = "Delete MFA request"),
    responses(
        (status_code = 200, description = "MFA deleted")
    )
)]
pub async fn delete_mfa(
    depot: &mut Depot,
    req: JsonBody<MfaDeleteRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    MfaService::delete_mfa(&pool, &user_id, &req.mfa_type).await?;

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// Set preferred MFA type
#[endpoint(
    tags("MFA"),
    request_body(content = SetPreferredMfaRequest, description = "Set preferred MFA type"),
    responses(
        (status_code = 200, description = "Preferred MFA type set")
    )
)]
pub async fn set_preferred_mfa(
    depot: &mut Depot,
    req: JsonBody<SetPreferredMfaRequest>,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    sqlx::query("UPDATE users SET preferred_mfa_type = $1, updated_at = $2 WHERE id = $3")
        .bind(&req.mfa_type)
        .bind(chrono::Utc::now())
        .bind(&user_id)
        .execute(&pool)
        .await?;

    Ok("Preferred MFA type set")
}
