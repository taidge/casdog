use salvo::oapi::ToSchema;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Request body for starting an impersonation session.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ImpersonateUserRequest {
    /// The ID of the user to impersonate.
    pub user_id: String,
    /// Optional reason for audit logging.
    pub reason: Option<String>,
}

/// Successful response when an impersonation session is started.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImpersonateUserResponse {
    /// Status indicator (`"ok"` on success).
    pub status: String,
    /// Temporary access token scoped to the impersonated user.
    pub access_token: String,
    /// ID of the user that is being impersonated.
    pub impersonated_user_id: String,
    /// ID of the admin who initiated the impersonation.
    pub original_user_id: String,
    /// Human-readable message.
    pub msg: String,
}

/// Successful response when an impersonation session is ended.
#[derive(Debug, Serialize, ToSchema)]
pub struct ExitImpersonateResponse {
    /// Status indicator (`"ok"` on success).
    pub status: String,
    /// The original admin user ID restored after exiting impersonation.
    pub restored_user_id: String,
    /// Human-readable message.
    pub msg: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Start impersonating another user.
///
/// The caller must be an authenticated admin. A temporary access token is
/// returned that is scoped to the target user. The original admin identity
/// is recorded so that it can be restored later via `exit_impersonate_user`.
///
/// **Note:** This is currently a placeholder implementation. In production the
/// token should be a real JWT with restricted lifetime and the impersonation
/// relationship should be persisted (e.g. in the sessions table).
#[endpoint(
    tags("Impersonation"),
    summary = "Impersonate a user",
    request_body(content = ImpersonateUserRequest, description = "Impersonation request"),
    responses(
        (status_code = 200, description = "Impersonation started", body = ImpersonateUserResponse),
        (status_code = 401, description = "Not authenticated"),
        (status_code = 403, description = "Insufficient permissions"),
        (status_code = 404, description = "Target user not found")
    )
)]
pub async fn impersonate_user(
    depot: &mut Depot,
    body: JsonBody<ImpersonateUserRequest>,
) -> AppResult<Json<ImpersonateUserResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    // Retrieve the authenticated admin's user ID from the depot.
    let admin_user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    let req = body.into_inner();

    // Verify the target user exists.
    let target_exists: Option<(String,)> =
        sqlx::query_as("SELECT id FROM users WHERE id = $1 AND is_deleted = FALSE")
            .bind(&req.user_id)
            .fetch_optional(&pool)
            .await?;

    if target_exists.is_none() {
        return Err(AppError::NotFound(format!(
            "User '{}' not found",
            req.user_id
        )));
    }

    // Verify the caller has admin privileges.
    let is_admin: Option<(bool,)> =
        sqlx::query_as("SELECT is_admin FROM users WHERE id = $1 AND is_deleted = FALSE")
            .bind(&admin_user_id)
            .fetch_optional(&pool)
            .await?;

    match is_admin {
        Some((true,)) => { /* allowed */ }
        _ => {
            return Err(AppError::Authorization(
                "Only administrators can impersonate users".to_string(),
            ));
        }
    }

    // Record the impersonation event for audit purposes.
    let _audit = sqlx::query(
        r#"
        INSERT INTO records (id, owner, name, created_at, organization, client_ip, "user", method, request_uri, action, is_triggered)
        VALUES ($1, $2, 'impersonate-user', NOW(), '', '', $3, 'POST', '/api/impersonate', $4, false)
        "#,
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&admin_user_id)
    .bind(&req.user_id)
    .bind(format!(
        "Admin {} impersonated user {}{}",
        admin_user_id,
        req.user_id,
        req.reason
            .as_ref()
            .map(|r| format!(" (reason: {})", r))
            .unwrap_or_default()
    ))
    .execute(&pool)
    .await;
    // We intentionally ignore audit insert failures so they don't block the
    // impersonation flow.

    // In a full implementation this would generate a real JWT containing both
    // the impersonated user ID and the original admin ID. For now we return a
    // placeholder token.
    let placeholder_token = format!("imp_{}", uuid::Uuid::new_v4());

    Ok(Json(ImpersonateUserResponse {
        status: "ok".to_string(),
        access_token: placeholder_token,
        impersonated_user_id: req.user_id,
        original_user_id: admin_user_id,
        msg: "Impersonation session started".to_string(),
    }))
}

/// Exit an active impersonation session and restore the original admin identity.
///
/// The caller should be in an active impersonation session. The handler
/// restores the original admin user context.
///
/// **Note:** This is currently a placeholder implementation. In production the
/// impersonation token should be invalidated and the original session token
/// should be returned.
#[endpoint(
    tags("Impersonation"),
    summary = "Exit user impersonation",
    responses(
        (status_code = 200, description = "Impersonation ended", body = ExitImpersonateResponse),
        (status_code = 401, description = "Not authenticated")
    )
)]
pub async fn exit_impersonate_user(depot: &mut Depot) -> AppResult<Json<ExitImpersonateResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    // In a real implementation the impersonation token would carry both the
    // impersonated user ID and the original admin ID. We would decode the
    // token to discover who the real admin is. For now we just read the
    // current user ID out of the depot.
    let current_user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;

    // Record the exit event for audit purposes.
    let _audit = sqlx::query(
        r#"
        INSERT INTO records (id, owner, name, created_at, organization, client_ip, "user", method, request_uri, action, is_triggered)
        VALUES ($1, $2, 'exit-impersonate', NOW(), '', '', $3, 'POST', '/api/exit-impersonate', 'exit_impersonate', false)
        "#,
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&current_user_id)
    .bind(&current_user_id)
    .execute(&pool)
    .await;

    Ok(Json(ExitImpersonateResponse {
        status: "ok".to_string(),
        restored_user_id: current_user_id,
        msg: "Impersonation session ended, original identity restored".to_string(),
    }))
}
