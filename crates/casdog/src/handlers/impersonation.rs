use chrono::Utc;
use salvo::oapi::ToSchema;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::models::{Application, User, UserResponse};
use crate::services::{
    AppService, AuthService, SessionService, TokenService, UserService, auth_service::Claims,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct ImpersonateUserRequest {
    pub user_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImpersonateUserResponse {
    pub status: String,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub session_id: String,
    pub application: String,
    pub impersonated_user_id: String,
    pub original_user_id: String,
    pub msg: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExitImpersonateResponse {
    pub status: String,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub session_id: String,
    pub application: String,
    pub restored_user_id: String,
    pub msg: String,
}

fn extract_bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
}

async fn resolve_impersonation_application(
    pool: &DieselPool,
    pg_pool: &Pool<Postgres>,
    user: &User,
) -> AppResult<Application> {
    let app_service = AppService::new(pool.clone());

    if let Some(app_ref) = user
        .signup_application
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Ok(application) = app_service.find_internal(app_ref, Some(&user.owner)).await {
            return Ok(application);
        }
    }

    if let Some(application) = sqlx::query_as::<_, Application>(
        r#"
        SELECT *
        FROM applications
        WHERE organization = $1 AND is_deleted = FALSE
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&user.owner)
    .fetch_optional(pg_pool)
    .await?
    {
        return Ok(application);
    }

    app_service
        .find_internal("app-built-in", Some("built-in"))
        .await
        .map_err(|_| {
            AppError::NotFound(format!(
                "No application available for impersonation target '{}'",
                user.id
            ))
        })
}

async fn write_audit_record(
    pool: &Pool<Postgres>,
    owner: &str,
    organization: Option<&str>,
    client_ip: Option<&str>,
    user_id: &str,
    request_uri: &str,
    action: &str,
    object: Option<&str>,
) {
    let _ = sqlx::query(
        r#"
        INSERT INTO records (
            id, owner, name, created_at, organization, client_ip, user_id,
            method, request_uri, action, object, is_triggered
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'POST', $8, $9, $10, false)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(owner)
    .bind(action)
    .bind(Utc::now())
    .bind(organization)
    .bind(client_ip)
    .bind(user_id)
    .bind(request_uri)
    .bind(action)
    .bind(object)
    .execute(pool)
    .await;
}

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
    req: &mut Request,
    body: JsonBody<ImpersonateUserRequest>,
) -> AppResult<Json<ImpersonateUserResponse>> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let admin_user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;
    let payload = body.into_inner();

    if payload.user_id == admin_user_id {
        return Err(AppError::Validation(
            "Cannot impersonate the current user".to_string(),
        ));
    }

    let user_service = UserService::new(pool.clone());
    let admin_user = user_service.get_by_id_internal(&admin_user_id).await?;
    if !admin_user.is_admin {
        return Err(AppError::Authorization(
            "Only administrators can impersonate users".to_string(),
        ));
    }

    let target_user = user_service.get_by_id_internal(&payload.user_id).await?;
    let application = resolve_impersonation_application(&pool, &pg_pool, &target_user).await?;
    let auth_service = AuthService::new(user_service.clone());
    let expires_in = auth_service.expires_in_seconds();
    let client_ip = req.remote_addr().to_string();
    let session_id = SessionService::create_login_session(
        &pg_pool,
        &target_user.id,
        &target_user.name,
        &application.organization,
        &application.name,
        Some(&client_ip),
        auth_service.expiration_hours(),
    )
    .await?;

    let target_user_response: UserResponse = target_user.clone().into();
    let mut claims = auth_service.claims_for_user(&target_user_response);
    claims.impersonator_user_id = Some(admin_user.id.clone());
    claims.impersonator_owner = Some(admin_user.owner.clone());
    claims.impersonator_name = Some(admin_user.name.clone());
    claims.impersonation_session_id = Some(session_id.clone());
    claims.impersonation_application = Some(application.name.clone());
    let access_token = auth_service.generate_token_from_claims(&claims)?;

    let _stored_token = TokenService::persist_issued_access_token(
        &pool,
        &application.owner,
        &format!("impersonation_{}", &session_id[..8]),
        &application.name,
        &application.organization,
        &target_user.id,
        &access_token,
        expires_in,
        Some("openid profile"),
    )
    .await?;
    let audit_object = format!(
        "admin={} target={} application={}{}",
        admin_user.id,
        target_user.id,
        application.name,
        payload
            .reason
            .as_deref()
            .map(|value| format!(" reason={}", value))
            .unwrap_or_default()
    );

    write_audit_record(
        &pg_pool,
        &admin_user.owner,
        Some(&application.organization),
        Some(&client_ip),
        &admin_user.id,
        "/api/impersonate-user",
        "impersonate-user",
        Some(&audit_object),
    )
    .await;

    Ok(Json(ImpersonateUserResponse {
        status: "ok".to_string(),
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        session_id,
        application: application.name,
        impersonated_user_id: target_user.id,
        original_user_id: admin_user.id,
        msg: "Impersonation session started".to_string(),
    }))
}

#[endpoint(
    tags("Impersonation"),
    summary = "Exit user impersonation",
    responses(
        (status_code = 200, description = "Impersonation ended", body = ExitImpersonateResponse),
        (status_code = 401, description = "Not authenticated")
    )
)]
pub async fn exit_impersonate_user(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<ExitImpersonateResponse>> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let claims = depot
        .get::<Claims>("claims")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;
    let impersonator_user_id = claims.impersonator_user_id.clone().ok_or_else(|| {
        AppError::Validation("Current token is not an impersonation session".to_string())
    })?;

    let user_service = UserService::new(pool.clone());
    let admin_user = user_service
        .get_by_id_internal(&impersonator_user_id)
        .await?;
    if !admin_user.is_admin {
        return Err(AppError::Authorization(
            "Original user no longer has admin privileges".to_string(),
        ));
    }

    let application = resolve_impersonation_application(&pool, &pg_pool, &admin_user).await?;
    let auth_service = AuthService::new(user_service);
    let expires_in = auth_service.expires_in_seconds();
    let client_ip = req.remote_addr().to_string();
    let session_id = SessionService::create_login_session(
        &pg_pool,
        &admin_user.id,
        &admin_user.name,
        &application.organization,
        &application.name,
        Some(&client_ip),
        auth_service.expiration_hours(),
    )
    .await?;

    let admin_user_response: UserResponse = admin_user.clone().into();
    let access_token = auth_service.generate_token(&admin_user_response)?;

    let _stored_token = TokenService::persist_issued_access_token(
        &pool,
        &application.owner,
        &format!("restored_{}", &session_id[..8]),
        &application.name,
        &application.organization,
        &admin_user.id,
        &access_token,
        expires_in,
        Some("openid profile"),
    )
    .await?;

    if let Some(token) = extract_bearer_token(req) {
        let _ = TokenService::delete_by_access_token(&pool, &token).await;
    }
    if let Some(impersonation_session_id) = claims.impersonation_session_id.as_deref() {
        let _ = SessionService::delete_by_session_id(&pg_pool, impersonation_session_id).await;
    }
    let audit_object = format!("restored_admin={}", admin_user.id);

    write_audit_record(
        &pg_pool,
        &admin_user.owner,
        Some(&application.organization),
        Some(&client_ip),
        &admin_user.id,
        "/api/exit-impersonate-user",
        "exit-impersonate-user",
        Some(&audit_object),
    )
    .await;

    Ok(Json(ExitImpersonateResponse {
        status: "ok".to_string(),
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        session_id,
        application: application.name,
        restored_user_id: admin_user.id,
        msg: "Impersonation session ended".to_string(),
    }))
}
