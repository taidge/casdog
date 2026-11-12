use jsonwebtoken::{DecodingKey, Validation, decode};
use salvo::prelude::*;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::config::AppConfig;
use crate::error::{AppError, AppResult, ErrorResponse};
use crate::services::auth_service::Claims;

pub fn session_fingerprint(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Validate the signed session against current account and revocation state.
/// A valid signature alone cannot keep a deleted, disabled or reset account signed in.
pub async fn validate_session_claims(pool: &PgPool, token: &str) -> AppResult<Claims> {
    let config = AppConfig::get();
    let mut validation = Validation::default();
    validation.set_issuer(&[config.jwt.issuer.as_str()]);
    validation.leeway = 0;
    let mut claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt.secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Authentication("Invalid or expired token".into()))?
    .claims;
    let user: Option<(String, String, bool, Option<String>)> = sqlx::query_as(
        "SELECT owner, name, is_admin, last_change_password_time FROM users WHERE id=$1 AND is_deleted=false AND is_forbidden=false")
        .bind(&claims.sub).fetch_optional(pool).await?;
    let (owner, name, admin, changed) =
        user.ok_or_else(|| AppError::Authentication("Account unavailable".into()))?;
    if owner != claims.owner {
        return Err(AppError::Authentication(
            "Account organization changed".into(),
        ));
    }
    validate_credential_epoch(&claims, changed)?;
    validate_logout_epoch(pool, &claims, &claims.sub).await?;
    if let Some(id) = claims.impersonator_user_id.as_deref() {
        let original: Option<(String, Option<String>)> = sqlx::query_as("SELECT owner,last_change_password_time FROM users WHERE id=$1 AND is_admin=true AND NOT is_deleted AND NOT is_forbidden")
            .bind(id).fetch_optional(pool).await?;
        let (original_owner, changed) = original
            .ok_or_else(|| AppError::Authentication("Original administrator unavailable".into()))?;
        if claims.impersonator_owner.as_deref() != Some(original_owner.as_str()) {
            return Err(AppError::Authentication(
                "Original administrator organization changed".into(),
            ));
        }
        validate_credential_epoch(&claims, changed)?;
        validate_logout_epoch(pool, &claims, id).await?;
        let session = claims
            .impersonation_session_id
            .as_deref()
            .ok_or_else(|| AppError::Authentication("Impersonation session missing".into()))?;
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE session_id=$1 AND user_id=$2)",
        )
        .bind(session)
        .bind(&claims.sub)
        .fetch_one(pool)
        .await?;
        if !active {
            return Err(AppError::Authentication(
                "Impersonation session ended".into(),
            ));
        }
    }
    let revoked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM revoked_session_tokens WHERE token_hash=$1 AND expires_at > NOW())")
        .bind(session_fingerprint(token)).fetch_one(pool).await?;
    if revoked {
        return Err(AppError::Authentication("Session revoked".into()));
    }
    claims.owner = owner;
    claims.name = name;
    claims.is_admin &= admin;
    Ok(claims)
}

async fn validate_logout_epoch(pool: &PgPool, claims: &Claims, id: &str) -> AppResult<()> {
    let cutoff: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT invalid_before FROM user_session_epochs WHERE user_id=$1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    validate_credential_epoch(claims, cutoff.map(|t| t.to_rfc3339()))
}

fn validate_credential_epoch(claims: &Claims, changed: Option<String>) -> AppResult<()> {
    if let Some(changed) = changed.filter(|s| !s.is_empty()) {
        let changed = chrono::DateTime::parse_from_rfc3339(&changed)
            .map_err(|_| AppError::Authentication("Invalid account credential state".into()))?;
        let stale = match claims.issued_at_ms {
            Some(issued) => issued <= changed.timestamp_millis(),
            None => claims.iat <= changed.timestamp(),
        };
        if stale {
            return Err(AppError::Authentication(
                "Credentials changed; sign in again".into(),
            ));
        }
    }
    Ok(())
}

pub fn insert_claims(depot: &mut Depot, claims: Claims) {
    super::authz::set_application_identity(depot, false);
    depot.inject(
        crate::services::key_credentials_service::CredentialIdentity::User(
            super::authz::Principal {
                id: claims.sub.clone(),
                owner: claims.owner.clone(),
                name: claims.name.clone(),
                admin: claims.is_admin,
                application_identity: false,
            },
        ),
    );
    depot.insert("user_id", claims.sub.clone());
    depot.insert("user_owner", claims.owner.clone());
    depot.insert("user_name", claims.name.clone());
    depot.insert("is_admin", claims.is_admin);
    if let Some(value) = &claims.impersonator_user_id {
        depot.insert("impersonator_user_id", value.clone());
        depot.insert("is_impersonating", true);
    }
    for (key, value) in [
        ("impersonator_owner", &claims.impersonator_owner),
        ("impersonator_name", &claims.impersonator_name),
        ("impersonation_session_id", &claims.impersonation_session_id),
        (
            "impersonation_application",
            &claims.impersonation_application,
        ),
    ] {
        if let Some(value) = value {
            depot.insert(key, value.clone());
        }
    }
    depot.insert("claims", claims);
}

pub struct JwtAuth;
/// Shared credential selection for required and optional authentication. A
/// malformed or failed explicit source is an error, never an anonymous retry.
pub async fn authenticate_request(req: &Request, depot: &mut Depot) -> AppResult<bool> {
    use crate::services::key_credentials_service::{self as credentials, CredentialSource};
    let Some(source) = credentials::source(req)? else {
        return Ok(false);
    };
    let pool = depot
        .obtain::<PgPool>()
        .cloned()
        .map_err(|_| AppError::Authentication("Credential validation unavailable".into()))?;
    match source {
        CredentialSource::Bearer(token) => {
            let claims = validate_session_claims(&pool, &token).await?;
            insert_claims(depot, claims);
        }
        source => {
            credentials::insert_identity(depot, credentials::authenticate(&pool, &source).await?)
        }
    }
    Ok(true)
}

#[async_trait]
impl Handler for JwtAuth {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        match authenticate_request(req, depot).await {
            Ok(true) => {
                ctrl.call_next(req, depot, res).await;
            }
            Ok(false) | Err(_) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ErrorResponse::new(
                    401,
                    "Missing, invalid or expired credentials",
                )));
                ctrl.skip_rest();
            }
        }
    }
}

pub struct OptionalJwtAuth;
#[async_trait]
impl Handler for OptionalJwtAuth {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if authenticate_request(req, depot).await.is_err() {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ErrorResponse::new(
                401,
                "Invalid or expired credentials",
            )));
            ctrl.skip_rest();
            return;
        }
        if crate::services::key_credentials_service::application_identity(depot)
            && matches!(
                req.uri().path().trim_end_matches('/'),
                "/api/send-verification-code" | "/api/verify-code"
            )
        {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(ErrorResponse::new(
                403,
                "Application credentials cannot authenticate an interactive user",
            )));
            ctrl.skip_rest();
            return;
        }
        ctrl.call_next(req, depot, res).await;
    }
}
