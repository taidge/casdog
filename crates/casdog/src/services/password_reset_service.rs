use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::Provider;
use crate::services::{CheckService, PasswordService, ProviderDispatchService};

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RequestPasswordReset {
    #[serde(alias = "owner")]
    pub organization: String,
    pub email: String,
    pub application: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CompletePasswordReset {
    #[serde(alias = "owner")]
    pub organization: String,
    pub email: String,
    pub application: Option<String>,
    #[serde(alias = "requestId")]
    pub request_id: String,
    pub code: String,
    #[serde(alias = "newPassword")]
    pub new_password: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PasswordResetReceipt {
    pub status: &'static str,
    pub msg: &'static str,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "expiresIn")]
    pub expires_in: i32,
}

#[derive(sqlx::FromRow)]
struct ResetApplication {
    id: String,
    providers: Option<serde_json::Value>,
}

#[derive(sqlx::FromRow)]
struct ResetChallenge {
    owner: String,
    email_hash: String,
    application_id: Option<String>,
    user_id: Option<String>,
    token_hash: String,
    attempts: i32,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

pub struct PasswordResetService;

impl PasswordResetService {
    fn hash(value: &str) -> String {
        hex::encode(Sha256::digest(value.as_bytes()))
    }

    fn identity(organization: &str, email: &str) -> AppResult<(String, String)> {
        let organization = organization.trim().to_string();
        let email = email.trim().to_lowercase();
        if organization.is_empty() || organization.len() > 100 || email.len() > 255 {
            return Err(AppError::Validation(
                "Organization and email are required".into(),
            ));
        }
        CheckService::check_email(&email)?;
        Ok((organization, email))
    }

    fn receipt(request_id: String) -> PasswordResetReceipt {
        PasswordResetReceipt {
            status: "ok",
            msg: "If this account can recover its password, a reset code will be sent to its email address.",
            request_id,
            expires_in: 900,
        }
    }

    fn invalid() -> AppError {
        AppError::Validation("Invalid or expired password reset code".into())
    }

    async fn application(
        pool: &PgPool,
        owner: &str,
        reference: Option<&str>,
    ) -> AppResult<Option<ResetApplication>> {
        let Some(reference) = reference.filter(|s| !s.trim().is_empty()) else {
            return Ok(None);
        };
        let rows: Vec<ResetApplication> = sqlx::query_as(
            "SELECT id, providers FROM applications WHERE organization = $1 AND is_deleted = false AND enable_password = true AND (id = $2 OR client_id = $2 OR owner || '/' || name = $2 OR name = $2) LIMIT 2")
            .bind(owner).bind(reference).fetch_all(pool).await?;
        if rows.len() != 1 {
            return Err(Self::invalid());
        }
        Ok(rows.into_iter().next())
    }

    async fn email_provider(
        pool: &PgPool,
        owner: &str,
        application: Option<&ResetApplication>,
    ) -> AppResult<Option<Provider>> {
        if let Some(items) = application
            .and_then(|app| app.providers.as_ref())
            .and_then(|p| p.as_array())
        {
            for item in items {
                let rule = item
                    .get("rule")
                    .and_then(|r| r.as_str())
                    .unwrap_or_default();
                if !["", "all", "forget", "reset", "none"]
                    .iter()
                    .any(|allowed| rule.eq_ignore_ascii_case(allowed))
                {
                    continue;
                }
                let Some(reference) = item.get("name").and_then(|n| n.as_str()) else {
                    continue;
                };
                let provider: Option<Provider> = if let Some((provider_owner, name)) =
                    reference.split_once('/')
                {
                    if provider_owner != owner && provider_owner != "admin" {
                        continue;
                    }
                    sqlx::query_as("SELECT * FROM providers WHERE owner = $1 AND name = $2 AND lower(category) = 'email' LIMIT 1")
                        .bind(provider_owner).bind(name).fetch_optional(pool).await?
                } else {
                    sqlx::query_as("SELECT * FROM providers WHERE owner IN ($1, 'admin') AND name = $2 AND lower(category) = 'email' ORDER BY CASE WHEN owner = $1 THEN 0 ELSE 1 END LIMIT 1")
                        .bind(owner).bind(reference).fetch_optional(pool).await?
                };
                if provider.is_some() {
                    return Ok(provider);
                }
            }
        }
        // Never pick another tenant's provider as an implicit default.
        Ok(sqlx::query_as("SELECT * FROM providers WHERE (owner = $1 OR ($1 = 'built-in' AND owner = 'admin')) AND lower(category) = 'email' ORDER BY created_at, id LIMIT 1")
            .bind(owner).fetch_optional(pool).await?)
    }

    pub async fn request(
        pool: &PgPool,
        payload: RequestPasswordReset,
        source: &str,
    ) -> AppResult<PasswordResetReceipt> {
        let (owner, email) = Self::identity(&payload.organization, &payload.email)?;
        let email_hash = Self::hash(&email);
        let source_hash = Self::hash(source);
        let id = Uuid::new_v4().to_string();
        let application = Self::application(pool, &owner, payload.application.as_deref()).await;
        let app_valid = application.is_ok();
        let application = application.unwrap_or(None);
        let mut transaction = pool.begin().await?;
        // Database-backed limits survive restarts and serialize concurrent resend attempts.
        for key in [
            format!("reset-source:{source_hash}"),
            format!("reset-user:{owner}:{email_hash}"),
        ] {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(key)
                .execute(&mut *transaction)
                .await?;
        }
        let source_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_requests WHERE source_hash = $1 AND created_at > NOW() - INTERVAL '1 hour'")
            .bind(&source_hash).fetch_one(&mut *transaction).await?;
        let recent: Option<String> = sqlx::query_scalar("SELECT id FROM password_reset_requests WHERE owner = $1 AND email_hash = $2 AND created_at > NOW() - INTERVAL '60 seconds' ORDER BY created_at DESC LIMIT 1")
            .bind(&owner).bind(&email_hash).fetch_optional(&mut *transaction).await?;
        if let Some(recent) = recent {
            return Ok(Self::receipt(recent));
        }
        let target_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_requests WHERE owner = $1 AND email_hash = $2 AND created_at > NOW() - INTERVAL '1 hour'")
            .bind(&owner).bind(&email_hash).fetch_one(&mut *transaction).await?;
        if source_count >= 20 || target_count >= 5 {
            return Ok(Self::receipt(id));
        }
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        // Unknown users receive the identical response and a challenge with no principal.
        let users: Vec<String> = sqlx::query_scalar("SELECT u.id FROM users u JOIN organizations o ON o.name = u.owner WHERE u.owner = $1 AND lower(u.email) = $2 AND u.is_deleted = false AND u.is_forbidden = false AND o.is_deleted = false LIMIT 2")
            .bind(&owner).bind(&email).fetch_all(&mut *transaction).await?;
        let user_id = if users.len() == 1 && app_valid {
            users.into_iter().next()
        } else {
            None
        };
        sqlx::query("INSERT INTO password_reset_requests (id, owner, email_hash, source_hash, application_id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&id).bind(&owner).bind(&email_hash).bind(&source_hash)
            .bind(application.as_ref().map(|a| a.id.as_str())).bind(&user_id)
            .bind(Self::hash(&token)).bind(Utc::now() + Duration::minutes(15))
            .execute(&mut *transaction).await?;
        transaction.commit().await?;
        if user_id.is_some() {
            let pool = pool.clone();
            let request_id = id.clone();
            // Mail delivery runs off the response path to avoid exposing account existence
            // through provider latency. The proof never appears in the HTTP response/logs.
            tokio::spawn(async move {
                let delivered = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    let provider = Self::email_provider(&pool, &owner, application.as_ref()).await?
                        .ok_or_else(|| AppError::Config("No recovery email provider configured".into()))?;
                    ProviderDispatchService::new(pool.clone()).send_email_with_provider(
                        &provider, &[email], "Reset your password",
                        &format!("Your password reset code is:\n{token}\n\nIt expires in 15 minutes. If you did not request this, ignore this message."), None).await
                }).await;
                if !matches!(delivered, Ok(Ok(_))) {
                    tracing::warn!(request_id, "Password reset email delivery failed");
                    let _ = sqlx::query(
                        "UPDATE password_reset_requests SET consumed_at = NOW() WHERE id = $1",
                    )
                    .bind(request_id)
                    .execute(&pool)
                    .await;
                }
            });
        }
        Ok(Self::receipt(id))
    }

    pub async fn complete(pool: &PgPool, payload: CompletePasswordReset) -> AppResult<()> {
        let (owner, email) = Self::identity(&payload.organization, &payload.email)?;
        if payload.new_password.len() > 1024 || payload.code.len() > 256 {
            return Err(Self::invalid());
        }
        let application = Self::application(pool, &owner, payload.application.as_deref())
            .await
            .map_err(|_| Self::invalid())?;
        let mut transaction = pool.begin().await?;
        let lock_key: String = sqlx::query_scalar(
            "SELECT COALESCE(user_id,id) FROM password_reset_requests WHERE id = $1",
        )
        .bind(&payload.request_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(Self::invalid)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("reset-complete:{lock_key}"))
            .execute(&mut *transaction)
            .await?;
        let challenge: ResetChallenge = sqlx::query_as("SELECT owner,email_hash,application_id,user_id,token_hash,attempts,expires_at,consumed_at FROM password_reset_requests WHERE id = $1 FOR UPDATE")
            .bind(&payload.request_id).fetch_optional(&mut *transaction).await?.ok_or_else(Self::invalid)?;
        if challenge.owner != owner
            || challenge.email_hash != Self::hash(&email)
            || challenge.application_id.as_deref() != application.as_ref().map(|a| a.id.as_str())
            || challenge.attempts >= 5
            || challenge.expires_at <= Utc::now()
            || challenge.consumed_at.is_some()
        {
            return Err(Self::invalid());
        }
        let candidate = Self::hash(payload.code.trim());
        if !bool::from(candidate.as_bytes().ct_eq(challenge.token_hash.as_bytes()))
            || challenge.user_id.is_none()
        {
            sqlx::query("UPDATE password_reset_requests SET attempts = attempts + 1 WHERE id = $1")
                .bind(&payload.request_id)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            return Err(Self::invalid());
        }
        let user_id = challenge.user_id.unwrap();
        let options: Option<serde_json::Value> = sqlx::query_scalar("SELECT o.password_options FROM users u JOIN organizations o ON o.name = u.owner WHERE u.id = $1 AND u.owner = $2 AND lower(u.email) = $3 AND u.is_deleted = false AND u.is_forbidden = false AND o.is_deleted = false FOR UPDATE OF u")
            .bind(&user_id).bind(&owner).bind(&email).fetch_optional(&mut *transaction).await?.ok_or_else(Self::invalid)?;
        CheckService::check_password_complexity(&payload.new_password, options.as_ref())?;
        let password = payload.new_password;
        let hash = tokio::task::spawn_blocking(move || {
            PasswordService::hash_password(&password, "argon2", None)
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
        let now = Utc::now();
        sqlx::query("UPDATE users SET password_hash = $1, password_type = 'argon2', password_salt = NULL, last_change_password_time = $2, need_update_password = false, signin_wrong_times = 0, last_signin_wrong_time = NULL, updated_at = NOW() WHERE id = $3")
            .bind(hash).bind(now.to_rfc3339()).bind(&user_id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE password_reset_requests SET consumed_at = NOW() WHERE user_id = $1 AND consumed_at IS NULL")
            .bind(&user_id).execute(&mut *transaction).await?;
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(&user_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM tokens WHERE user_id = $1")
            .bind(&user_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}
