//! Durable OAuth browser proofs shared by every instance using the same PostgreSQL.
//! Raw nonces never enter persisted rows. Binding failures do not consume valid flows.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

use crate::error::{AppError, AppResult};

pub const FLOW_TTL_SECONDS: u32 = 300;
pub const COMPLETION_TTL_SECONDS: u32 = 300;
pub const MAX_COMPLETION_ATTEMPTS: i32 = 5;
const MAX_PENDING_GLOBAL: i64 = 10_000;
const MAX_PENDING_PER_ORGANIZATION: i64 = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOAuthFlow {
    pub provider_id: String,
    pub provider_name: String,
    pub application_id: String,
    pub organization: String,
    pub redirect_uri: String,
    pub purpose: String,
    pub context: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OAuthFlow {
    pub provider_id: String,
    pub provider_name: String,
    pub application_id: String,
    pub organization: String,
    pub redirect_uri: String,
    pub purpose: String,
    pub context: Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewCompletion {
    pub user_id: String,
    pub provider_id: String,
    pub provider_name: String,
    pub application_id: String,
    pub organization: String,
    pub context: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Completion {
    pub user_id: String,
    pub provider_id: String,
    pub provider_name: String,
    pub application_id: String,
    pub organization: String,
    pub context: Value,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

fn nonce() -> String {
    let mut value = [0u8; 32];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

pub fn proof_hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn invalid() -> AppError {
    AppError::Authentication("OAuth proof is invalid, expired or already used".into())
}

fn valid_nonce(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

async fn reserve_capacity(
    tx: &mut Transaction<'_, Postgres>,
    organization: &str,
    completion: bool,
) -> AppResult<()> {
    // A database-wide lock bounds counts even when multiple instances create concurrently.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(if completion {
            "casdog-social-completion-capacity"
        } else {
            "casdog-social-flow-capacity"
        })
        .execute(&mut **tx)
        .await?;
    let table = if completion {
        "social_oauth_completions"
    } else {
        "social_oauth_flows"
    };
    sqlx::query(&format!(
        "DELETE FROM {table} WHERE expires_at <= clock_timestamp()"
    ))
    .execute(&mut **tx)
    .await?;
    let (global, local): (i64, i64) = sqlx::query_as(&format!(
        "SELECT COUNT(*),COUNT(*) FILTER(WHERE organization=$1) FROM {table}"
    ))
    .bind(organization)
    .fetch_one(&mut **tx)
    .await?;
    if global >= MAX_PENDING_GLOBAL || local >= MAX_PENDING_PER_ORGANIZATION {
        return Err(AppError::Validation(
            "Too many pending OAuth requests; retry later".into(),
        ));
    }
    Ok(())
}

pub async fn create_flow(pool: &PgPool, flow: &NewOAuthFlow) -> AppResult<(String, String)> {
    if !matches!(flow.purpose.as_str(), "signin" | "link") || !flow.context.is_object() {
        return Err(AppError::Validation(
            "Invalid OAuth flow purpose or context".into(),
        ));
    }
    let state = nonce();
    let browser = nonce();
    let mut tx = pool.begin().await?;
    reserve_capacity(&mut tx, &flow.organization, false).await?;
    sqlx::query("INSERT INTO social_oauth_flows(state_hash,browser_hash,provider_id,provider_name,application_id,organization,redirect_uri,purpose,context) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(proof_hash(&state)).bind(proof_hash(&browser)).bind(&flow.provider_id).bind(&flow.provider_name)
        .bind(&flow.application_id).bind(&flow.organization).bind(&flow.redirect_uri).bind(&flow.purpose).bind(&flow.context)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((state, browser))
}

pub async fn consume_flow(
    pool: &PgPool,
    state: &str,
    browser: &str,
    provider_name: &str,
) -> AppResult<OAuthFlow> {
    if !valid_nonce(state) || !valid_nonce(browser) {
        return Err(invalid());
    }
    sqlx::query_as("DELETE FROM social_oauth_flows WHERE state_hash=$1 AND browser_hash=$2 AND provider_name=$3 AND expires_at>clock_timestamp() RETURNING provider_id,provider_name,application_id,organization,redirect_uri,purpose,context,created_at,expires_at")
        .bind(proof_hash(state)).bind(proof_hash(browser)).bind(provider_name)
        .fetch_optional(pool).await?.ok_or_else(invalid)
}

pub async fn create_completion(pool: &PgPool, completion: &NewCompletion) -> AppResult<String> {
    if !completion.context.is_object() {
        return Err(AppError::Validation(
            "Invalid OAuth completion context".into(),
        ));
    }
    let secret = nonce();
    let mut tx = pool.begin().await?;
    reserve_capacity(&mut tx, &completion.organization, true).await?;
    sqlx::query("INSERT INTO social_oauth_completions(secret_hash,user_id,provider_id,provider_name,application_id,organization,context) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(proof_hash(&secret)).bind(&completion.user_id).bind(&completion.provider_id).bind(&completion.provider_name)
        .bind(&completion.application_id).bind(&completion.organization).bind(&completion.context)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(secret)
}

pub async fn load_completion(pool: &PgPool, secret: &str) -> AppResult<Completion> {
    if !valid_nonce(secret) {
        return Err(invalid());
    }
    sqlx::query_as("SELECT user_id,provider_id,provider_name,application_id,organization,context,attempts,created_at,expires_at FROM social_oauth_completions WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND attempts<5")
        .bind(proof_hash(secret)).fetch_optional(pool).await?.ok_or_else(invalid)
}

pub async fn consume_completion(pool: &PgPool, secret: &str) -> AppResult<Completion> {
    if !valid_nonce(secret) {
        return Err(invalid());
    }
    sqlx::query_as("DELETE FROM social_oauth_completions WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND attempts<5 RETURNING user_id,provider_id,provider_name,application_id,organization,context,attempts,created_at,expires_at")
        .bind(proof_hash(secret)).fetch_optional(pool).await?.ok_or_else(invalid)
}

/// A failed MFA proof uses a budget stored in the same database as the challenge.
/// Saturation cannot wrap, and exhausted rows cannot be loaded or consumed.
pub async fn record_failure(pool: &PgPool, secret: &str) -> AppResult<()> {
    if !valid_nonce(secret) {
        return Err(invalid());
    }
    let result = sqlx::query("UPDATE social_oauth_completions SET attempts=attempts+1 WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND attempts<5")
        .bind(proof_hash(secret)).execute(pool).await?;
    if result.rows_affected() != 1 {
        return Err(invalid());
    }
    Ok(())
}

/// Lock a completion inside the caller's transaction before checking an MFA proof.
/// Keep proof verification, failure accounting and final consumption in this transaction.
pub async fn load_completion_for_update(
    conn: &mut PgConnection,
    secret: &str,
) -> AppResult<Completion> {
    if !valid_nonce(secret) {
        return Err(invalid());
    }
    let completion: Completion = sqlx::query_as("SELECT user_id,provider_id,provider_name,application_id,organization,context,attempts,created_at,expires_at FROM social_oauth_completions WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND attempts<5 FOR UPDATE")
        .bind(proof_hash(secret)).fetch_optional(&mut *conn).await?.ok_or_else(invalid)?;
    // A lock may have waited past the deadline. Check the database clock again
    // after acquiring it; transaction-start NOW() is not an expiry clock.
    let active: bool = sqlx::query_scalar("SELECT $1::timestamptz > clock_timestamp()")
        .bind(completion.expires_at)
        .fetch_one(conn)
        .await?;
    if !active {
        return Err(invalid());
    }
    Ok(completion)
}

pub async fn consume_completion_conn(
    conn: &mut PgConnection,
    secret: &str,
) -> AppResult<Completion> {
    if !valid_nonce(secret) {
        return Err(invalid());
    }
    sqlx::query_as("DELETE FROM social_oauth_completions WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND attempts<5 RETURNING user_id,provider_id,provider_name,application_id,organization,context,attempts,created_at,expires_at")
        .bind(proof_hash(secret)).fetch_optional(conn).await?.ok_or_else(invalid)
}

pub async fn record_failure_conn(conn: &mut PgConnection, secret: &str) -> AppResult<()> {
    if !valid_nonce(secret) {
        return Err(invalid());
    }
    let result = sqlx::query("UPDATE social_oauth_completions SET attempts=attempts+1 WHERE secret_hash=$1 AND expires_at>clock_timestamp() AND attempts<5")
        .bind(proof_hash(secret)).execute(conn).await?;
    if result.rows_affected() != 1 {
        return Err(invalid());
    }
    Ok(())
}
