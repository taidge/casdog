use chrono::Utc;
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

pub struct MfaService;

#[derive(Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct UserMfa {
    pub id: String,
    pub user_id: String,
    pub mfa_type: String,
    pub secret: Option<String>,
    pub recovery_codes: Option<String>,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

impl MfaService {
    /// Enumerate factors from the same records used by the enrollment API.
    pub async fn login_methods(
        pool: &PgPool,
        user: &crate::models::User,
    ) -> AppResult<Vec<String>> {
        let records: Vec<UserMfa> =
            sqlx::query_as("SELECT * FROM user_mfa WHERE user_id = $1 AND is_enabled = true")
                .bind(&user.id)
                .fetch_all(pool)
                .await?;
        let mut methods = Vec::new();
        if (user.mfa_enabled && user.totp_secret.as_ref().is_some_and(|s| !s.is_empty()))
            || records
                .iter()
                .any(|m| matches!(m.mfa_type.as_str(), "totp" | "app"))
        {
            methods.push("app".to_string());
        }
        if user.mfa_phone_enabled {
            methods.push("sms".to_string());
        }
        if user.mfa_email_enabled {
            methods.push("email".to_string());
        }
        if records
            .iter()
            .any(|m| m.recovery_codes.as_ref().is_some_and(|s| s != "[]"))
        {
            methods.push("recovery".to_string());
        }
        Ok(methods)
    }

    /// Verify an enrolled factor before issuing a session or authorization code.
    pub async fn verify_login(
        pool: &PgPool,
        user: &crate::models::User,
        method: Option<&str>,
        code: &str,
    ) -> AppResult<bool> {
        if code.trim().is_empty() {
            return Ok(false);
        }
        let method = method
            .or(user.preferred_mfa_type.as_deref())
            .unwrap_or("app");
        match method {
            "app" | "totp" => {
                for kind in ["totp", "app"] {
                    if let Some(mfa) = Self::get_user_mfa(pool, &user.id, kind).await? {
                        if mfa.is_enabled {
                            if let Some(secret) = mfa.secret {
                                return Self::verify_totp(&secret, code);
                            }
                        }
                    }
                }
                match user.totp_secret.as_deref().filter(|s| !s.is_empty()) {
                    Some(secret) if user.mfa_enabled => Self::verify_totp(secret, code),
                    _ => Ok(false),
                }
            }
            "recovery" => Self::verify_recovery_code(pool, &user.id, code).await,
            "sms" | "email" => {
                let receiver = match method {
                    "sms" if user.mfa_phone_enabled => user.phone.as_deref(),
                    "email" if user.mfa_email_enabled => user.email.as_deref(),
                    _ => None,
                };
                let Some(receiver) = receiver.filter(|r| !r.is_empty()) else {
                    return Ok(false);
                };
                // Consume exactly one unexpired code belonging to this account. The
                // row predicate is rechecked after concurrent UPDATEs acquire its lock.
                let result = sqlx::query(
                    "UPDATE verifications SET is_used = true WHERE id = (SELECT id FROM verifications WHERE owner = $1 AND user_id = $2 AND receiver = $3 AND code = $4 AND type = $5 AND is_used = false AND created_at > NOW() - INTERVAL '5 minutes' ORDER BY created_at DESC LIMIT 1) AND is_used = false")
                    .bind(&user.owner).bind(&user.id).bind(receiver).bind(code)
                    .bind(if method == "sms" { "phone" } else { "email" })
                    .execute(pool).await?;
                Ok(result.rows_affected() == 1)
            }
            _ => Ok(false),
        }
    }

    /// Initiate TOTP setup - generates secret and returns QR code URL
    pub fn initiate_totp_setup(user_name: &str, issuer: &str) -> AppResult<(String, String)> {
        use totp_rs::{Algorithm, Secret, TOTP};

        let secret = Secret::generate_secret();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret
                .to_bytes()
                .map_err(|e| AppError::Internal(format!("TOTP secret error: {}", e)))?,
            Some(issuer.to_string()),
            user_name.to_string(),
        )
        .map_err(|e| AppError::Internal(format!("TOTP creation error: {}", e)))?;

        let qr_url = totp.get_url();
        let secret_base32 = secret.to_encoded().to_string();

        Ok((secret_base32, qr_url))
    }

    /// Verify a TOTP code
    pub fn verify_totp(secret_base32: &str, code: &str) -> AppResult<bool> {
        use totp_rs::{Algorithm, Secret, TOTP};

        let secret = Secret::Encoded(secret_base32.to_string());
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret
                .to_bytes()
                .map_err(|e| AppError::Internal(format!("TOTP secret error: {}", e)))?,
            None,
            "user".to_string(),
        )
        .map_err(|e| AppError::Internal(format!("TOTP creation error: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(totp.check(code, now))
    }

    /// Generate recovery codes
    pub fn generate_recovery_codes(count: usize) -> Vec<String> {
        let mut rng = rand::thread_rng();
        (0..count)
            .map(|_| {
                let code: String = (0..8)
                    .map(|_| {
                        let idx = rng.gen_range(0..36);
                        if idx < 10 {
                            (b'0' + idx) as char
                        } else {
                            (b'a' + idx - 10) as char
                        }
                    })
                    .collect();
                code
            })
            .collect()
    }

    /// Save MFA setup to database
    pub async fn save_mfa(
        pool: &PgPool,
        user_id: &str,
        mfa_type: &str,
        secret: Option<&str>,
    ) -> AppResult<UserMfa> {
        if Self::get_user_mfa(pool, user_id, mfa_type)
            .await?
            .is_some_and(|mfa| mfa.is_enabled)
        {
            return Err(AppError::Conflict(
                "Disable the existing MFA factor before replacing it".to_string(),
            ));
        }
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let recovery_codes =
            serde_json::to_string(&Self::generate_recovery_codes(10)).unwrap_or_default();

        let mfa = sqlx::query_as::<_, UserMfa>(
            r#"INSERT INTO user_mfa (id, user_id, mfa_type, secret, recovery_codes, is_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, false, $6, $7)
            ON CONFLICT (user_id, mfa_type) DO UPDATE SET secret = $4, recovery_codes = $5, updated_at = $7 WHERE user_mfa.is_enabled = false
            RETURNING *"#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(mfa_type)
        .bind(secret)
        .bind(&recovery_codes)
        .bind(now)
        .bind(now)
        .fetch_one(pool)
        .await?;

        Ok(mfa)
    }

    /// Lock enrollment while checking proof so concurrent setup cannot swap the secret.
    pub async fn confirm_setup(
        pool: &PgPool,
        user_id: &str,
        mfa_type: &str,
        code: &str,
    ) -> AppResult<Option<UserMfa>> {
        if !matches!(mfa_type, "totp" | "app") {
            return Err(AppError::Validation("TOTP setup required".to_string()));
        }
        let mut transaction = pool.begin().await?;
        // Social completion locks the account before its factors. Use the same
        // order here so enrollment cannot hold a factor while waiting on a
        // social login that already holds this account.
        sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
        let mfa: UserMfa = sqlx::query_as(
            "SELECT * FROM user_mfa WHERE user_id = $1 AND mfa_type = $2 FOR UPDATE",
        )
        .bind(user_id)
        .bind(mfa_type)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| AppError::NotFound("Initiate MFA setup first".to_string()))?;
        let secret = mfa
            .secret
            .as_deref()
            .ok_or_else(|| AppError::Validation("MFA secret missing".to_string()))?;
        if !Self::verify_totp(secret, code)? {
            return Ok(None);
        }
        sqlx::query("UPDATE user_mfa SET is_enabled = true, updated_at = NOW() WHERE id = $1")
            .bind(&mfa.id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("UPDATE users SET mfa_enabled = true, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(Some(mfa))
    }

    /// Enable MFA after verification
    pub async fn enable_mfa(pool: &PgPool, user_id: &str, mfa_type: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE user_mfa SET is_enabled = true, updated_at = $1 WHERE user_id = $2 AND mfa_type = $3"
        )
        .bind(Utc::now())
        .bind(user_id)
        .bind(mfa_type)
        .execute(pool)
        .await?;

        // Update user's mfa_enabled flag
        sqlx::query("UPDATE users SET mfa_enabled = true, updated_at = $1 WHERE id = $2")
            .bind(Utc::now())
            .bind(user_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Delete MFA for a user
    pub async fn delete_mfa(pool: &PgPool, user_id: &str, mfa_type: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM user_mfa WHERE user_id = $1 AND mfa_type = $2")
            .bind(user_id)
            .bind(mfa_type)
            .execute(pool)
            .await?;

        // Check if user has any remaining MFA
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_mfa WHERE user_id = $1 AND is_enabled = true",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        if count.0 == 0 {
            sqlx::query("UPDATE users SET mfa_enabled = false, updated_at = $1 WHERE id = $2")
                .bind(Utc::now())
                .bind(user_id)
                .execute(pool)
                .await?;
        }

        Ok(())
    }

    /// Get MFA record for a user
    pub async fn get_user_mfa(
        pool: &PgPool,
        user_id: &str,
        mfa_type: &str,
    ) -> AppResult<Option<UserMfa>> {
        let mfa = sqlx::query_as::<_, UserMfa>(
            "SELECT * FROM user_mfa WHERE user_id = $1 AND mfa_type = $2",
        )
        .bind(user_id)
        .bind(mfa_type)
        .fetch_optional(pool)
        .await?;

        Ok(mfa)
    }

    /// Check if user has MFA enabled
    pub async fn is_mfa_enabled(pool: &PgPool, user_id: &str) -> AppResult<bool> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_mfa WHERE user_id = $1 AND is_enabled = true",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    /// Verify recovery code
    pub async fn verify_recovery_code(pool: &PgPool, user_id: &str, code: &str) -> AppResult<bool> {
        let mut transaction = pool.begin().await?;
        let mfa_records: Vec<UserMfa> =
            sqlx::query_as("SELECT * FROM user_mfa WHERE user_id = $1 AND is_enabled = true ORDER BY id FOR UPDATE")
                .bind(user_id)
                .fetch_all(&mut *transaction)
                .await?;

        for mfa in &mfa_records {
            if let Some(ref codes_json) = mfa.recovery_codes {
                if let Ok(mut codes) = serde_json::from_str::<Vec<String>>(codes_json) {
                    if let Some(pos) = codes.iter().position(|c| c == code) {
                        codes.remove(pos);
                        let new_codes = serde_json::to_string(&codes).unwrap_or_default();
                        sqlx::query("UPDATE user_mfa SET recovery_codes = $1, updated_at = $2 WHERE id = $3")
                            .bind(&new_codes)
                            .bind(Utc::now())
                            .bind(&mfa.id)
                            .execute(&mut *transaction)
                            .await?;
                        transaction.commit().await?;
                        return Ok(true);
                    }
                }
            }
        }

        transaction.commit().await?;
        Ok(false)
    }
}
