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
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let recovery_codes =
            serde_json::to_string(&Self::generate_recovery_codes(10)).unwrap_or_default();

        let mfa = sqlx::query_as::<_, UserMfa>(
            r#"INSERT INTO user_mfa (id, user_id, mfa_type, secret, recovery_codes, is_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, false, $6, $7)
            ON CONFLICT (user_id, mfa_type) DO UPDATE SET secret = $4, recovery_codes = $5, updated_at = $7
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
        let mfa_records: Vec<UserMfa> =
            sqlx::query_as("SELECT * FROM user_mfa WHERE user_id = $1 AND is_enabled = true")
                .bind(user_id)
                .fetch_all(pool)
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
                            .execute(pool)
                            .await?;
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }
}
