use crate::error::{AppError, AppResult};
use crate::models::{CaptchaResponse, VerificationResponse, VerifyCodeResponse};
use sqlx::PgPool;
use rand::Rng;
use uuid::Uuid;

pub struct VerificationService;

impl VerificationService {
    pub async fn send_verification_code(
        pool: &PgPool,
        owner: &str,
        dest: &str,
        dest_type: &str, // email or phone
    ) -> AppResult<VerificationResponse> {
        // Generate a 6-digit code
        let code: String = {
            let mut rng = rand::thread_rng();
            (0..6).map(|_| rng.gen_range(0..10).to_string()).collect()
        };

        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        // Store the verification code
        sqlx::query(
            r#"
            INSERT INTO verifications (id, owner, name, created_at, "type", "user", provider, receiver, code, is_used)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false)
            "#,
        )
        .bind(&id)
        .bind(owner)
        .bind(&format!("verification_{}", id))
        .bind(now)
        .bind(dest_type)
        .bind(owner)
        .bind("default")
        .bind(dest)
        .bind(&code)
        .execute(pool)
        .await?;

        // In production, send the code via email/SMS here
        Ok(VerificationResponse {
            id,
            owner: owner.to_string(),
            created_at: now,
            verification_type: dest_type.to_string(),
            user: owner.to_string(),
            receiver: dest.to_string(),
            is_used: false,
        })
    }

    pub async fn verify_code(
        pool: &PgPool,
        dest: &str,
        code: &str,
    ) -> AppResult<VerifyCodeResponse> {
        let verification: Option<(String, bool)> = sqlx::query_as(
            r#"
            SELECT id, is_used
            FROM verifications
            WHERE receiver = $1 AND code = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(dest)
        .bind(code)
        .fetch_optional(pool)
        .await?;

        match verification {
            Some((id, is_used)) => {
                if is_used {
                    return Ok(VerifyCodeResponse {
                        success: false,
                        message: "Code has already been used".to_string(),
                    });
                }

                // Mark the code as used
                sqlx::query("UPDATE verifications SET is_used = true WHERE id = $1")
                    .bind(&id)
                    .execute(pool)
                    .await?;

                Ok(VerifyCodeResponse {
                    success: true,
                    message: "Code verified successfully".to_string(),
                })
            }
            None => Ok(VerifyCodeResponse {
                success: false,
                message: "Invalid verification code".to_string(),
            }),
        }
    }

    pub fn generate_captcha() -> AppResult<CaptchaResponse> {
        let captcha_id = Uuid::new_v4().to_string();

        // In production, generate actual captcha image
        // For now, return a placeholder
        let captcha_image = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==".to_string();

        Ok(CaptchaResponse {
            captcha_id,
            captcha_image,
        })
    }

    pub fn verify_captcha(
        _captcha_id: &str,
        _captcha_code: &str,
    ) -> AppResult<bool> {
        // In production, validate against stored captcha
        Ok(true)
    }

    pub async fn get_email_and_phone(
        pool: &PgPool,
        username: &str,
        _organization: &str,
    ) -> AppResult<(Option<String>, Option<String>)> {
        let user: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT email, phone FROM users WHERE name = $1",
        )
        .bind(username)
        .fetch_optional(pool)
        .await?;

        match user {
            Some((email, phone)) => Ok((email, phone)),
            None => Err(AppError::NotFound("User not found".to_string())),
        }
    }
}
