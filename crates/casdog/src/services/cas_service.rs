use sqlx::PgPool;

use crate::error::{AppError, AppResult};
use crate::services::TokenService;

pub struct CasService;

impl CasService {
    /// Generate a CAS service ticket
    pub async fn generate_ticket(
        pool: &PgPool,
        user_id: &str,
        service_url: &str,
    ) -> AppResult<String> {
        let ticket = format!("ST-{}", TokenService::generate_token());
        let now = chrono::Utc::now();
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"INSERT INTO tokens (id, owner, name, created_at, application, organization, user_id,
                code, access_token, expires_in, scope, token_type, code_is_used, code_expire_in, redirect_uri)
            VALUES ($1, 'cas', $2, $3, 'cas', '', $4, $5, '', 0, 'cas', 'Bearer', false, 300, $6)"#,
        )
        .bind(&id)
        .bind(&format!("cas_ticket_{}", id))
        .bind(now)
        .bind(user_id)
        .bind(&ticket)
        .bind(service_url)
        .execute(pool)
        .await?;

        Ok(ticket)
    }

    /// Validate a CAS service ticket
    pub async fn validate_ticket(
        pool: &PgPool,
        ticket: &str,
        service_url: &str,
    ) -> AppResult<CasValidationResult> {
        let token = sqlx::query_as::<_, (String, String, Option<String>, bool)>(
            "SELECT user_id, application, redirect_uri, code_is_used FROM tokens WHERE code = $1",
        )
        .bind(ticket)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::Authentication("Invalid ticket".to_string()))?;

        let (user_id, _app, stored_service, is_used) = token;

        if is_used {
            return Err(AppError::Authentication("Ticket already used".to_string()));
        }

        if let Some(ref stored) = stored_service {
            if stored != service_url {
                return Err(AppError::Authentication("Service URL mismatch".to_string()));
            }
        }

        // Mark ticket as used
        sqlx::query("UPDATE tokens SET code_is_used = true WHERE code = $1")
            .bind(ticket)
            .execute(pool)
            .await?;

        // Get user info
        let user: Option<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT id, name, email FROM users WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(&user_id)
        .fetch_optional(pool)
        .await?;

        match user {
            Some((id, name, email)) => Ok(CasValidationResult {
                valid: true,
                user: Some(name),
                attributes: vec![
                    ("uid".to_string(), id),
                    ("email".to_string(), email.unwrap_or_default()),
                ],
            }),
            None => Err(AppError::NotFound("User not found".to_string())),
        }
    }
}

pub struct CasValidationResult {
    pub valid: bool,
    pub user: Option<String>,
    pub attributes: Vec<(String, String)>,
}
