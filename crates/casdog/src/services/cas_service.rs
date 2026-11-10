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
        Self::store_cas_ticket(pool, "ST", user_id, service_url, "cas").await
    }

    pub async fn generate_proxy_granting_ticket(
        pool: &PgPool,
        validation: &CasValidationResult,
        issued_service: &str,
    ) -> AppResult<CasProxyGrant> {
        let user_id = validation
            .user_id
            .as_deref()
            .ok_or_else(|| AppError::Authentication("CAS validation has no user".to_string()))?;
        let pgt_id = format!("PGT-{}", TokenService::generate_token());
        let pgt_iou = format!("PGTIOU-{}", TokenService::generate_token());
        let now = chrono::Utc::now();
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"INSERT INTO tokens (id, owner, name, created_at, application, organization, user_id,
                code, access_token, expires_in, scope, token_type, code_is_used, code_expire_in, redirect_uri)
            VALUES ($1, 'cas', $2, $3, 'cas', '', $4, $5, $6, 7200, 'cas_pgt', 'Bearer', false, 7200, $7)"#,
        )
        .bind(&id)
        .bind(format!("cas_pgt_{}", id))
        .bind(now)
        .bind(user_id)
        .bind(&pgt_id)
        .bind(&pgt_iou)
        .bind(issued_service)
        .execute(pool)
        .await?;

        Ok(CasProxyGrant { pgt_id, pgt_iou })
    }

    pub async fn generate_proxy_ticket(
        pool: &PgPool,
        pgt: &str,
        target_service: &str,
    ) -> AppResult<String> {
        let user_id: String = sqlx::query_scalar(
            r#"
            SELECT user_id
            FROM tokens
            WHERE code = $1 AND scope = 'cas_pgt' AND code_is_used = false
            "#,
        )
        .bind(pgt)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::Authorization("service not authorized".to_string()))?;

        Self::store_cas_ticket(pool, "PT", &user_id, target_service, "cas_pt").await
    }

    async fn store_cas_ticket(
        pool: &PgPool,
        prefix: &str,
        user_id: &str,
        service_url: &str,
        scope: &str,
    ) -> AppResult<String> {
        let ticket = format!("{}-{}", prefix, TokenService::generate_token());
        let now = chrono::Utc::now();
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"INSERT INTO tokens (id, owner, name, created_at, application, organization, user_id,
                code, access_token, expires_in, scope, token_type, code_is_used, code_expire_in, redirect_uri)
            VALUES ($1, 'cas', $2, $3, 'cas', '', $4, $5, '', 0, $6, 'Bearer', false, 300, $7)"#,
        )
        .bind(&id)
        .bind(format!("cas_{}_{}", prefix.to_ascii_lowercase(), id))
        .bind(now)
        .bind(user_id)
        .bind(&ticket)
        .bind(scope)
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
            let decoded = urlencoding::decode(service_url)
                .map(|value| value.into_owned())
                .unwrap_or_else(|_| service_url.to_string());
            if !service_url.starts_with(stored) && !decoded.starts_with(stored) {
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
                user_id: Some(id.clone()),
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
    pub user_id: Option<String>,
    pub attributes: Vec<(String, String)>,
}

pub struct CasProxyGrant {
    pub pgt_id: String,
    pub pgt_iou: String,
}
