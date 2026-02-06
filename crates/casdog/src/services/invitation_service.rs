use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{
    CreateInvitationRequest, Invitation, InvitationResponse, UpdateInvitationRequest,
    VerifyInvitationRequest, VerifyInvitationResponse,
};

pub struct InvitationService;

impl InvitationService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<InvitationResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let invitations: Vec<Invitation> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, updated_at, display_name, code, is_regexp,
                       quota, used_count, application, username, email, phone, signup_group,
                       default_code, state
                FROM invitations
                WHERE owner = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, updated_at, display_name, code, is_regexp,
                       quota, used_count, application, username, email, phone, signup_group,
                       default_code, state
                FROM invitations
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
                "#,
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?
        };

        let total: i64 = if let Some(owner) = owner {
            sqlx::query_scalar("SELECT COUNT(*) FROM invitations WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM invitations")
                .fetch_one(pool)
                .await?
        };

        Ok((invitations.into_iter().map(|i| i.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<InvitationResponse> {
        let invitation: Invitation = sqlx::query_as(
            r#"
            SELECT id, owner, name, created_at, updated_at, display_name, code, is_regexp,
                   quota, used_count, application, username, email, phone, signup_group,
                   default_code, state
            FROM invitations
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Invitation not found".to_string()))?;

        Ok(invitation.into())
    }

    pub async fn create(
        pool: &PgPool,
        req: CreateInvitationRequest,
    ) -> AppResult<InvitationResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        // Generate code if not provided
        let code = req.code.unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            (0..8)
                .map(|_| {
                    let idx = rng.gen_range(0..36);
                    if idx < 10 {
                        (b'0' + idx) as char
                    } else {
                        (b'A' + idx - 10) as char
                    }
                })
                .collect()
        });

        sqlx::query(
            r#"
            INSERT INTO invitations (id, owner, name, created_at, updated_at, display_name, code,
                                     is_regexp, quota, used_count, application, username, email,
                                     phone, signup_group, state)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, $10, $11, $12, $13, $14, 'Active')
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(now)
        .bind(now)
        .bind(&req.display_name)
        .bind(&code)
        .bind(req.is_regexp.unwrap_or(false))
        .bind(req.quota.unwrap_or(1))
        .bind(&req.application)
        .bind(&req.username)
        .bind(&req.email)
        .bind(&req.phone)
        .bind(&req.signup_group)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateInvitationRequest,
    ) -> AppResult<InvitationResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE invitations
            SET display_name = COALESCE($1, display_name),
                code = COALESCE($2, code),
                is_regexp = COALESCE($3, is_regexp),
                quota = COALESCE($4, quota),
                application = COALESCE($5, application),
                username = COALESCE($6, username),
                email = COALESCE($7, email),
                phone = COALESCE($8, phone),
                signup_group = COALESCE($9, signup_group),
                state = COALESCE($10, state),
                updated_at = $11
            WHERE id = $12
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.code)
        .bind(req.is_regexp)
        .bind(req.quota)
        .bind(&req.application)
        .bind(&req.username)
        .bind(&req.email)
        .bind(&req.phone)
        .bind(&req.signup_group)
        .bind(&req.state)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM invitations WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Invitation not found".to_string()));
        }

        Ok(())
    }

    pub async fn verify(
        pool: &PgPool,
        req: VerifyInvitationRequest,
    ) -> AppResult<VerifyInvitationResponse> {
        let invitation: Option<Invitation> = sqlx::query_as(
            r#"
            SELECT id, owner, name, created_at, updated_at, display_name, code, is_regexp,
                   quota, used_count, application, username, email, phone, signup_group,
                   default_code, state
            FROM invitations
            WHERE code = $1 AND state = 'Active'
            "#,
        )
        .bind(&req.code)
        .fetch_optional(pool)
        .await?;

        match invitation {
            Some(inv) => {
                // Check if application matches (if specified)
                if let Some(ref app) = req.application {
                    if let Some(ref inv_app) = inv.application {
                        if inv_app != app {
                            return Ok(VerifyInvitationResponse {
                                valid: false,
                                message: Some(
                                    "Invitation code is not valid for this application".to_string(),
                                ),
                            });
                        }
                    }
                }

                // Check quota
                if inv.used_count >= inv.quota {
                    return Ok(VerifyInvitationResponse {
                        valid: false,
                        message: Some("Invitation code has reached its usage limit".to_string()),
                    });
                }

                Ok(VerifyInvitationResponse {
                    valid: true,
                    message: None,
                })
            }
            None => Ok(VerifyInvitationResponse {
                valid: false,
                message: Some("Invalid invitation code".to_string()),
            }),
        }
    }

    pub async fn use_invitation(pool: &PgPool, code: &str) -> AppResult<()> {
        let result = sqlx::query(
            r#"
            UPDATE invitations
            SET used_count = used_count + 1
            WHERE code = $1 AND state = 'Active' AND used_count < quota
            "#,
        )
        .bind(code)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::Validation(
                "Invalid or exhausted invitation code".to_string(),
            ));
        }

        Ok(())
    }
}
