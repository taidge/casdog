use crate::error::{AppError, AppResult};
use crate::models::{CasbinEnforcer, CasbinEnforcerResponse, CreateCasbinEnforcerRequest, UpdateCasbinEnforcerRequest};
use sqlx::PgPool;
use uuid::Uuid;

pub struct EnforcerService;

impl EnforcerService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<CasbinEnforcerResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let enforcers: Vec<CasbinEnforcer> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, description, model_id,
                       adapter_id, is_enabled, created_at, updated_at
                FROM casbin_enforcers
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
                SELECT id, owner, name, display_name, description, model_id,
                       adapter_id, is_enabled, created_at, updated_at
                FROM casbin_enforcers
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
            sqlx::query_scalar("SELECT COUNT(*) FROM casbin_enforcers WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM casbin_enforcers")
                .fetch_one(pool)
                .await?
        };

        Ok((enforcers.into_iter().map(|e| e.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<CasbinEnforcerResponse> {
        let enforcer: CasbinEnforcer = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, description, model_id,
                   adapter_id, is_enabled, created_at, updated_at
            FROM casbin_enforcers
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Casbin enforcer not found".to_string()))?;

        Ok(enforcer.into())
    }

    pub async fn create(pool: &PgPool, req: CreateCasbinEnforcerRequest) -> AppResult<CasbinEnforcerResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let is_enabled = req.is_enabled.unwrap_or(true);

        sqlx::query(
            r#"
            INSERT INTO casbin_enforcers (id, owner, name, display_name, description, model_id,
                                          adapter_id, is_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.model_id)
        .bind(&req.adapter_id)
        .bind(is_enabled)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateCasbinEnforcerRequest,
    ) -> AppResult<CasbinEnforcerResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE casbin_enforcers
            SET display_name = COALESCE($1, display_name),
                description = COALESCE($2, description),
                model_id = COALESCE($3, model_id),
                adapter_id = COALESCE($4, adapter_id),
                is_enabled = COALESCE($5, is_enabled),
                updated_at = $6
            WHERE id = $7
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.model_id)
        .bind(&req.adapter_id)
        .bind(req.is_enabled)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM casbin_enforcers WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Casbin enforcer not found".to_string()));
        }

        Ok(())
    }
}
