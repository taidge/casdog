use crate::error::{AppError, AppResult};
use crate::models::{CasbinModel, CasbinModelResponse, CreateCasbinModelRequest, UpdateCasbinModelRequest};
use sqlx::PgPool;
use uuid::Uuid;

pub struct ModelService;

impl ModelService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<CasbinModelResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let models: Vec<CasbinModel> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, description, model_text,
                       is_enabled, created_at, updated_at
                FROM casbin_models
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
                SELECT id, owner, name, display_name, description, model_text,
                       is_enabled, created_at, updated_at
                FROM casbin_models
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
            sqlx::query_scalar("SELECT COUNT(*) FROM casbin_models WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM casbin_models")
                .fetch_one(pool)
                .await?
        };

        Ok((models.into_iter().map(|m| m.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<CasbinModelResponse> {
        let model: CasbinModel = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, description, model_text,
                   is_enabled, created_at, updated_at
            FROM casbin_models
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Casbin model not found".to_string()))?;

        Ok(model.into())
    }

    pub async fn create(pool: &PgPool, req: CreateCasbinModelRequest) -> AppResult<CasbinModelResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let is_enabled = req.is_enabled.unwrap_or(true);

        sqlx::query(
            r#"
            INSERT INTO casbin_models (id, owner, name, display_name, description, model_text,
                                       is_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.model_text)
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
        req: UpdateCasbinModelRequest,
    ) -> AppResult<CasbinModelResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE casbin_models
            SET display_name = COALESCE($1, display_name),
                description = COALESCE($2, description),
                model_text = COALESCE($3, model_text),
                is_enabled = COALESCE($4, is_enabled),
                updated_at = $5
            WHERE id = $6
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.model_text)
        .bind(req.is_enabled)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM casbin_models WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Casbin model not found".to_string()));
        }

        Ok(())
    }
}
