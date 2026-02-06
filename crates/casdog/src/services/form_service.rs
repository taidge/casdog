use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreateFormRequest, Form, FormResponse, UpdateFormRequest};

pub struct FormService;

impl FormService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<FormResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let forms: Vec<Form> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, form_items, is_enabled, is_deleted,
                       created_at, updated_at
                FROM forms
                WHERE owner = $1 AND is_deleted = false
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
                SELECT id, owner, name, display_name, form_items, is_enabled, is_deleted,
                       created_at, updated_at
                FROM forms
                WHERE is_deleted = false
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
            sqlx::query_scalar("SELECT COUNT(*) FROM forms WHERE owner = $1 AND is_deleted = false")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM forms WHERE is_deleted = false")
                .fetch_one(pool)
                .await?
        };

        Ok((forms.into_iter().map(|f| f.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<FormResponse> {
        let form: Form = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, form_items, is_enabled, is_deleted,
                   created_at, updated_at
            FROM forms
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Form not found".to_string()))?;

        Ok(form.into())
    }

    pub async fn create(pool: &PgPool, req: CreateFormRequest) -> AppResult<FormResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO forms (id, owner, name, display_name, form_items, is_enabled,
                               is_deleted, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.form_items)
        .bind(req.is_enabled.unwrap_or(true))
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateFormRequest,
    ) -> AppResult<FormResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE forms
            SET display_name = COALESCE($1, display_name),
                form_items = COALESCE($2, form_items),
                is_enabled = COALESCE($3, is_enabled),
                updated_at = $4
            WHERE id = $5 AND is_deleted = false
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.form_items)
        .bind(req.is_enabled)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM forms WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Form not found".to_string()));
        }

        Ok(())
    }
}
