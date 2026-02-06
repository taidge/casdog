use crate::error::{AppError, AppResult};
use crate::models::{CasbinAdapter, CasbinAdapterResponse, CreateCasbinAdapterRequest, UpdateCasbinAdapterRequest};
use sqlx::PgPool;
use uuid::Uuid;

pub struct AdapterService;

impl AdapterService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<CasbinAdapterResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let adapters: Vec<CasbinAdapter> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, description, adapter_type,
                       host, database_type, is_enabled, created_at, updated_at
                FROM casbin_adapters
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
                SELECT id, owner, name, display_name, description, adapter_type,
                       host, database_type, is_enabled, created_at, updated_at
                FROM casbin_adapters
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
            sqlx::query_scalar("SELECT COUNT(*) FROM casbin_adapters WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM casbin_adapters")
                .fetch_one(pool)
                .await?
        };

        Ok((adapters.into_iter().map(|a| a.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<CasbinAdapterResponse> {
        let adapter: CasbinAdapter = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, description, adapter_type,
                   host, database_type, is_enabled, created_at, updated_at
            FROM casbin_adapters
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Casbin adapter not found".to_string()))?;

        Ok(adapter.into())
    }

    pub async fn create(pool: &PgPool, req: CreateCasbinAdapterRequest) -> AppResult<CasbinAdapterResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let adapter_type = req.adapter_type.unwrap_or_else(|| "database".to_string());
        let is_enabled = req.is_enabled.unwrap_or(true);

        sqlx::query(
            r#"
            INSERT INTO casbin_adapters (id, owner, name, display_name, description, adapter_type,
                                         host, database_type, is_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&adapter_type)
        .bind(&req.host)
        .bind(&req.database_type)
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
        req: UpdateCasbinAdapterRequest,
    ) -> AppResult<CasbinAdapterResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE casbin_adapters
            SET display_name = COALESCE($1, display_name),
                description = COALESCE($2, description),
                adapter_type = COALESCE($3, adapter_type),
                host = COALESCE($4, host),
                database_type = COALESCE($5, database_type),
                is_enabled = COALESCE($6, is_enabled),
                updated_at = $7
            WHERE id = $8
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.adapter_type)
        .bind(&req.host)
        .bind(&req.database_type)
        .bind(req.is_enabled)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM casbin_adapters WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Casbin adapter not found".to_string()));
        }

        Ok(())
    }
}
