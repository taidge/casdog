use crate::error::{AppError, AppResult};
use crate::models::{CreateResourceRequest, Resource, ResourceResponse, UpdateResourceRequest};
use sqlx::PgPool;
use uuid::Uuid;

pub struct ResourceService;

impl ResourceService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<ResourceResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let resources: Vec<Resource> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, "user", provider, application,
                       tag, parent, file_name, file_type, file_format, file_size, url, description
                FROM resources
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
                SELECT id, owner, name, created_at, "user", provider, application,
                       tag, parent, file_name, file_type, file_format, file_size, url, description
                FROM resources
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
            sqlx::query_scalar("SELECT COUNT(*) FROM resources WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM resources")
                .fetch_one(pool)
                .await?
        };

        Ok((resources.into_iter().map(|r| r.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<ResourceResponse> {
        let resource: Resource = sqlx::query_as(
            r#"
            SELECT id, owner, name, created_at, "user", provider, application,
                   tag, parent, file_name, file_type, file_format, file_size, url, description
            FROM resources
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Resource not found".to_string()))?;

        Ok(resource.into())
    }

    pub async fn create(pool: &PgPool, req: CreateResourceRequest) -> AppResult<ResourceResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO resources (id, owner, name, created_at, "user", provider, application,
                                   tag, parent, file_name, file_type, file_format, file_size, url, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(now)
        .bind(&req.user)
        .bind(&req.provider)
        .bind(&req.application)
        .bind(&req.tag)
        .bind(&req.parent)
        .bind(&req.file_name)
        .bind(&req.file_type)
        .bind(&req.file_format)
        .bind(req.file_size)
        .bind(&req.url)
        .bind(&req.description)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateResourceRequest,
    ) -> AppResult<ResourceResponse> {
        sqlx::query(
            r#"
            UPDATE resources
            SET tag = COALESCE($1, tag),
                description = COALESCE($2, description)
            WHERE id = $3
            "#,
        )
        .bind(&req.tag)
        .bind(&req.description)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM resources WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Resource not found".to_string()));
        }

        Ok(())
    }
}
