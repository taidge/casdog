use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreateWebhookRequest, UpdateWebhookRequest, Webhook, WebhookResponse};

pub struct WebhookService;

impl WebhookService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<WebhookResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let webhooks: Vec<Webhook> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, created_at, organization, url, method, content_type,
                       headers, events, is_user_extended, is_enabled
                FROM webhooks
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
                SELECT id, owner, name, created_at, organization, url, method, content_type,
                       headers, events, is_user_extended, is_enabled
                FROM webhooks
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
            sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM webhooks")
                .fetch_one(pool)
                .await?
        };

        Ok((webhooks.into_iter().map(|w| w.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<WebhookResponse> {
        let webhook: Webhook = sqlx::query_as(
            r#"
            SELECT id, owner, name, created_at, organization, url, method, content_type,
                   headers, events, is_user_extended, is_enabled
            FROM webhooks
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

        Ok(webhook.into())
    }

    pub async fn create(pool: &PgPool, req: CreateWebhookRequest) -> AppResult<WebhookResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let events_json = req
            .events
            .map(|e| serde_json::to_string(&e).unwrap_or_default());
        let headers_json = req
            .headers
            .map(|h| serde_json::to_string(&h).unwrap_or_default());

        sqlx::query(
            r#"
            INSERT INTO webhooks (id, owner, name, created_at, organization, url, method, content_type,
                                  headers, events, is_user_extended, is_enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(now)
        .bind(&req.organization)
        .bind(&req.url)
        .bind(req.method.as_deref().unwrap_or("POST"))
        .bind(req.content_type.as_deref().unwrap_or("application/json"))
        .bind(&headers_json)
        .bind(&events_json)
        .bind(req.is_user_extended.unwrap_or(false))
        .bind(req.is_enabled.unwrap_or(true))
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateWebhookRequest,
    ) -> AppResult<WebhookResponse> {
        let events_json = req
            .events
            .map(|e| serde_json::to_string(&e).unwrap_or_default());
        let headers_json = req
            .headers
            .map(|h| serde_json::to_string(&h).unwrap_or_default());

        sqlx::query(
            r#"
            UPDATE webhooks
            SET url = COALESCE($1, url),
                method = COALESCE($2, method),
                content_type = COALESCE($3, content_type),
                headers = COALESCE($4, headers),
                events = COALESCE($5, events),
                is_user_extended = COALESCE($6, is_user_extended),
                is_enabled = COALESCE($7, is_enabled)
            WHERE id = $8
            "#,
        )
        .bind(&req.url)
        .bind(&req.method)
        .bind(&req.content_type)
        .bind(&headers_json)
        .bind(&events_json)
        .bind(req.is_user_extended)
        .bind(req.is_enabled)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM webhooks WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Webhook not found".to_string()));
        }

        Ok(())
    }
}
