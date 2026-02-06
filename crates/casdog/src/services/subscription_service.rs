use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{
    CreateSubscriptionRequest, Subscription, SubscriptionResponse, UpdateSubscriptionRequest,
};

pub struct SubscriptionService;

impl SubscriptionService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<SubscriptionResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let subscriptions: Vec<Subscription> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, description, user_id, plan_id, pricing_id,
                       start_date, end_date, period, state, is_deleted, created_at, updated_at
                FROM subscriptions
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
                SELECT id, owner, name, display_name, description, user_id, plan_id, pricing_id,
                       start_date, end_date, period, state, is_deleted, created_at, updated_at
                FROM subscriptions
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
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM subscriptions WHERE owner = $1 AND is_deleted = false",
            )
            .bind(owner)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions WHERE is_deleted = false")
                .fetch_one(pool)
                .await?
        };

        Ok((subscriptions.into_iter().map(|s| s.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<SubscriptionResponse> {
        let subscription: Subscription = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, description, user_id, plan_id, pricing_id,
                   start_date, end_date, period, state, is_deleted, created_at, updated_at
            FROM subscriptions
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Subscription not found".to_string()))?;

        Ok(subscription.into())
    }

    pub async fn create(
        pool: &PgPool,
        req: CreateSubscriptionRequest,
    ) -> AppResult<SubscriptionResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let start_date = req.start_date.unwrap_or(now);

        sqlx::query(
            r#"
            INSERT INTO subscriptions (id, owner, name, display_name, description, user_id,
                                       plan_id, pricing_id, start_date, end_date, period,
                                       state, is_deleted, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, false, $13, $14)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.user_id)
        .bind(&req.plan_id)
        .bind(&req.pricing_id)
        .bind(start_date)
        .bind(req.end_date)
        .bind(&req.period.unwrap_or_else(|| "monthly".to_string()))
        .bind(&req.state.unwrap_or_else(|| "active".to_string()))
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateSubscriptionRequest,
    ) -> AppResult<SubscriptionResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE subscriptions
            SET display_name = COALESCE($1, display_name),
                description = COALESCE($2, description),
                plan_id = COALESCE($3, plan_id),
                pricing_id = COALESCE($4, pricing_id),
                end_date = COALESCE($5, end_date),
                period = COALESCE($6, period),
                state = COALESCE($7, state),
                updated_at = $8
            WHERE id = $9 AND is_deleted = false
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.plan_id)
        .bind(&req.pricing_id)
        .bind(req.end_date)
        .bind(&req.period)
        .bind(&req.state)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM subscriptions WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Subscription not found".to_string()));
        }

        Ok(())
    }
}
