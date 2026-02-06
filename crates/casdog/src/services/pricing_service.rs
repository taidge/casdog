use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreatePricingRequest, Pricing, PricingResponse, UpdatePricingRequest};

pub struct PricingService;

impl PricingService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<PricingResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let pricings: Vec<Pricing> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, description, plans, trial_duration,
                       application, is_enabled, is_deleted, created_at, updated_at
                FROM pricings
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
                SELECT id, owner, name, display_name, description, plans, trial_duration,
                       application, is_enabled, is_deleted, created_at, updated_at
                FROM pricings
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
                "SELECT COUNT(*) FROM pricings WHERE owner = $1 AND is_deleted = false",
            )
            .bind(owner)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM pricings WHERE is_deleted = false")
                .fetch_one(pool)
                .await?
        };

        Ok((pricings.into_iter().map(|p| p.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<PricingResponse> {
        let pricing: Pricing = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, description, plans, trial_duration,
                   application, is_enabled, is_deleted, created_at, updated_at
            FROM pricings
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Pricing not found".to_string()))?;

        Ok(pricing.into())
    }

    pub async fn create(pool: &PgPool, req: CreatePricingRequest) -> AppResult<PricingResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO pricings (id, owner, name, display_name, description, plans,
                                  trial_duration, application, is_enabled, is_deleted,
                                  created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, $10, $11)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.plans.unwrap_or_else(|| "[]".to_string()))
        .bind(req.trial_duration.unwrap_or(0))
        .bind(&req.application)
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
        req: UpdatePricingRequest,
    ) -> AppResult<PricingResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE pricings
            SET display_name = COALESCE($1, display_name),
                description = COALESCE($2, description),
                plans = COALESCE($3, plans),
                trial_duration = COALESCE($4, trial_duration),
                application = COALESCE($5, application),
                is_enabled = COALESCE($6, is_enabled),
                updated_at = $7
            WHERE id = $8 AND is_deleted = false
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.plans)
        .bind(req.trial_duration)
        .bind(&req.application)
        .bind(req.is_enabled)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM pricings WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Pricing not found".to_string()));
        }

        Ok(())
    }
}
