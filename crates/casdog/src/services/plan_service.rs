use crate::error::{AppError, AppResult};
use crate::models::{CreatePlanRequest, Plan, PlanResponse, UpdatePlanRequest};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PlanService;

impl PlanService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<PlanResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let plans: Vec<Plan> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, description, price_per_month, price_per_year,
                       currency, role, options, is_enabled, is_deleted, created_at, updated_at
                FROM plans
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
                SELECT id, owner, name, display_name, description, price_per_month, price_per_year,
                       currency, role, options, is_enabled, is_deleted, created_at, updated_at
                FROM plans
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
            sqlx::query_scalar("SELECT COUNT(*) FROM plans WHERE owner = $1 AND is_deleted = false")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM plans WHERE is_deleted = false")
                .fetch_one(pool)
                .await?
        };

        Ok((plans.into_iter().map(|p| p.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<PlanResponse> {
        let plan: Plan = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, description, price_per_month, price_per_year,
                   currency, role, options, is_enabled, is_deleted, created_at, updated_at
            FROM plans
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Plan not found".to_string()))?;

        Ok(plan.into())
    }

    pub async fn create(pool: &PgPool, req: CreatePlanRequest) -> AppResult<PlanResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO plans (id, owner, name, display_name, description, price_per_month,
                               price_per_year, currency, role, options, is_enabled, is_deleted,
                               created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false, $12, $13)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(req.price_per_month.unwrap_or(0.0))
        .bind(req.price_per_year.unwrap_or(0.0))
        .bind(&req.currency.unwrap_or_else(|| "USD".to_string()))
        .bind(&req.role)
        .bind(&req.options.unwrap_or_else(|| "[]".to_string()))
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
        req: UpdatePlanRequest,
    ) -> AppResult<PlanResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE plans
            SET display_name = COALESCE($1, display_name),
                description = COALESCE($2, description),
                price_per_month = COALESCE($3, price_per_month),
                price_per_year = COALESCE($4, price_per_year),
                currency = COALESCE($5, currency),
                role = COALESCE($6, role),
                options = COALESCE($7, options),
                is_enabled = COALESCE($8, is_enabled),
                updated_at = $9
            WHERE id = $10 AND is_deleted = false
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(req.price_per_month)
        .bind(req.price_per_year)
        .bind(&req.currency)
        .bind(&req.role)
        .bind(&req.options)
        .bind(req.is_enabled)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM plans WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Plan not found".to_string()));
        }

        Ok(())
    }
}
