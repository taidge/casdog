use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreateProductRequest, Product, ProductResponse, UpdateProductRequest};

pub struct ProductService;

impl ProductService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<ProductResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let products: Vec<Product> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, description, image, detail, currency,
                       price, quantity, sold, is_recharge, recharge_options, disable_custom_recharge, plan_id, tag, state, is_deleted, created_at, updated_at
                FROM products
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
                SELECT id, owner, name, display_name, description, image, detail, currency,
                       price, quantity, sold, is_recharge, recharge_options, disable_custom_recharge, plan_id, tag, state, is_deleted, created_at, updated_at
                FROM products
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
                "SELECT COUNT(*) FROM products WHERE owner = $1 AND is_deleted = false",
            )
            .bind(owner)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM products WHERE is_deleted = false")
                .fetch_one(pool)
                .await?
        };

        Ok((products.into_iter().map(|p| p.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<ProductResponse> {
        let product: Product = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, description, image, detail, currency,
                   price, quantity, sold, is_recharge, recharge_options, disable_custom_recharge, plan_id, tag, state, is_deleted, created_at, updated_at
            FROM products
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Product not found".to_string()))?;

        Ok(product.into())
    }

    pub async fn create(pool: &PgPool, req: CreateProductRequest) -> AppResult<ProductResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        Self::validate_price(req.price.unwrap_or(0.0), false)?;
        let plan_id = Self::validate_configuration(
            pool,
            &req.owner,
            req.is_recharge.unwrap_or(false),
            req.recharge_options.as_deref().unwrap_or(&[]),
            req.plan_id.as_deref(),
        )
        .await?;

        sqlx::query(
            r#"
            INSERT INTO products (id, owner, name, display_name, description, image, detail,
                                  currency, price, quantity, sold, tag, state, is_deleted,
                                  created_at, updated_at, is_recharge, recharge_options, disable_custom_recharge, plan_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, $11, $12, false, $13, $14, $15, $16, $17, $18)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.image)
        .bind(&req.detail)
        .bind(&req.currency.unwrap_or_else(|| "USD".to_string()))
        .bind(req.price.unwrap_or(0.0))
        .bind(req.quantity.unwrap_or(-1))
        .bind(&req.tag)
        .bind(&req.state.unwrap_or_else(|| "active".to_string()))
        .bind(now)
        .bind(now)
        .bind(req.is_recharge.unwrap_or(false))
        .bind(serde_json::json!(req.recharge_options.unwrap_or_default()))
        .bind(req.disable_custom_recharge.unwrap_or(false))
        .bind(plan_id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateProductRequest,
    ) -> AppResult<ProductResponse> {
        let now = chrono::Utc::now();
        let existing = Self::get_by_id(pool, id).await?;
        Self::validate_price(req.price.unwrap_or(existing.price), false)?;
        let options = req.recharge_options.clone().unwrap_or_else(|| {
            serde_json::from_value(existing.recharge_options.clone()).unwrap_or_default()
        });
        let plan_id = Self::validate_configuration(
            pool,
            &existing.owner,
            req.is_recharge.unwrap_or(existing.is_recharge),
            &options,
            req.plan_id.as_deref().or(existing.plan_id.as_deref()),
        )
        .await?;

        sqlx::query(
            r#"
            UPDATE products
            SET display_name = COALESCE($1, display_name),
                description = COALESCE($2, description),
                image = COALESCE($3, image),
                detail = COALESCE($4, detail),
                currency = COALESCE($5, currency),
                price = COALESCE($6, price),
                quantity = COALESCE($7, quantity),
                tag = COALESCE($8, tag),
                state = COALESCE($9, state),
                updated_at = $10,
                is_recharge = COALESCE($12,is_recharge),
                recharge_options = COALESCE($13,recharge_options),
                disable_custom_recharge = COALESCE($14,disable_custom_recharge),
                plan_id = $15
            WHERE id = $11 AND is_deleted = false
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.image)
        .bind(&req.detail)
        .bind(&req.currency)
        .bind(req.price)
        .bind(req.quantity)
        .bind(&req.tag)
        .bind(&req.state)
        .bind(now)
        .bind(id)
        .bind(req.is_recharge)
        .bind(req.recharge_options.map(|v| serde_json::json!(v)))
        .bind(req.disable_custom_recharge)
        .bind(plan_id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub fn validate_price(amount: f64, positive: bool) -> AppResult<i64> {
        if !amount.is_finite()
            || amount < 0.0
            || (positive && amount == 0.0)
            || amount > 9_000_000_000_000.0
            || ((amount * 100.0).round() - amount * 100.0).abs() > 0.000001
        {
            return Err(AppError::Validation(
                "Amounts must use cents and be within the supported range".into(),
            ));
        }
        Ok((amount * 100.0).round() as i64)
    }

    async fn validate_configuration(
        pool: &PgPool,
        owner: &str,
        recharge: bool,
        options: &[f64],
        plan: Option<&str>,
    ) -> AppResult<Option<String>> {
        for &amount in options {
            Self::validate_price(amount, true)?;
        }
        let plan = plan.filter(|s| !s.is_empty());
        if recharge && plan.is_some() {
            return Err(AppError::Validation(
                "A recharge product cannot sell a subscription plan".into(),
            ));
        }
        let Some(plan) = plan else {
            return Ok(None);
        };
        let (hint_owner, hint) = plan.split_once('/').unwrap_or((owner, plan));
        if hint_owner != owner {
            return Err(AppError::Authorization(
                "Plan belongs to another tenant".into(),
            ));
        }
        let found: Option<(String,String)>=sqlx::query_as("SELECT id,owner FROM plans WHERE (id=$1 OR (owner=$2 AND name=$1)) AND is_deleted=false ORDER BY (id=$1) DESC LIMIT 1")
            .bind(hint).bind(owner).fetch_optional(pool).await?;
        let (id, plan_owner) =
            found.ok_or_else(|| AppError::Validation("Product plan does not exist".into()))?;
        if plan_owner != owner {
            return Err(AppError::Authorization(
                "Plan belongs to another tenant".into(),
            ));
        }
        Ok(Some(id))
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query(
            "UPDATE products SET is_deleted=true,updated_at=NOW() WHERE id=$1 AND is_deleted=false",
        )
        .bind(id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Product not found".to_string()));
        }

        Ok(())
    }
}
