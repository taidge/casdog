use crate::error::{AppError, AppResult};
use crate::models::{CreateProductRequest, Product, ProductResponse, UpdateProductRequest};
use sqlx::PgPool;
use uuid::Uuid;

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
                       price, quantity, sold, tag, state, is_deleted, created_at, updated_at
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
                       price, quantity, sold, tag, state, is_deleted, created_at, updated_at
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
            sqlx::query_scalar("SELECT COUNT(*) FROM products WHERE owner = $1 AND is_deleted = false")
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
                   price, quantity, sold, tag, state, is_deleted, created_at, updated_at
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

        sqlx::query(
            r#"
            INSERT INTO products (id, owner, name, display_name, description, image, detail,
                                  currency, price, quantity, sold, tag, state, is_deleted,
                                  created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, $11, $12, false, $13, $14)
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
                updated_at = $10
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
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM products WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Product not found".to_string()));
        }

        Ok(())
    }
}
