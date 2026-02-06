use crate::error::{AppError, AppResult};
use crate::models::{CreateOrderRequest, Order, OrderResponse, UpdateOrderRequest};
use sqlx::PgPool;
use uuid::Uuid;

pub struct OrderService;

impl OrderService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        state: Option<&str>,
        user: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<OrderResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let mut query = String::from(
            r#"
            SELECT id, owner, name, display_name, provider, product_name, product_display_name,
                   quantity, price, currency, state, tag, invoice_url, payment_id, payment_name,
                   return_url, "user", plan_name, pricing_name, error_text, is_deleted,
                   created_at, updated_at
            FROM orders
            WHERE is_deleted = false
            "#,
        );

        let mut conditions: Vec<String> = Vec::new();
        if owner.is_some() {
            conditions.push("owner = $1".to_string());
        }
        if state.is_some() {
            conditions.push(format!("state = ${}", conditions.len() + 1));
        }
        if user.is_some() {
            conditions.push(format!("\"user\" = ${}", conditions.len() + 1));
        }

        if !conditions.is_empty() {
            query.push_str(" AND ");
            query.push_str(&conditions.join(" AND "));
        }

        query.push_str(" ORDER BY created_at DESC LIMIT $");
        query.push_str(&(conditions.len() + 1).to_string());
        query.push_str(" OFFSET $");
        query.push_str(&(conditions.len() + 2).to_string());

        let mut q = sqlx::query_as::<_, Order>(&query);
        if let Some(o) = owner {
            q = q.bind(o);
        }
        if let Some(s) = state {
            q = q.bind(s);
        }
        if let Some(u) = user {
            q = q.bind(u);
        }
        q = q.bind(page_size).bind(offset);

        let orders = q.fetch_all(pool).await?;

        let mut count_query = String::from("SELECT COUNT(*) FROM orders WHERE is_deleted = false");
        if !conditions.is_empty() {
            count_query.push_str(" AND ");
            let count_conditions: Vec<String> = (1..=conditions.len())
                .map(|i| {
                    if i == 1 && owner.is_some() {
                        "owner = $1".to_string()
                    } else if (i == 2 && owner.is_some() || i == 1 && owner.is_none()) && state.is_some() {
                        format!("state = ${}", i)
                    } else {
                        format!("\"user\" = ${}", i)
                    }
                })
                .collect();
            count_query.push_str(&count_conditions.join(" AND "));
        }

        let mut cq = sqlx::query_scalar::<_, i64>(&count_query);
        if let Some(o) = owner {
            cq = cq.bind(o);
        }
        if let Some(s) = state {
            cq = cq.bind(s);
        }
        if let Some(u) = user {
            cq = cq.bind(u);
        }

        let total = cq.fetch_one(pool).await?;

        Ok((orders.into_iter().map(|o| o.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<OrderResponse> {
        let order: Order = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, provider, product_name, product_display_name,
                   quantity, price, currency, state, tag, invoice_url, payment_id, payment_name,
                   return_url, "user", plan_name, pricing_name, error_text, is_deleted,
                   created_at, updated_at
            FROM orders
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Order not found".to_string()))?;

        Ok(order.into())
    }

    pub async fn create(pool: &PgPool, req: CreateOrderRequest) -> AppResult<OrderResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO orders (id, owner, name, display_name, provider, product_name,
                                product_display_name, quantity, price, currency, state, tag,
                                invoice_url, payment_id, payment_name, return_url, "user",
                                plan_name, pricing_name, error_text, is_deleted,
                                created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                    $18, $19, NULL, false, $20, $21)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.provider)
        .bind(&req.product_name)
        .bind(&req.product_display_name)
        .bind(req.quantity.unwrap_or(1))
        .bind(req.price.unwrap_or(0.0))
        .bind(&req.currency.unwrap_or_else(|| "USD".to_string()))
        .bind(&req.state.unwrap_or_else(|| "Created".to_string()))
        .bind(&req.tag)
        .bind(&req.invoice_url)
        .bind(&req.payment_id)
        .bind(&req.payment_name)
        .bind(&req.return_url)
        .bind(&req.user)
        .bind(&req.plan_name)
        .bind(&req.pricing_name)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateOrderRequest,
    ) -> AppResult<OrderResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE orders
            SET display_name = COALESCE($1, display_name),
                provider = COALESCE($2, provider),
                product_name = COALESCE($3, product_name),
                product_display_name = COALESCE($4, product_display_name),
                quantity = COALESCE($5, quantity),
                price = COALESCE($6, price),
                currency = COALESCE($7, currency),
                state = COALESCE($8, state),
                tag = COALESCE($9, tag),
                invoice_url = COALESCE($10, invoice_url),
                payment_id = COALESCE($11, payment_id),
                payment_name = COALESCE($12, payment_name),
                return_url = COALESCE($13, return_url),
                "user" = COALESCE($14, "user"),
                plan_name = COALESCE($15, plan_name),
                pricing_name = COALESCE($16, pricing_name),
                error_text = COALESCE($17, error_text),
                updated_at = $18
            WHERE id = $19 AND is_deleted = false
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.provider)
        .bind(&req.product_name)
        .bind(&req.product_display_name)
        .bind(req.quantity)
        .bind(req.price)
        .bind(&req.currency)
        .bind(&req.state)
        .bind(&req.tag)
        .bind(&req.invoice_url)
        .bind(&req.payment_id)
        .bind(&req.payment_name)
        .bind(&req.return_url)
        .bind(&req.user)
        .bind(&req.plan_name)
        .bind(&req.pricing_name)
        .bind(&req.error_text)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn update_state(pool: &PgPool, id: &str, state: &str) -> AppResult<OrderResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE orders
            SET state = $1,
                updated_at = $2
            WHERE id = $3 AND is_deleted = false
            "#,
        )
        .bind(state)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM orders WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Order not found".to_string()));
        }

        Ok(())
    }
}
