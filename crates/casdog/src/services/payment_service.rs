use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreatePaymentRequest, Payment, PaymentResponse, UpdatePaymentRequest};

pub struct PaymentService;

impl PaymentService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<PaymentResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let payments: Vec<Payment> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, description, provider_id, payment_type,
                       product_id, product_name, user_id, amount, currency, state, message,
                       out_order_id, pay_url, invoice_url, return_url, is_deleted, created_at, updated_at
                FROM payments
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
                SELECT id, owner, name, display_name, description, provider_id, payment_type,
                       product_id, product_name, user_id, amount, currency, state, message,
                       out_order_id, pay_url, invoice_url, return_url, is_deleted, created_at, updated_at
                FROM payments
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
                "SELECT COUNT(*) FROM payments WHERE owner = $1 AND is_deleted = false",
            )
            .bind(owner)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE is_deleted = false")
                .fetch_one(pool)
                .await?
        };

        Ok((payments.into_iter().map(|p| p.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<PaymentResponse> {
        let payment: Payment = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, description, provider_id, payment_type,
                   product_id, product_name, user_id, amount, currency, state, message,
                   out_order_id, pay_url, invoice_url, return_url, is_deleted, created_at, updated_at
            FROM payments
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Payment not found".to_string()))?;

        Ok(payment.into())
    }

    pub async fn create(pool: &PgPool, req: CreatePaymentRequest) -> AppResult<PaymentResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO payments (id, owner, name, display_name, description, provider_id,
                                  payment_type, product_id, product_name, user_id, amount,
                                  currency, state, message, out_order_id, pay_url, invoice_url,
                                  return_url, is_deleted, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                    $18, false, $19, $20)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.provider_id)
        .bind(&req.payment_type.unwrap_or_else(|| "pay-pal".to_string()))
        .bind(&req.product_id)
        .bind(&req.product_name)
        .bind(&req.user_id)
        .bind(req.amount.unwrap_or(0.0))
        .bind(&req.currency.unwrap_or_else(|| "USD".to_string()))
        .bind(&req.state.unwrap_or_else(|| "created".to_string()))
        .bind(&req.message)
        .bind(&req.out_order_id)
        .bind(&req.pay_url)
        .bind(&req.invoice_url)
        .bind(&req.return_url)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdatePaymentRequest,
    ) -> AppResult<PaymentResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE payments
            SET display_name = COALESCE($1, display_name),
                description = COALESCE($2, description),
                provider_id = COALESCE($3, provider_id),
                payment_type = COALESCE($4, payment_type),
                product_id = COALESCE($5, product_id),
                product_name = COALESCE($6, product_name),
                user_id = COALESCE($7, user_id),
                amount = COALESCE($8, amount),
                currency = COALESCE($9, currency),
                state = COALESCE($10, state),
                message = COALESCE($11, message),
                out_order_id = COALESCE($12, out_order_id),
                pay_url = COALESCE($13, pay_url),
                invoice_url = COALESCE($14, invoice_url),
                return_url = COALESCE($15, return_url),
                updated_at = $16
            WHERE id = $17 AND is_deleted = false
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.provider_id)
        .bind(&req.payment_type)
        .bind(&req.product_id)
        .bind(&req.product_name)
        .bind(&req.user_id)
        .bind(req.amount)
        .bind(&req.currency)
        .bind(&req.state)
        .bind(&req.message)
        .bind(&req.out_order_id)
        .bind(&req.pay_url)
        .bind(&req.invoice_url)
        .bind(&req.return_url)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query(
            "UPDATE payments SET is_deleted = true, updated_at = NOW() WHERE id = $1 AND is_deleted = false",
        )
        .bind(id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Payment not found".to_string()));
        }

        Ok(())
    }
}
