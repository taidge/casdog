use crate::error::{AppError, AppResult};
use crate::models::{
    CreateTransactionRequest, Transaction, TransactionResponse, UpdateTransactionRequest,
};
use sqlx::PgPool;
use uuid::Uuid;

pub struct TransactionService;

impl TransactionService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<TransactionResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let transactions: Vec<Transaction> = if let Some(owner) = owner {
            sqlx::query_as(
                r#"
                SELECT id, owner, name, display_name, description, provider_id, category,
                       transaction_type, product_id, user_id, application, amount, currency,
                       balance, state, is_deleted, created_at, updated_at
                FROM transactions
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
                SELECT id, owner, name, display_name, description, provider_id, category,
                       transaction_type, product_id, user_id, application, amount, currency,
                       balance, state, is_deleted, created_at, updated_at
                FROM transactions
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
                "SELECT COUNT(*) FROM transactions WHERE owner = $1 AND is_deleted = false",
            )
            .bind(owner)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM transactions WHERE is_deleted = false")
                .fetch_one(pool)
                .await?
        };

        Ok((
            transactions.into_iter().map(|t| t.into()).collect(),
            total,
        ))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<TransactionResponse> {
        let transaction: Transaction = sqlx::query_as(
            r#"
            SELECT id, owner, name, display_name, description, provider_id, category,
                   transaction_type, product_id, user_id, application, amount, currency,
                   balance, state, is_deleted, created_at, updated_at
            FROM transactions
            WHERE id = $1 AND is_deleted = false
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Transaction not found".to_string()))?;

        Ok(transaction.into())
    }

    pub async fn create(
        pool: &PgPool,
        req: CreateTransactionRequest,
    ) -> AppResult<TransactionResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO transactions (id, owner, name, display_name, description, provider_id,
                                      category, transaction_type, product_id, user_id, application,
                                      amount, currency, balance, state, is_deleted,
                                      created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, false,
                    $16, $17)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.provider_id)
        .bind(&req.category)
        .bind(&req.transaction_type.unwrap_or_else(|| "balance".to_string()))
        .bind(&req.product_id)
        .bind(&req.user_id)
        .bind(&req.application)
        .bind(req.amount.unwrap_or(0.0))
        .bind(&req.currency.unwrap_or_else(|| "USD".to_string()))
        .bind(req.balance.unwrap_or(0.0))
        .bind(&req.state.unwrap_or_else(|| "created".to_string()))
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateTransactionRequest,
    ) -> AppResult<TransactionResponse> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE transactions
            SET display_name = COALESCE($1, display_name),
                description = COALESCE($2, description),
                provider_id = COALESCE($3, provider_id),
                category = COALESCE($4, category),
                transaction_type = COALESCE($5, transaction_type),
                product_id = COALESCE($6, product_id),
                user_id = COALESCE($7, user_id),
                application = COALESCE($8, application),
                amount = COALESCE($9, amount),
                currency = COALESCE($10, currency),
                balance = COALESCE($11, balance),
                state = COALESCE($12, state),
                updated_at = $13
            WHERE id = $14 AND is_deleted = false
            "#,
        )
        .bind(&req.display_name)
        .bind(&req.description)
        .bind(&req.provider_id)
        .bind(&req.category)
        .bind(&req.transaction_type)
        .bind(&req.product_id)
        .bind(&req.user_id)
        .bind(&req.application)
        .bind(req.amount)
        .bind(&req.currency)
        .bind(req.balance)
        .bind(&req.state)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query(
            "UPDATE transactions SET is_deleted = true, updated_at = NOW() WHERE id = $1 AND is_deleted = false",
        )
        .bind(id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Transaction not found".to_string()));
        }

        Ok(())
    }
}
