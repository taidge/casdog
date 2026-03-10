use std::collections::HashMap;

use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{Order, OrderResponse, Payment, PaymentResponse, Provider, User};
use crate::services::providers::payment_provider::build_payment_provider;

pub struct PaymentFlowService;

#[derive(Debug, Serialize)]
pub struct PaymentStartResult {
    pub order: OrderResponse,
    pub payment: PaymentResponse,
    pub pay_url: Option<String>,
    pub auto_paid: bool,
    pub attach_info: Value,
}

#[derive(Debug, Serialize)]
pub struct PaymentNotifyResult {
    pub payment: PaymentResponse,
    pub order: Option<OrderResponse>,
    pub transaction_name: Option<String>,
    pub verified: bool,
}

impl PaymentFlowService {
    pub async fn start_order_payment(
        pool: &PgPool,
        order_id: &str,
        provider_hint: Option<&str>,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
        external_origin: Option<&str>,
    ) -> AppResult<PaymentStartResult> {
        let order = Self::load_order(pool, order_id).await?;
        if !is_admin
            && (order.owner != current_owner || order.user.as_deref() != Some(current_name))
        {
            return Err(AppError::Authorization(
                "Unauthorized order payment operation".to_string(),
            ));
        }
        if !order.state.eq_ignore_ascii_case("created") {
            return Err(AppError::Validation(format!(
                "Order '{}' is not payable in state '{}'",
                order_id, order.state
            )));
        }

        if let Some(payment_id) = order.payment_id.as_deref() {
            let existing_payment = Self::load_payment(pool, payment_id).await?;
            if !Self::is_terminal_payment_state(&existing_payment.state) {
                return Ok(PaymentStartResult {
                    order: order.into(),
                    pay_url: existing_payment.pay_url.clone(),
                    payment: existing_payment.into(),
                    auto_paid: false,
                    attach_info: json!({}),
                });
            }
        }

        let provider =
            Self::resolve_provider(pool, &order.owner, provider_hint, order.provider.as_deref())
                .await?;
        let return_url = Self::build_return_url(&order, external_origin, None);
        if Self::normalize_provider_type(&provider.provider_type) == "balance" {
            return Self::pay_with_balance(pool, order, provider, return_url).await;
        }

        let payment_id = Uuid::new_v4().to_string();
        let payment_name = format!("payment_{}", &payment_id[..12]);
        let return_url = Self::build_return_url(&order, external_origin, Some(&payment_id));
        let payment_provider = build_payment_provider(&provider)?;
        let pay_response = payment_provider
            .pay(&crate::services::providers::payment_provider::PayRequest {
                product_name: order
                    .product_name
                    .clone()
                    .unwrap_or_else(|| order.name.clone()),
                product_display_name: order
                    .product_display_name
                    .clone()
                    .or_else(|| order.product_name.clone())
                    .unwrap_or_else(|| order.display_name.clone()),
                provider_name: provider.name.clone(),
                price: order.price,
                currency: order.currency.clone().unwrap_or_else(|| "USD".to_string()),
                quantity: order.quantity.max(1),
                return_url: return_url.clone(),
                order_id: payment_id.clone(),
                payer_name: order.user.clone(),
                payer_email: Self::load_order_user(pool, &order)
                    .await
                    .ok()
                    .and_then(|user| user.email),
            })
            .await?;

        let payment = sqlx::query_as::<_, Payment>(
            r#"
            INSERT INTO payments (
                id, owner, name, display_name, description, provider_id, payment_type,
                product_id, product_name, user_id, amount, currency, state, message,
                out_order_id, pay_url, invoice_url, return_url, is_deleted, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8, $9, $10, $11, $12, $13, $14,
                $15, $16, NULL, $17, false, NOW(), NOW()
            )
            RETURNING *
            "#,
        )
        .bind(&payment_id)
        .bind(&order.owner)
        .bind(&payment_name)
        .bind(&payment_name)
        .bind(&order.tag)
        .bind(&provider.id)
        .bind(&provider.provider_type)
        .bind(None::<String>)
        .bind(&order.product_name)
        .bind(&order.user)
        .bind(order.price)
        .bind(order.currency.clone().unwrap_or_else(|| "USD".to_string()))
        .bind("created")
        .bind(Some(format!(
            "Checkout created with provider {}",
            provider.display_name
        )))
        .bind(&pay_response.order_id)
        .bind(&pay_response.pay_url)
        .bind(&return_url)
        .fetch_one(pool)
        .await?;

        let order = sqlx::query_as::<_, Order>(
            r#"
            UPDATE orders
            SET provider = $2,
                payment_id = $3,
                payment_name = $4,
                return_url = COALESCE(return_url, $5),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(&order.id)
        .bind(&provider.name)
        .bind(&payment.id)
        .bind(&payment.name)
        .bind(&return_url)
        .fetch_one(pool)
        .await?;

        Ok(PaymentStartResult {
            order: order.into(),
            payment: payment.clone().into(),
            pay_url: payment.pay_url.clone(),
            auto_paid: false,
            attach_info: json!({}),
        })
    }

    pub async fn cancel_order(
        pool: &PgPool,
        order_id: &str,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
    ) -> AppResult<OrderResponse> {
        let order = Self::load_order(pool, order_id).await?;
        if !is_admin
            && (order.owner != current_owner || order.user.as_deref() != Some(current_name))
        {
            return Err(AppError::Authorization(
                "Unauthorized order cancellation".to_string(),
            ));
        }
        if !order.state.eq_ignore_ascii_case("created") {
            return Err(AppError::Validation(format!(
                "Order '{}' cannot be canceled in state '{}'",
                order_id, order.state
            )));
        }

        let order = sqlx::query_as::<_, Order>(
            r#"
            UPDATE orders
            SET state = 'Canceled',
                error_text = 'Canceled by user',
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(order_id)
        .fetch_one(pool)
        .await?;
        Ok(order.into())
    }

    pub async fn notify_payment(
        pool: &PgPool,
        payment_id: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> AppResult<PaymentNotifyResult> {
        let payment = Self::load_payment(pool, payment_id).await?;
        let provider_id = payment.provider_id.clone().ok_or_else(|| {
            AppError::Validation("Payment provider is required for webhook processing".to_string())
        })?;
        let provider = Self::load_provider_by_id(pool, &provider_id).await?;
        let payment_provider = build_payment_provider(&provider)?;
        let notify_result = payment_provider
            .notify(body, headers, payment.out_order_id.as_deref())
            .await?;

        if let Some(amount) = notify_result.amount
            && (amount - payment.amount).abs() > 0.01
        {
            return Err(AppError::Authentication(format!(
                "Payment amount mismatch: expected {:.2}, got {:.2}",
                payment.amount, amount
            )));
        }
        if let (Some(expected_currency), Some(actual_currency)) = (
            payment.currency.as_deref(),
            notify_result.currency.as_deref(),
        ) && !expected_currency.eq_ignore_ascii_case(actual_currency)
        {
            return Err(AppError::Authentication(format!(
                "Payment currency mismatch: expected {}, got {}",
                expected_currency, actual_currency
            )));
        }

        let new_payment_state = Self::map_provider_payment_state(&notify_result.payment_status);
        let mut tx = pool.begin().await?;
        let payment = Self::load_payment_for_update(&mut tx, payment_id).await?;
        if Self::is_terminal_payment_state(&payment.state)
            && payment.state.eq_ignore_ascii_case(&new_payment_state)
        {
            tx.commit().await?;
            let order = Self::load_order_by_payment_optional(pool, payment_id).await?;
            return Ok(PaymentNotifyResult {
                payment: payment.into(),
                order: order.map(Into::into),
                transaction_name: None,
                verified: true,
            });
        }

        let payment = sqlx::query_as::<_, Payment>(
            r#"
            UPDATE payments
            SET state = $2,
                message = $3,
                invoice_url = COALESCE($4, invoice_url),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(&payment.id)
        .bind(&new_payment_state)
        .bind(notify_result.raw_state.clone().or(Some(format!(
            "{} webhook processed",
            provider.provider_type
        ))))
        .bind(&notify_result.invoice_url)
        .fetch_one(&mut *tx)
        .await?;

        let mut transaction_name = None;
        let order = if let Some(order) =
            Self::load_order_by_payment_optional_tx(&mut tx, &payment.id).await?
        {
            let order_state = Self::map_payment_state_to_order_state(&new_payment_state);
            let error_text = if order_state.eq_ignore_ascii_case("Failed")
                || order_state.eq_ignore_ascii_case("Canceled")
            {
                payment.message.clone()
            } else {
                None
            };
            let order = sqlx::query_as::<_, Order>(
                r#"
                UPDATE orders
                SET state = $2,
                    error_text = $3,
                    updated_at = NOW()
                WHERE id = $1
                RETURNING *
                "#,
            )
            .bind(&order.id)
            .bind(&order_state)
            .bind(&error_text)
            .fetch_one(&mut *tx)
            .await?;

            if new_payment_state.eq_ignore_ascii_case("paid") {
                transaction_name =
                    Self::create_purchase_transaction(&mut tx, &order, &payment, &provider, None)
                        .await?;
                Self::update_product_stock(&mut tx, &order).await?;
            }

            Some(order)
        } else {
            None
        };
        tx.commit().await?;

        Ok(PaymentNotifyResult {
            payment: payment.into(),
            order: order.map(Into::into),
            transaction_name,
            verified: true,
        })
    }

    pub async fn manual_notify_payment(
        pool: &PgPool,
        payment_id: &str,
        state: &str,
        message: Option<&str>,
        invoice_url: Option<&str>,
    ) -> AppResult<PaymentNotifyResult> {
        let new_payment_state = Self::map_provider_payment_state(state);
        let mut tx = pool.begin().await?;
        let payment = sqlx::query_as::<_, Payment>(
            r#"
            UPDATE payments
            SET state = $2,
                message = COALESCE($3, message),
                invoice_url = COALESCE($4, invoice_url),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(payment_id)
        .bind(&new_payment_state)
        .bind(message)
        .bind(invoice_url)
        .fetch_one(&mut *tx)
        .await?;

        let order = if let Some(order) =
            Self::load_order_by_payment_optional_tx(&mut tx, &payment.id).await?
        {
            let order = sqlx::query_as::<_, Order>(
                r#"
                UPDATE orders
                SET state = $2,
                    error_text = $3,
                    updated_at = NOW()
                WHERE id = $1
                RETURNING *
                "#,
            )
            .bind(&order.id)
            .bind(Self::map_payment_state_to_order_state(&new_payment_state))
            .bind(message)
            .fetch_one(&mut *tx)
            .await?;
            Some(order)
        } else {
            None
        };
        tx.commit().await?;

        Ok(PaymentNotifyResult {
            payment: payment.into(),
            order: order.map(Into::into),
            transaction_name: None,
            verified: false,
        })
    }

    pub async fn invoice_payment(pool: &PgPool, payment_id: &str) -> AppResult<PaymentResponse> {
        let payment = Self::load_payment(pool, payment_id).await?;
        if !payment.state.eq_ignore_ascii_case("paid") {
            return Err(AppError::Validation(format!(
                "Payment '{}' must be paid before invoicing",
                payment_id
            )));
        }
        if payment
            .invoice_url
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return Ok(payment.into());
        }

        let provider_id = payment.provider_id.clone().ok_or_else(|| {
            AppError::Validation("Payment provider is required for invoicing".to_string())
        })?;
        let provider = Self::load_provider_by_id(pool, &provider_id).await?;
        let payment_provider = build_payment_provider(&provider)?;
        let invoice_url = payment_provider
            .get_invoice(
                payment
                    .out_order_id
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .unwrap_or(&payment.id),
            )
            .await?;

        let payment = sqlx::query_as::<_, Payment>(
            r#"
            UPDATE payments
            SET invoice_url = $2,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(payment_id)
        .bind(&invoice_url)
        .fetch_one(pool)
        .await?;
        Ok(payment.into())
    }

    async fn pay_with_balance(
        pool: &PgPool,
        order: Order,
        provider: Provider,
        return_url: String,
    ) -> AppResult<PaymentStartResult> {
        let mut tx = pool.begin().await?;
        let user = Self::load_order_user_for_update(&mut tx, &order).await?;
        let new_balance = user.balance - order.price;
        if new_balance < user.balance_credit {
            return Err(AppError::Validation(format!(
                "Insufficient balance for user '{}'",
                user.name
            )));
        }

        let payment_id = Uuid::new_v4().to_string();
        let payment_name = format!("payment_{}", &payment_id[..12]);
        let pay_url = Self::build_return_url(&order, Some(&return_url), Some(&payment_id));
        let payment = sqlx::query_as::<_, Payment>(
            r#"
            INSERT INTO payments (
                id, owner, name, display_name, description, provider_id, payment_type,
                product_id, product_name, user_id, amount, currency, state, message,
                out_order_id, pay_url, invoice_url, return_url, is_deleted, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8, $9, $10, $11, $12, 'paid', $13,
                $14, $15, NULL, $16, false, NOW(), NOW()
            )
            RETURNING *
            "#,
        )
        .bind(&payment_id)
        .bind(&order.owner)
        .bind(&payment_name)
        .bind(&payment_name)
        .bind(&order.tag)
        .bind(&provider.id)
        .bind(&provider.provider_type)
        .bind(None::<String>)
        .bind(&order.product_name)
        .bind(&order.user)
        .bind(order.price)
        .bind(order.currency.clone().unwrap_or_else(|| "USD".to_string()))
        .bind(Some("Balance payment completed".to_string()))
        .bind(&payment_id)
        .bind(&pay_url)
        .bind(&return_url)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE users
            SET balance = $2,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(&user.id)
        .bind(new_balance)
        .execute(&mut *tx)
        .await?;

        let order = sqlx::query_as::<_, Order>(
            r#"
            UPDATE orders
            SET provider = $2,
                payment_id = $3,
                payment_name = $4,
                return_url = COALESCE(return_url, $5),
                state = 'Paid',
                error_text = NULL,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(&order.id)
        .bind(&provider.name)
        .bind(&payment.id)
        .bind(&payment.name)
        .bind(&return_url)
        .fetch_one(&mut *tx)
        .await?;

        let transaction_name = Self::create_purchase_transaction(
            &mut tx,
            &order,
            &payment,
            &provider,
            Some(new_balance),
        )
        .await?;
        Self::update_product_stock(&mut tx, &order).await?;
        tx.commit().await?;

        Ok(PaymentStartResult {
            order: order.into(),
            payment: payment.clone().into(),
            pay_url: payment.pay_url.clone(),
            auto_paid: true,
            attach_info: json!({ "transactionName": transaction_name }),
        })
    }

    async fn create_purchase_transaction(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
        payment: &Payment,
        provider: &Provider,
        balance_snapshot: Option<f64>,
    ) -> AppResult<Option<String>> {
        let transaction_name = format!("purchase_{}", payment.name);
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT name FROM transactions WHERE owner = $1 AND name = $2 AND is_deleted = false LIMIT 1",
        )
        .bind(&payment.owner)
        .bind(&transaction_name)
        .fetch_optional(&mut **tx)
        .await?;
        if existing.is_some() {
            return Ok(None);
        }

        let user = if let Some(user_name) = order.user.as_deref() {
            Some(Self::load_user_by_name_tx(tx, &payment.owner, user_name).await?)
        } else {
            None
        };
        let product_id = if let Some(product_name) = order.product_name.as_deref() {
            sqlx::query_scalar::<_, String>(
                "SELECT id FROM products WHERE owner = $1 AND name = $2 AND is_deleted = false LIMIT 1",
            )
            .bind(&payment.owner)
            .bind(product_name)
            .fetch_optional(&mut **tx)
            .await?
        } else {
            None
        };

        sqlx::query(
            r#"
            INSERT INTO transactions (
                id, owner, name, display_name, description, provider_id, category, transaction_type,
                product_id, user_id, application, amount, currency, balance, state, is_deleted,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11, $12, $13, $14, 'paid', false, NOW(), NOW()
            )
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&payment.owner)
        .bind(&transaction_name)
        .bind(
            order
                .product_display_name
                .clone()
                .unwrap_or_else(|| payment.display_name.clone()),
        )
        .bind(payment.message.clone())
        .bind(&payment.provider_id)
        .bind(Some("purchase".to_string()))
        .bind(Self::normalize_provider_type(&provider.provider_type))
        .bind(&product_id)
        .bind(user.as_ref().map(|value| value.id.clone()))
        .bind(
            user.as_ref()
                .and_then(|value| value.signup_application.clone()),
        )
        .bind(-payment.amount)
        .bind(
            payment
                .currency
                .clone()
                .unwrap_or_else(|| "USD".to_string()),
        )
        .bind(
            balance_snapshot
                .unwrap_or_else(|| user.as_ref().map(|value| value.balance).unwrap_or_default()),
        )
        .execute(&mut **tx)
        .await?;

        Ok(Some(transaction_name))
    }

    async fn update_product_stock(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
    ) -> AppResult<()> {
        let Some(product_name) = order.product_name.as_deref() else {
            return Ok(());
        };
        let product = sqlx::query(
            r#"
            SELECT id, quantity, sold
            FROM products
            WHERE owner = $1 AND name = $2 AND is_deleted = false
            FOR UPDATE
            "#,
        )
        .bind(&order.owner)
        .bind(product_name)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(product) = product else {
            return Ok(());
        };

        let quantity: i32 = product.try_get("quantity")?;
        let sold: i32 = product.try_get("sold")?;
        if quantity >= 0 && quantity < order.quantity {
            return Err(AppError::Validation(format!(
                "Product '{}' does not have enough stock",
                product_name
            )));
        }

        sqlx::query(
            r#"
            UPDATE products
            SET quantity = CASE WHEN quantity < 0 THEN quantity ELSE quantity - $2 END,
                sold = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(product.try_get::<String, _>("id")?)
        .bind(order.quantity)
        .bind(sold + order.quantity)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn resolve_provider(
        pool: &PgPool,
        owner: &str,
        provider_hint: Option<&str>,
        order_provider: Option<&str>,
    ) -> AppResult<Provider> {
        let hint = provider_hint
            .or(order_provider)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::Validation("Payment provider is required".to_string()))?;

        if let Some(provider) =
            sqlx::query_as::<_, Provider>("SELECT * FROM providers WHERE id = $1 LIMIT 1")
                .bind(hint)
                .fetch_optional(pool)
                .await?
        {
            return Ok(provider);
        }

        sqlx::query_as::<_, Provider>(
            "SELECT * FROM providers WHERE owner = $1 AND name = $2 LIMIT 1",
        )
        .bind(owner)
        .bind(hint)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Provider '{}/{}' not found", owner, hint)))
    }

    fn build_return_url(
        order: &Order,
        external_origin: Option<&str>,
        payment_id: Option<&str>,
    ) -> String {
        let base = external_origin
            .filter(|value| value.starts_with("http://") || value.starts_with("https://"))
            .map(ToOwned::to_owned)
            .or_else(|| order.return_url.clone())
            .unwrap_or_else(|| {
                let config = AppConfig::get();
                format!(
                    "http://{}:{}/payments/result",
                    config.server.host, config.server.port
                )
            });

        let url = Self::append_query_pair(&base, "orderId", &order.id);
        if let Some(payment_id) = payment_id {
            Self::append_query_pair(&url, "paymentId", payment_id)
        } else {
            url
        }
    }

    fn append_query_pair(url: &str, key: &str, value: &str) -> String {
        format!(
            "{}{}{}={}",
            url,
            if url.contains('?') { "&" } else { "?" },
            urlencoding::encode(key),
            urlencoding::encode(value)
        )
    }

    fn normalize_provider_type(provider_type: &str) -> String {
        provider_type
            .chars()
            .filter(|ch| !matches!(ch, ' ' | '-' | '_'))
            .flat_map(char::to_lowercase)
            .collect()
    }

    fn map_provider_payment_state(value: &str) -> String {
        match value.to_ascii_lowercase().as_str() {
            "paid" | "completed" | "success" | "succeeded" => "paid".to_string(),
            "failed" | "error" | "denied" => "failed".to_string(),
            "canceled" | "cancelled" | "voided" => "canceled".to_string(),
            "timeout" | "expired" => "timeout".to_string(),
            _ => "pending".to_string(),
        }
    }

    fn map_payment_state_to_order_state(value: &str) -> &'static str {
        match value.to_ascii_lowercase().as_str() {
            "paid" => "Paid",
            "failed" => "Failed",
            "canceled" => "Canceled",
            "timeout" => "Timeout",
            _ => "Processing",
        }
    }

    fn is_terminal_payment_state(value: &str) -> bool {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "paid" | "failed" | "canceled" | "timeout"
        )
    }

    async fn load_order(pool: &PgPool, id: &str) -> AppResult<Order> {
        sqlx::query_as::<_, Order>(
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
        .ok_or_else(|| AppError::NotFound(format!("Order '{}' not found", id)))
    }

    async fn load_payment(pool: &PgPool, id: &str) -> AppResult<Payment> {
        sqlx::query_as::<_, Payment>(
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
        .ok_or_else(|| AppError::NotFound(format!("Payment '{}' not found", id)))
    }

    async fn load_payment_for_update(
        tx: &mut Transaction<'_, Postgres>,
        id: &str,
    ) -> AppResult<Payment> {
        sqlx::query_as::<_, Payment>(
            r#"
            SELECT id, owner, name, display_name, description, provider_id, payment_type,
                   product_id, product_name, user_id, amount, currency, state, message,
                   out_order_id, pay_url, invoice_url, return_url, is_deleted, created_at, updated_at
            FROM payments
            WHERE id = $1 AND is_deleted = false
            FOR UPDATE
            "#,
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Payment '{}' not found", id)))
    }

    async fn load_provider_by_id(pool: &PgPool, id: &str) -> AppResult<Provider> {
        sqlx::query_as::<_, Provider>("SELECT * FROM providers WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Provider '{}' not found", id)))
    }

    async fn load_order_by_payment_optional(
        pool: &PgPool,
        payment_id: &str,
    ) -> AppResult<Option<Order>> {
        sqlx::query_as::<_, Order>(
            r#"
            SELECT id, owner, name, display_name, provider, product_name, product_display_name,
                   quantity, price, currency, state, tag, invoice_url, payment_id, payment_name,
                   return_url, "user", plan_name, pricing_name, error_text, is_deleted,
                   created_at, updated_at
            FROM orders
            WHERE payment_id = $1 AND is_deleted = false
            LIMIT 1
            "#,
        )
        .bind(payment_id)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
    }

    async fn load_order_by_payment_optional_tx(
        tx: &mut Transaction<'_, Postgres>,
        payment_id: &str,
    ) -> AppResult<Option<Order>> {
        sqlx::query_as::<_, Order>(
            r#"
            SELECT id, owner, name, display_name, provider, product_name, product_display_name,
                   quantity, price, currency, state, tag, invoice_url, payment_id, payment_name,
                   return_url, "user", plan_name, pricing_name, error_text, is_deleted,
                   created_at, updated_at
            FROM orders
            WHERE payment_id = $1 AND is_deleted = false
            LIMIT 1
            FOR UPDATE
            "#,
        )
        .bind(payment_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(Into::into)
    }

    async fn load_order_user(pool: &PgPool, order: &Order) -> AppResult<User> {
        let user_name = order
            .user
            .as_deref()
            .ok_or_else(|| AppError::Validation("Order user is required".to_string()))?;
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE owner = $1 AND name = $2 AND is_deleted = false",
        )
        .bind(&order.owner)
        .bind(user_name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("User '{}/{}' not found", order.owner, user_name))
        })
    }

    async fn load_order_user_for_update(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
    ) -> AppResult<User> {
        let user_name = order
            .user
            .as_deref()
            .ok_or_else(|| AppError::Validation("Order user is required".to_string()))?;
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE owner = $1 AND name = $2 AND is_deleted = false FOR UPDATE",
        )
        .bind(&order.owner)
        .bind(user_name)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("User '{}/{}' not found", order.owner, user_name))
        })
    }

    async fn load_user_by_name_tx(
        tx: &mut Transaction<'_, Postgres>,
        owner: &str,
        name: &str,
    ) -> AppResult<User> {
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE owner = $1 AND name = $2 AND is_deleted = false",
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User '{}/{}' not found", owner, name)))
    }
}
