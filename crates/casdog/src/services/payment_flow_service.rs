use std::collections::HashMap;

use chrono::{DateTime, Months, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{Order, OrderResponse, Payment, PaymentResponse, Provider, User};
use crate::services::providers::payment_provider::build_payment_provider;

pub struct PaymentFlowService;

#[derive(sqlx::FromRow)]
struct PurchaseBenefit {
    kind: String,
    user_id: String,
    amount_cents: i64,
    plan_id: Option<String>,
    pricing_id: Option<String>,
    period: Option<String>,
    role_id: Option<String>,
    fulfilled_at: Option<DateTime<Utc>>,
}

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
        // All mutations use the same lock order: order, payment, product, user.
        // This serializes checkout creation across server instances as well as
        // cancellation and webhooks, without a process-local mutex.
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *tx)
            .await?;
        let order = Self::load_order_for_update(&mut tx, order_id).await?;
        Self::authorize_order(&order, current_owner, current_name, is_admin)?;
        if let Some(payment_id) = order.payment_id.as_deref().filter(|id| !id.is_empty()) {
            let payment = Self::load_payment_for_update(&mut tx, payment_id).await?;
            if !Self::is_terminal_payment_state(&payment.state)
                || payment.state.eq_ignore_ascii_case("paid")
            {
                let auto_paid = payment.state.eq_ignore_ascii_case("paid");
                tx.commit().await?;
                return Ok(PaymentStartResult {
                    order: order.into(),
                    pay_url: payment.pay_url.clone(),
                    payment: payment.into(),
                    auto_paid,
                    attach_info: json!({}),
                });
            }
        }
        if !order.state.eq_ignore_ascii_case("created") {
            return Err(AppError::Validation(format!(
                "Order '{}' is not payable in state '{}'",
                order_id, order.state
            )));
        }
        Self::validate_order_amount(&order)?;
        let provider = Self::resolve_provider(
            &mut tx,
            &order.owner,
            provider_hint,
            order.provider.as_deref(),
        )
        .await?;
        Self::validate_benefit_checkout(&mut tx, &order, &provider).await?;
        let return_url = Self::build_return_url(&order, external_origin, None);
        if Self::normalize_provider_type(&provider.provider_type) == "balance" {
            return Self::pay_with_balance(tx, order, provider, return_url).await;
        }
        let payment_provider = build_payment_provider(&provider)?;
        Self::reserve_product_stock(&mut tx, &order).await?;
        let payment_id = Uuid::new_v4().to_string();
        let payment_name = format!("payment_{}", &payment_id[..12]);
        let return_url = Self::build_return_url(&order, external_origin, Some(&payment_id));
        let payer_email = Self::load_order_user_for_update(&mut tx, &order)
            .await
            .ok()
            .and_then(|u| u.email);
        let payment = sqlx::query_as::<_, Payment>(
            r#"INSERT INTO payments (
                id, owner, name, display_name, description, provider_id, payment_type,
                product_name, user_id, amount, currency, state, message,
                out_order_id, return_url, is_deleted, created_at, updated_at
            ) VALUES ($1,$2,$3,$3,$4,$5,$6,$7,$8,$9,$10,'created',
                'Checkout initialization in progress',$1,$11,false,NOW(),NOW()) RETURNING *"#,
        )
        .bind(&payment_id)
        .bind(&order.owner)
        .bind(&payment_name)
        .bind(&order.tag)
        .bind(&provider.id)
        .bind(&provider.provider_type)
        .bind(&order.product_name)
        .bind(&order.user)
        .bind(order.price)
        .bind(order.currency.clone().unwrap_or_else(|| "USD".to_string()))
        .bind(&return_url)
        .fetch_one(&mut *tx)
        .await?;
        let order = sqlx::query_as::<_, Order>(
            "UPDATE orders SET provider=$2,payment_id=$3,payment_name=$4,return_url=COALESCE(return_url,$5),updated_at=NOW() WHERE id=$1 RETURNING *",
        ).bind(&order.id).bind(&provider.name).bind(&payment.id).bind(&payment.name)
            .bind(&return_url).fetch_one(&mut *tx).await?;
        // The remote request is made only after its local payment and inventory
        // reservation are durable. Other callers reuse this payment ID.
        tx.commit().await?;
        let remote = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            payment_provider.pay(&crate::services::providers::payment_provider::PayRequest {
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
                // order.price is the total payable amount, including discounts.
                price: order.price,
                currency: order.currency.clone().unwrap_or_else(|| "USD".to_string()),
                quantity: 1,
                return_url: return_url.clone(),
                order_id: payment_id.clone(),
                payer_name: order.user.clone(),
                payer_email,
            }),
        )
        .await;
        let response = match remote {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                // A transport/server error does not prove that no charge was
                // created. Only a definitive rejection may release inventory.
                if matches!(
                    &error,
                    AppError::Validation(_) | AppError::Authentication(_) | AppError::Config(_)
                ) {
                    Self::apply_payment_state(
                        pool,
                        &payment_id,
                        "failed",
                        Some(&error.to_string()),
                        None,
                        false,
                    )
                    .await?;
                }
                return Err(error);
            }
            Err(_) => {
                // A transport timeout can happen after the provider has accepted
                // the request. Keep its durable reservation until a verified
                // notification or an explicit cancellation resolves the outcome.
                return Err(AppError::Internal(
                    "Checkout response timed out; payment remains pending".into(),
                ));
            }
        };
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *tx)
            .await?;
        let order = Self::load_order_for_update(&mut tx, &order.id).await?;
        let payment = Self::load_payment_for_update(&mut tx, &payment_id).await?;
        // A fast webhook/cancellation may have finalized the payment already.
        let payment = if !Self::is_terminal_payment_state(&payment.state) {
            sqlx::query_as::<_, Payment>(
                "UPDATE payments SET out_order_id=$2,pay_url=$3,message=$4,updated_at=NOW() WHERE id=$1 RETURNING *",
            ).bind(&payment_id).bind(&response.order_id).bind(&response.pay_url)
                .bind(format!("Checkout created with provider {}",provider.display_name))
                .fetch_one(&mut *tx).await?
        } else {
            payment
        };
        tx.commit().await?;
        Ok(PaymentStartResult {
            order: order.into(),
            pay_url: payment.pay_url.clone(),
            auto_paid: payment.state.eq_ignore_ascii_case("paid"),
            payment: payment.into(),
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
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *tx)
            .await?;
        let order = Self::load_order_for_update(&mut tx, order_id).await?;
        Self::authorize_order(&order, current_owner, current_name, is_admin)?;
        if order.state.eq_ignore_ascii_case("canceled") {
            return Ok(order.into());
        }
        if !matches!(
            order.state.to_ascii_lowercase().as_str(),
            "created" | "processing"
        ) {
            return Err(AppError::Validation(format!(
                "Order '{}' cannot be canceled in state '{}'",
                order_id, order.state
            )));
        }
        if let Some(payment_id) = order.payment_id.as_deref().filter(|s| !s.is_empty()) {
            let payment = Self::load_payment_for_update(&mut tx, payment_id).await?;
            if payment.state.eq_ignore_ascii_case("paid") {
                return Err(AppError::Validation(
                    "A paid order cannot be canceled".into(),
                ));
            }
            let provider_id = payment.provider_id.as_deref().ok_or_else(|| {
                AppError::Conflict(
                    "The pending payment must be resolved before cancellation".into(),
                )
            })?;
            let provider = Self::load_provider_by_id_tx(&mut tx, provider_id).await?;
            // A local state change cannot void a remote checkout. Releasing
            // stock here would lose fulfilment if a real charge arrives later.
            // Until provider-specific void/refund exists, only local providers
            // can acknowledge cancellation synchronously.
            if !matches!(
                Self::normalize_provider_type(&provider.provider_type).as_str(),
                "dummy" | "balance"
            ) {
                return Err(AppError::Conflict(
                    "Remote checkout is still pending; wait for a verified payment or expiration notification before releasing stock".into(),
                ));
            }
            sqlx::query("UPDATE payments SET state='canceled',message='Canceled by user',updated_at=NOW() WHERE id=$1")
                .bind(payment_id).execute(&mut *tx).await?;
        }
        Self::release_product_stock(&mut tx, &order).await?;
        let order = sqlx::query_as::<_, Order>(
            "UPDATE orders SET state='Canceled',error_text='Canceled by user',updated_at=NOW() WHERE id=$1 RETURNING *",
        ).bind(order_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
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
        if !matches!(
            Self::normalize_provider_type(&provider.provider_type).as_str(),
            "stripe" | "paypal"
        ) {
            return Err(AppError::Authentication(
                "This payment provider does not accept public notifications".into(),
            ));
        }
        if provider.owner != payment.owner {
            return Err(AppError::Authorization(
                "Payment references another tenant".into(),
            ));
        }
        let payment_provider = build_payment_provider(&provider)?;
        let notify_result = payment_provider
            .notify(body, headers, payment.out_order_id.as_deref())
            .await?;

        if Self::map_provider_payment_state(&notify_result.payment_status) == "paid"
            && (notify_result.amount.is_none() || notify_result.currency.is_none())
        {
            return Err(AppError::Authentication(
                "A settled payment notification must include amount and currency".into(),
            ));
        }

        if let Some(amount) = notify_result.amount
            && (!amount.is_finite() || (amount - payment.amount).abs() > 0.000001)
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

        Self::apply_payment_state(
            pool,
            payment_id,
            &notify_result.payment_status,
            notify_result.raw_state.as_deref(),
            notify_result.invoice_url.as_deref(),
            true,
        )
        .await
    }

    pub async fn manual_notify_payment(
        pool: &PgPool,
        payment_id: &str,
        state: &str,
        message: Option<&str>,
        invoice_url: Option<&str>,
    ) -> AppResult<PaymentNotifyResult> {
        Self::apply_payment_state(pool, payment_id, state, message, invoice_url, false).await
    }

    async fn apply_payment_state(
        pool: &PgPool,
        payment_id: &str,
        state: &str,
        message: Option<&str>,
        invoice_url: Option<&str>,
        verified: bool,
    ) -> AppResult<PaymentNotifyResult> {
        let new_state = Self::map_provider_payment_state(state);
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *tx)
            .await?;
        // Lock the order first, exactly as start/cancel do. Never invert this
        // order by locking the payment before its order.
        let order = Self::load_order_by_payment_optional_tx(&mut tx, payment_id).await?;
        let payment = Self::load_payment_for_update(&mut tx, payment_id).await?;
        if Self::is_terminal_payment_state(&payment.state) {
            tx.commit().await?;
            return Ok(PaymentNotifyResult {
                payment: payment.into(),
                order: order.map(Into::into),
                transaction_name: None,
                verified,
            });
        }
        let provider_id = payment.provider_id.as_deref().ok_or_else(|| {
            AppError::Validation("Payment provider is required for settlement".into())
        })?;
        let provider = Self::load_provider_by_id_tx(&mut tx, provider_id).await?;
        if provider.owner != payment.owner
            || order.as_ref().is_some_and(|o| o.owner != payment.owner)
        {
            return Err(AppError::Authorization(
                "Payment references another tenant".into(),
            ));
        }
        let payment = sqlx::query_as::<_, Payment>(
            "UPDATE payments SET state=$2,message=COALESCE($3,message),invoice_url=COALESCE($4,invoice_url),updated_at=NOW() WHERE id=$1 RETURNING *",
        ).bind(payment_id).bind(&new_state).bind(message).bind(invoice_url)
            .fetch_one(&mut *tx).await?;
        let mut transaction_name = None;
        let order = if let Some(order) = order {
            if new_state == "paid" {
                // Legacy orders without a reservation are checked under the
                // same product lock before their first settlement.
                Self::update_product_stock(&mut tx, &order).await?;
                transaction_name =
                    Self::create_purchase_transaction(&mut tx, &order, &payment, &provider, None)
                        .await?;
                Self::fulfill_order_benefit(&mut tx, &order, &payment, &provider).await?;
            } else if Self::is_terminal_payment_state(&new_state) {
                Self::release_product_stock(&mut tx, &order).await?;
            }
            let error = if new_state != "paid" && Self::is_terminal_payment_state(&new_state) {
                payment.message.clone()
            } else {
                None
            };
            Some(sqlx::query_as::<_, Order>(
                "UPDATE orders SET state=$2,error_text=$3,updated_at=NOW() WHERE id=$1 RETURNING *",
            ).bind(&order.id).bind(Self::map_payment_state_to_order_state(&new_state))
                .bind(error).fetch_one(&mut *tx).await?)
        } else {
            None
        };
        tx.commit().await?;
        Ok(PaymentNotifyResult {
            payment: payment.into(),
            order: order.map(Into::into),
            transaction_name,
            verified,
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
        mut tx: Transaction<'_, Postgres>,
        order: Order,
        provider: Provider,
        return_url: String,
    ) -> AppResult<PaymentStartResult> {
        Self::reserve_product_stock(&mut tx, &order).await?;
        let user = Self::load_order_user_for_update(&mut tx, &order).await?;
        Self::validate_balance_currency(
            &json!({"balance_currency":user.balance_currency,"currency":user.currency}),
            order.currency.as_deref().unwrap_or("USD"),
        )?;
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
        let benefit = Self::fulfill_order_benefit(&mut tx, &order, &payment, &provider).await?;
        tx.commit().await?;

        Ok(PaymentStartResult {
            order: order.into(),
            payment: payment.clone().into(),
            pay_url: payment.pay_url.clone(),
            auto_paid: true,
            attach_info: json!({ "transactionName": transaction_name,"benefit":benefit }),
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

        let user = if order.user.is_some() {
            Some(Self::load_order_user_for_update(tx, order).await?)
        } else {
            None
        };
        // The reservation pins the purchased SKU even if its catalogue entry is
        // archived or renamed while the external checkout is awaiting payment.
        let product_id: Option<String> =
            sqlx::query_scalar("SELECT product_id FROM order_stock_reservations WHERE order_id=$1")
                .bind(&order.id)
                .fetch_optional(&mut **tx)
                .await?;
        let product_id = if product_id.is_some() {
            product_id
        } else if let Some(product_name) = order.product_name.as_deref() {
            sqlx::query_scalar::<_, String>(
                "SELECT id FROM products WHERE owner=$1 AND name=$2 LIMIT 1",
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

    pub fn validate_balance_currency(user: &Value, currency: &str) -> AppResult<()> {
        let expected = user
            .get("balance_currency")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                user.get("currency")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or("USD");
        if !expected.eq_ignore_ascii_case(currency) {
            return Err(AppError::Validation(
                "Payment currency does not match the account balance currency".into(),
            ));
        }
        Ok(())
    }

    async fn validate_benefit_checkout(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
        provider: &Provider,
    ) -> AppResult<()> {
        let benefit =
            sqlx::query_as::<_, PurchaseBenefit>("SELECT * FROM order_benefits WHERE order_id=$1")
                .bind(&order.id)
                .fetch_optional(&mut **tx)
                .await?;
        if let Some(benefit) = benefit {
            if order.quantity != 1
                || benefit.amount_cents
                    != crate::services::ProductService::validate_price(
                        order.price,
                        benefit.kind == "recharge",
                    )?
            {
                return Err(AppError::Validation(
                    "Checkout does not match its purchase benefit snapshot".into(),
                ));
            }
            let user: User =
                sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND is_deleted=false")
                    .bind(&benefit.user_id)
                    .bind(&order.owner)
                    .fetch_optional(&mut **tx)
                    .await?
                    .ok_or_else(|| {
                        AppError::Authorization("The purchase beneficiary is unavailable".into())
                    })?;
            if user.id != benefit.user_id || user.is_forbidden {
                return Err(AppError::Authorization(
                    "The purchase beneficiary is unavailable".into(),
                ));
            }
            if benefit.kind == "recharge" {
                if Self::normalize_provider_type(&provider.provider_type) == "balance" {
                    return Err(AppError::Validation(
                        "Recharge requires an external payment provider".into(),
                    ));
                }
                Self::validate_balance_currency(
                    &json!({"balance_currency":user.balance_currency,"currency":user.currency}),
                    order.currency.as_deref().unwrap_or("USD"),
                )?;
            }
        } else if let Some(name) = order.product_name.as_deref() {
            let special: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM products WHERE owner=$1 AND name=$2 AND (is_recharge=true OR plan_id IS NOT NULL))")
                .bind(&order.owner).bind(name).fetch_one(&mut **tx).await?;
            if special {
                return Err(AppError::Validation(
                    "Use buy-product to create a plan or recharge checkout".into(),
                ));
            }
        }
        Ok(())
    }

    async fn fulfill_order_benefit(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
        payment: &Payment,
        provider: &Provider,
    ) -> AppResult<Value> {
        let benefit = sqlx::query_as::<_, PurchaseBenefit>(
            "SELECT * FROM order_benefits WHERE order_id=$1 FOR UPDATE",
        )
        .bind(&order.id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(benefit) = benefit else {
            return Ok(Value::Null);
        };
        if benefit.fulfilled_at.is_some() {
            return Ok(Value::Null);
        }
        if !payment.state.eq_ignore_ascii_case("paid")
            || benefit.amount_cents
                != crate::services::ProductService::validate_price(
                    payment.amount,
                    benefit.kind == "recharge",
                )?
        {
            return Err(AppError::Validation(
                "Payment does not match its purchase benefit".into(),
            ));
        }
        let user = Self::load_order_user_for_update(tx, order).await?;
        if user.id != benefit.user_id {
            return Err(AppError::Authorization(
                "The purchase beneficiary changed".into(),
            ));
        }
        let mut subscription_id: Option<String> = None;
        let result = if benefit.kind == "recharge" {
            if Self::normalize_provider_type(&provider.provider_type) == "balance" {
                return Err(AppError::Validation(
                    "Balance payments cannot recharge an account".into(),
                ));
            }
            let currency = order.currency.as_deref().unwrap_or("USD");
            Self::validate_balance_currency(
                &json!({"balance_currency":user.balance_currency,"currency":user.currency}),
                currency,
            )?;
            let absolute =
                crate::services::ProductService::validate_price(user.balance.abs(), false)?;
            let current = if user.balance < 0.0 {
                -absolute
            } else {
                absolute
            };
            let new_cents = current
                .checked_add(benefit.amount_cents)
                .filter(|v| v.abs() <= 900_000_000_000_000)
                .ok_or_else(|| {
                    AppError::Validation(
                        "Recharge would exceed the supported account balance".into(),
                    )
                })?;
            let balance = new_cents as f64 / 100.0;
            sqlx::query("UPDATE users SET balance=$2,updated_at=NOW() WHERE id=$1 AND owner=$3")
                .bind(&user.id)
                .bind(balance)
                .bind(&order.owner)
                .execute(&mut **tx)
                .await?;
            let product_id: Option<String> = sqlx::query_scalar(
                "SELECT product_id FROM order_stock_reservations WHERE order_id=$1",
            )
            .bind(&order.id)
            .fetch_optional(&mut **tx)
            .await?;
            sqlx::query("INSERT INTO transactions(id,owner,name,display_name,provider_id,category,transaction_type,product_id,user_id,application,amount,currency,balance,state) VALUES($1,$2,$3,'Account recharge',$4,'recharge',$5,$6,$7,$8,$9,$10,$11,'paid')")
                .bind(Uuid::new_v4().to_string()).bind(&order.owner).bind(format!("recharge_{}",payment.name))
                .bind(&provider.id).bind(Self::normalize_provider_type(&provider.provider_type))
                .bind(product_id).bind(&user.id).bind(&user.signup_application)
                .bind(benefit.amount_cents as f64/100.0).bind(currency).bind(balance)
                .execute(&mut **tx).await?;
            json!({"kind":"recharge","creditedAmount":benefit.amount_cents as f64/100.0,"balance":balance})
        } else {
            let plan_id = benefit
                .plan_id
                .as_deref()
                .ok_or_else(|| AppError::Validation("Purchase plan is missing".into()))?;
            let pricing_id = benefit
                .pricing_id
                .as_deref()
                .ok_or_else(|| AppError::Validation("Purchase pricing is missing".into()))?;
            let period = benefit
                .period
                .as_deref()
                .ok_or_else(|| AppError::Validation("Purchase period is missing".into()))?;
            let same_tenant: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM plans p JOIN pricings pr ON pr.id=$2 AND pr.owner=p.owner WHERE p.id=$1 AND p.owner=$3) AND ($4::text IS NULL OR EXISTS(SELECT 1 FROM roles WHERE id=$4 AND owner=$3))")
                .bind(plan_id).bind(pricing_id).bind(&order.owner).bind(&benefit.role_id).fetch_one(&mut **tx).await?;
            if !same_tenant {
                return Err(AppError::Authorization(
                    "Plan purchase references another tenant".into(),
                ));
            }
            // The beneficiary row lock serializes different paid orders for the
            // same account. Their extensions cannot overwrite each other.
            let suspended: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM subscriptions WHERE owner=$1 AND user_id=$2 AND plan_id=$3 AND is_deleted=false AND lower(state)='suspended')")
                .bind(&order.owner).bind(&user.id).bind(plan_id).fetch_one(&mut **tx).await?;
            if suspended {
                return Err(AppError::Conflict(
                    "The purchased plan is suspended; an administrator must resolve the payment"
                        .into(),
                ));
            }
            let existing=sqlx::query_as::<_,crate::models::Subscription>("SELECT * FROM subscriptions WHERE owner=$1 AND user_id=$2 AND plan_id=$3 AND pricing_id=$4 AND is_deleted=false AND lower(state) IN ('active','expired') ORDER BY end_date DESC NULLS FIRST LIMIT 1 FOR UPDATE")
                .bind(&order.owner).bind(&user.id).bind(plan_id).bind(pricing_id).fetch_optional(&mut **tx).await?;
            let now = Utc::now();
            let (id, start) = if let Some(existing) = &existing {
                let end = existing.end_date.ok_or_else(|| {
                    AppError::Conflict(
                        "A lifetime subscription does not need a paid renewal".into(),
                    )
                })?;
                (existing.id.clone(), end.max(now))
            } else {
                (Uuid::new_v4().to_string(), now)
            };
            let months = match period {
                "monthly" => 1,
                "yearly" => 12,
                _ => {
                    return Err(AppError::Validation(
                        "Unsupported subscription period".into(),
                    ));
                }
            };
            let end = start
                .checked_add_months(Months::new(months))
                .ok_or_else(|| {
                    AppError::Validation("Subscription end date is out of range".into())
                })?;
            if existing.is_some() {
                sqlx::query("UPDATE subscriptions SET end_date=$2,state='active',period=$3,updated_at=NOW() WHERE id=$1")
                    .bind(&id).bind(end).bind(period).execute(&mut **tx).await?;
            } else {
                sqlx::query("INSERT INTO subscriptions(id,owner,name,display_name,user_id,plan_id,pricing_id,start_date,end_date,period,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active')")
                    .bind(&id).bind(&order.owner).bind(format!("sub_{id}"))
                    .bind(order.product_display_name.as_deref().unwrap_or(&order.display_name))
                    .bind(&user.id).bind(plan_id).bind(pricing_id).bind(start).bind(end).bind(period)
                    .execute(&mut **tx).await?;
            }
            sqlx::query("INSERT INTO subscription_grants(id,subscription_id,order_id,owner,user_id,role_id,starts_at,ends_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(Uuid::new_v4().to_string()).bind(&id).bind(&order.id).bind(&order.owner)
                .bind(&user.id).bind(&benefit.role_id).bind(start).bind(end).execute(&mut **tx).await?;
            subscription_id = Some(id.clone());
            json!({"kind":"plan","subscriptionId":id,"period":period,"startsAt":start,"endsAt":end})
        };
        sqlx::query("UPDATE order_benefits SET fulfilled_at=NOW(),subscription_id=$2 WHERE order_id=$1 AND fulfilled_at IS NULL")
            .bind(&order.id).bind(subscription_id).execute(&mut **tx).await?;
        Ok(result)
    }

    fn authorize_order(order: &Order, owner: &str, name: &str, admin: bool) -> AppResult<()> {
        let global_admin = admin && owner == "built-in";
        if !global_admin
            && (order.owner != owner || (!admin && order.user.as_deref() != Some(name)))
        {
            return Err(AppError::Authorization(
                "Unauthorized order operation".into(),
            ));
        }
        Ok(())
    }

    fn validate_order_amount(order: &Order) -> AppResult<()> {
        if order.quantity <= 0
            || !order.price.is_finite()
            || order.price < 0.0
            || order.price > 9_000_000_000_000.0
            || ((order.price * 100.0).round() - order.price * 100.0).abs() > 0.000001
        {
            return Err(AppError::Validation(
                "Invalid order quantity or amount; checkout uses cents".into(),
            ));
        }
        Ok(())
    }

    async fn reserve_product_stock(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
    ) -> AppResult<()> {
        let Some(name) = order.product_name.as_deref().filter(|s| !s.is_empty()) else {
            return Ok(());
        };
        let existing: Option<String> =
            sqlx::query_scalar("SELECT state FROM order_stock_reservations WHERE order_id=$1")
                .bind(&order.id)
                .fetch_optional(&mut **tx)
                .await?;
        if let Some(state) = existing {
            return if state == "reserved" {
                Ok(())
            } else {
                Err(AppError::Validation(
                    "Order inventory reservation has already been finalized".into(),
                ))
            };
        }
        let product = sqlx::query("SELECT id,quantity,state FROM products WHERE owner=$1 AND name=$2 AND is_deleted=false FOR UPDATE")
            .bind(&order.owner).bind(name).fetch_optional(&mut **tx).await?
            .ok_or_else(|| AppError::NotFound(format!("Product '{}/{}' not found",order.owner,name)))?;
        let stock: i32 = product.try_get("quantity")?;
        let state: String = product.try_get("state")?;
        if !matches!(
            state.to_ascii_lowercase().as_str(),
            "active" | "published" | "on sale"
        ) {
            return Err(AppError::Validation("Product is not for sale".into()));
        }
        let recharge: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM order_benefits WHERE order_id=$1 AND kind='recharge')",
        )
        .bind(&order.id)
        .fetch_one(&mut **tx)
        .await?;
        let finite = stock >= 0 && !recharge;
        if finite && stock < order.quantity {
            return Err(AppError::Validation(format!(
                "Product '{}' does not have enough stock",
                name
            )));
        }
        let product_id: String = product.try_get("id")?;
        if finite {
            sqlx::query("UPDATE products SET quantity=quantity-$2,updated_at=NOW() WHERE id=$1")
                .bind(&product_id)
                .bind(order.quantity)
                .execute(&mut **tx)
                .await?;
        }
        sqlx::query("INSERT INTO order_stock_reservations(order_id,product_id,quantity,finite_stock) VALUES($1,$2,$3,$4)")
            .bind(&order.id).bind(&product_id).bind(order.quantity).bind(finite).execute(&mut **tx).await?;
        Ok(())
    }

    async fn release_product_stock(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
    ) -> AppResult<()> {
        let reservation = sqlx::query("UPDATE order_stock_reservations SET state='released',updated_at=NOW() WHERE order_id=$1 AND state='reserved' RETURNING product_id,quantity,finite_stock")
            .bind(&order.id).fetch_optional(&mut **tx).await?;
        if let Some(row) = reservation {
            if row.try_get::<bool, _>("finite_stock")? {
                sqlx::query(
                    "UPDATE products SET quantity=quantity+$2,updated_at=NOW() WHERE id=$1",
                )
                .bind(row.try_get::<String, _>("product_id")?)
                .bind(row.try_get::<i32, _>("quantity")?)
                .execute(&mut **tx)
                .await?;
            }
        }
        Ok(())
    }

    async fn update_product_stock(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
    ) -> AppResult<()> {
        if order.product_name.as_deref().is_none_or(str::is_empty) {
            return Ok(());
        }
        let state: Option<String> =
            sqlx::query_scalar("SELECT state FROM order_stock_reservations WHERE order_id=$1")
                .bind(&order.id)
                .fetch_optional(&mut **tx)
                .await?;
        match state.as_deref() {
            Some("consumed") => return Ok(()),
            Some("released") => {
                return Err(AppError::Validation(
                    "Order inventory reservation was released".into(),
                ));
            }
            None => Self::reserve_product_stock(tx, order).await?,
            _ => (),
        }
        let product_id: String = sqlx::query_scalar("UPDATE order_stock_reservations SET state='consumed',updated_at=NOW() WHERE order_id=$1 AND state='reserved' RETURNING product_id")
            .bind(&order.id).fetch_one(&mut **tx).await?;
        sqlx::query("UPDATE products SET sold=sold+$2,updated_at=NOW() WHERE id=$1")
            .bind(product_id)
            .bind(order.quantity)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn load_order_for_update(
        tx: &mut Transaction<'_, Postgres>,
        id: &str,
    ) -> AppResult<Order> {
        sqlx::query_as::<_, Order>(
            "SELECT * FROM orders WHERE id=$1 AND is_deleted=false FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Order '{}' not found", id)))
    }

    async fn resolve_provider(
        tx: &mut Transaction<'_, Postgres>,
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
                .fetch_optional(&mut **tx)
                .await?
        {
            if provider.owner != owner || !provider.category.eq_ignore_ascii_case("payment") {
                return Err(AppError::Authorization(
                    "Checkout requires a payment provider from the order's tenant".into(),
                ));
            }
            return Ok(provider);
        }

        let name = if let Some((hint_owner, name)) = hint.split_once('/') {
            if hint_owner != owner {
                return Err(AppError::Authorization(
                    "Checkout provider belongs to another tenant".into(),
                ));
            }
            name
        } else {
            hint
        };
        let provider = sqlx::query_as::<_, Provider>(
            "SELECT * FROM providers WHERE owner = $1 AND name = $2 LIMIT 1",
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Provider '{}/{}' not found", owner, hint)))?;
        if !provider.category.eq_ignore_ascii_case("payment") {
            return Err(AppError::Validation(
                "Checkout requires a payment provider".into(),
            ));
        }
        Ok(provider)
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

    async fn load_provider_by_id_tx(
        tx: &mut Transaction<'_, Postgres>,
        id: &str,
    ) -> AppResult<Provider> {
        sqlx::query_as::<_, Provider>("SELECT * FROM providers WHERE id=$1")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| AppError::NotFound("Payment provider not found".into()))
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

    async fn load_order_user_for_update(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
    ) -> AppResult<User> {
        let user_name = order
            .user
            .as_deref()
            .ok_or_else(|| AppError::Validation("Order user is required".to_string()))?;
        sqlx::query_as::<_, User>(
            "SELECT u.* FROM users u WHERE u.owner=$1 AND u.is_deleted=false AND u.id=COALESCE((SELECT user_id FROM order_benefits WHERE order_id=$3),(SELECT id FROM users WHERE owner=$1 AND name=$2 AND is_deleted=false)) FOR UPDATE OF u",
        )
        .bind(&order.owner)
        .bind(user_name)
        .bind(&order.id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("User '{}/{}' not found", order.owner, user_name))
        })
    }
}
