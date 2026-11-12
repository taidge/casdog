use std::collections::HashMap;

use chrono::{DateTime, Months, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::{Order, OrderResponse, Payment, PaymentResponse, Provider, User};
use crate::services::providers::payment_provider::{
    NotifyResult, PayRequest, PaymentProvider, build_payment_provider, validate_checkout_url,
};

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
    /// Internal Balance renewal capability. The durable work token is checked
    /// inside the very transaction that debits funds; no user JWT is synthesized.
    pub(crate) async fn pay_subscription_renewal(
        pool: &PgPool,
        work_id: &str,
        token: &str,
        order_id: &str,
    ) -> AppResult<PaymentStartResult> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *tx)
            .await?;
        let order = Self::load_order_for_update(&mut tx, order_id).await?;
        if let Some(payment_id) = order.payment_id.as_deref().filter(|s| !s.is_empty()) {
            let payment = Self::load_payment_for_update(&mut tx, payment_id).await?;
            if payment.state.eq_ignore_ascii_case("paid") {
                tx.commit().await?;
                return Ok(Self::start_result(order, payment, json!({})));
            }
            return Err(AppError::Conflict(
                "A renewal already has a pending payment".into(),
            ));
        }
        if !order.state.eq_ignore_ascii_case("created") {
            return Err(AppError::Conflict("Renewal order is not payable".into()));
        }
        Self::validate_order_amount(&order)?;
        let provider =
            Self::resolve_provider(&mut tx, &order.owner, None, order.provider.as_deref()).await?;
        if Self::normalize_provider_type(&provider.provider_type) != "balance" {
            return Err(AppError::Conflict(
                "Background renewal requires an authorized Balance provider".into(),
            ));
        }
        // Preserve checkout's order -> product -> user -> subscription ordering.
        let _: Option<String> =
            sqlx::query_scalar("SELECT id FROM products WHERE owner=$1 AND name=$2 FOR UPDATE")
                .bind(&order.owner)
                .bind(&order.product_name)
                .fetch_optional(&mut *tx)
                .await?;
        Self::load_order_user_for_update(&mut tx, &order).await?;
        super::subscription_renewal_service::SubscriptionRenewalService::validate_balance_charge(
            &mut tx, work_id, token, &order, &provider,
        )
        .await?;
        Self::validate_benefit_checkout(&mut tx, &order, &provider).await?;
        let return_url = Self::build_return_url(&order, None, None);
        Self::pay_with_balance(tx, order, provider, return_url).await
    }

    pub(crate) async fn reconcile_in_background(
        pool: &PgPool,
        order_id: &str,
        gateway: Option<&dyn PaymentProvider>,
    ) -> AppResult<PaymentStartResult> {
        Self::remote_order_action(pool, order_id, "", "", false, gateway, false, true).await
    }
    pub async fn start_order_payment(
        pool: &PgPool,
        order_id: &str,
        provider_hint: Option<&str>,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
        external_origin: Option<&str>,
    ) -> AppResult<PaymentStartResult> {
        Self::start_order_payment_inner(
            pool,
            order_id,
            provider_hint,
            current_owner,
            current_name,
            is_admin,
            external_origin,
            None,
        )
        .await
    }

    /// Explicit transport injection for embedded gateways and HTTP integration
    /// tests. HTTP handlers always use the provider factory above.
    pub async fn start_order_payment_using(
        pool: &PgPool,
        order_id: &str,
        provider_hint: Option<&str>,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
        external_origin: Option<&str>,
        gateway: &dyn PaymentProvider,
    ) -> AppResult<PaymentStartResult> {
        Self::start_order_payment_inner(
            pool,
            order_id,
            provider_hint,
            current_owner,
            current_name,
            is_admin,
            external_origin,
            Some(gateway),
        )
        .await
    }

    async fn start_order_payment_inner(
        pool: &PgPool,
        order_id: &str,
        provider_hint: Option<&str>,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
        external_origin: Option<&str>,
        gateway: Option<&dyn PaymentProvider>,
    ) -> AppResult<PaymentStartResult> {
        // All mutations use the same lock order: order, payment, product, user.
        // This serializes checkout creation across server instances as well as
        // cancellation and webhooks, without a process-local mutex.
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *tx)
            .await?;
        let order = Self::load_order_for_update(&mut tx, order_id).await?;
        Self::authorize_order(&mut tx, &order, current_owner, current_name, is_admin).await?;
        if let Some(payment_id) = order.payment_id.as_deref().filter(|id| !id.is_empty()) {
            let payment = Self::load_payment_for_update(&mut tx, payment_id).await?;
            if !Self::is_terminal_payment_state(&payment.state)
                || payment.state.eq_ignore_ascii_case("paid")
            {
                if Self::is_terminal_payment_state(&payment.state)
                    || payment.pay_url.as_deref().is_some_and(|u| !u.is_empty())
                    || payment
                        .out_order_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty() && id != payment.id)
                {
                    tx.commit().await?;
                    return Ok(Self::start_result(order, payment, json!({})));
                }
                let provider_id = payment
                    .provider_id
                    .as_deref()
                    .ok_or_else(|| AppError::Validation("Payment provider is missing".into()))?;
                let provider = Self::load_provider_by_id_tx(&mut tx, provider_id).await?;
                Self::check_provider_identity(&order, &payment, &provider)?;
                let Some((request, token, attempt)) =
                    Self::claim_checkout_create(&mut tx, &payment, &provider).await?
                else {
                    tx.commit().await?;
                    return Ok(Self::start_result(order, payment, json!({"retryAfter":45})));
                };
                tx.commit().await?;
                return Self::dispatch_checkout(
                    pool, order, payment, provider, request, token, attempt, gateway,
                )
                .await;
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
        if gateway.is_none() {
            build_payment_provider(&provider)?;
        }
        Self::reserve_product_stock(&mut tx, &order).await?;
        let payment_id = Uuid::new_v4().to_string();
        let payment_name = format!("payment_{}", &payment_id[..12]);
        let return_url = Self::build_return_url(&order, external_origin, Some(&payment_id));
        let payer = Self::load_order_user_for_update(&mut tx, &order).await.ok();
        let payer_email = payer.as_ref().and_then(|u| u.email.clone());
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
        .bind(payer.as_ref().map(|u| &u.id))
        .bind(order.price)
        .bind(order.currency.clone().unwrap_or_else(|| "USD".to_string()))
        .bind(&return_url)
        .fetch_one(&mut *tx)
        .await?;
        let order = sqlx::query_as::<_, Order>(
            "UPDATE orders SET provider=$2,payment_id=$3,payment_name=$4,return_url=COALESCE(return_url,$5),updated_at=NOW() WHERE id=$1 RETURNING *",
        ).bind(&order.id).bind(&provider.name).bind(&payment.id).bind(&payment.name)
            .bind(&return_url).fetch_one(&mut *tx).await?;
        let request = PayRequest {
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
            currency: order.currency.clone().unwrap_or_else(|| "USD".into()),
            quantity: 1,
            return_url,
            order_id: payment_id,
            payer_name: order.user.clone(),
            payer_email,
        };
        let token = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO payment_remote_operations(payment_id,checkout_request,provider_fingerprint,create_retry_until,lease_token,lease_kind,lease_until,attempts) VALUES($1,$2,$3,clock_timestamp()+$4::bigint*INTERVAL '1 second',$5,'create',clock_timestamp()+INTERVAL '45 seconds',1)")
            .bind(&payment.id).bind(serde_json::to_value(&request).map_err(|e|AppError::Internal(e.to_string()))?)
            .bind(Self::provider_fingerprint(&provider)).bind(Self::create_retry_seconds(&provider)).bind(&token).execute(&mut *tx).await?;
        // Persist the exact payload and provider identity before outbound I/O.
        tx.commit().await?;
        Self::dispatch_checkout(pool, order, payment, provider, request, token, 1, gateway).await
    }

    fn start_result(order: Order, payment: Payment, attach_info: Value) -> PaymentStartResult {
        PaymentStartResult {
            order: order.into(),
            pay_url: payment.pay_url.clone(),
            auto_paid: payment.state.eq_ignore_ascii_case("paid"),
            payment: payment.into(),
            attach_info,
        }
    }

    fn provider_fingerprint(provider: &Provider) -> String {
        let identity = json!([
            provider.id,
            provider.provider_type,
            provider.client_id,
            provider.client_secret,
            provider.host
        ]);
        hex::encode(Sha256::digest(identity.to_string().as_bytes()))
    }

    fn check_provider_identity(
        order: &Order,
        payment: &Payment,
        provider: &Provider,
    ) -> AppResult<()> {
        if order.owner != payment.owner
            || provider.owner != order.owner
            || !provider.category.eq_ignore_ascii_case("payment")
            || Self::normalize_provider_type(&payment.payment_type)
                != Self::normalize_provider_type(&provider.provider_type)
        {
            return Err(AppError::Conflict(
                "Checkout provider identity has changed; operator reconciliation is required"
                    .into(),
            ));
        }
        Ok(())
    }

    fn create_retry_seconds(provider: &Provider) -> i64 {
        // Stripe keeps keys for >=24h; PayPal Orders documents 6h. Leave a
        // conservative margin instead of creating another object after expiry.
        if Self::normalize_provider_type(&provider.provider_type) == "paypal" {
            5 * 3600
        } else {
            23 * 3600
        }
    }

    async fn claim_checkout_create(
        tx: &mut Transaction<'_, Postgres>,
        payment: &Payment,
        provider: &Provider,
    ) -> AppResult<Option<(PayRequest, String, i32)>> {
        let row=sqlx::query("SELECT *,lease_until>clock_timestamp() AS leased,create_retry_until>clock_timestamp() AS safe_retry FROM payment_remote_operations WHERE payment_id=$1 FOR UPDATE")
            .bind(&payment.id).fetch_optional(&mut **tx).await?
            .ok_or_else(||AppError::Conflict("Legacy checkout has no original request snapshot; reconcile it with the provider before retrying".into()))?;
        if row.try_get::<Option<bool>, _>("leased")?.unwrap_or(false) {
            return Ok(None);
        }
        if !row
            .try_get::<Option<bool>, _>("safe_retry")?
            .unwrap_or(false)
        {
            return Err(AppError::Conflict("Checkout creation idempotency window has elapsed; operator reconciliation is required".into()));
        }
        if row
            .try_get::<Option<String>, _>("provider_fingerprint")?
            .as_deref()
            != Some(Self::provider_fingerprint(provider).as_str())
        {
            return Err(AppError::Conflict(
                "Checkout credentials changed; an unknown payment cannot be recreated safely"
                    .into(),
            ));
        }
        let original: Value = row
            .try_get::<Option<Value>, _>("checkout_request")?
            .ok_or_else(|| AppError::Conflict("Original checkout request is unavailable".into()))?;
        let request: PayRequest = serde_json::from_value(original)
            .map_err(|_| AppError::Internal("Invalid original checkout request".into()))?;
        if request.order_id != payment.id
            || request.price != payment.amount
            || payment.currency.as_deref() != Some(request.currency.as_str())
        {
            return Err(AppError::Conflict(
                "Original checkout request does not match payment".into(),
            ));
        }
        let token = Uuid::new_v4().to_string();
        let attempts: i32=sqlx::query_scalar("UPDATE payment_remote_operations SET lease_token=$2,lease_kind='create',lease_until=clock_timestamp()+INTERVAL '45 seconds',attempts=attempts+1,updated_at=NOW() WHERE payment_id=$1 RETURNING attempts")
            .bind(&payment.id).bind(&token).fetch_one(&mut **tx).await?;
        Ok(Some((request, token, attempts)))
    }

    async fn dispatch_checkout(
        pool: &PgPool,
        order: Order,
        payment: Payment,
        provider: Provider,
        request: PayRequest,
        token: String,
        attempt: i32,
        gateway: Option<&dyn PaymentProvider>,
    ) -> AppResult<PaymentStartResult> {
        let native = if gateway.is_none() {
            Some(build_payment_provider(&provider)?)
        } else {
            None
        };
        let driver = gateway
            .or_else(|| native.as_deref())
            .ok_or_else(|| AppError::Internal("Payment transport unavailable".into()))?;
        let remote =
            tokio::time::timeout(std::time::Duration::from_secs(30), driver.pay(&request)).await;
        let response = match remote {
            Ok(Ok(response)) => response,
            result => {
                let error = match result {
                    Ok(Err(error)) => error,
                    _ => AppError::Internal(
                        "Checkout response timed out; payment remains recoverable".into(),
                    ),
                };
                // Only the first definitive rejection can prove that no remote
                // checkout exists. A rejected retry does not disprove an earlier
                // request with an unknown outcome.
                if attempt == 1 && matches!(&error, AppError::Validation(_)) {
                    Self::apply_payment_state_inner(
                        pool,
                        &payment.id,
                        "failed",
                        Some(&error.to_string()),
                        None,
                        false,
                        Some(&token),
                    )
                    .await?;
                }
                Self::release_remote_lease(pool, &payment.id, &token, Some(&error.to_string()))
                    .await?;
                return Err(error);
            }
        };
        if let Err(error) = validate_checkout_url(
            &Self::normalize_provider_type(&provider.provider_type),
            &response.pay_url,
        ) {
            Self::release_remote_lease(pool, &payment.id, &token, Some(&error.to_string())).await?;
            return Err(error);
        }
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *tx)
            .await?;
        let order = Self::load_order_for_update(&mut tx, &order.id).await?;
        let payment = Self::load_payment_for_update(&mut tx, &payment.id).await?;
        let lease: Option<String> = sqlx::query_scalar(
            "SELECT lease_token FROM payment_remote_operations WHERE payment_id=$1 FOR UPDATE",
        )
        .bind(&payment.id)
        .fetch_one(&mut *tx)
        .await?;
        let payment = if lease.as_deref() == Some(token.as_str())
            && (!Self::is_terminal_payment_state(&payment.state)
                || payment
                    .out_order_id
                    .as_deref()
                    .is_none_or(|id| id == payment.id || id.is_empty()))
        {
            // A webhook may settle before create returns. Keep its terminal
            // state but retain the provider ID for receipts and later audits.
            sqlx::query_as::<_,Payment>("UPDATE payments SET out_order_id=$2,pay_url=$3,message=CASE WHEN lower(state) IN ('paid','failed','canceled','timeout') THEN message ELSE 'Checkout ready' END,updated_at=NOW() WHERE id=$1 RETURNING *")
                .bind(&payment.id).bind(response.order_id).bind(response.pay_url).fetch_one(&mut *tx).await?
        } else {
            payment
        };
        sqlx::query("UPDATE payment_remote_operations SET lease_token=NULL,lease_kind=NULL,lease_until=NULL,last_error=NULL,updated_at=NOW() WHERE payment_id=$1 AND lease_token=$2")
            .bind(&payment.id).bind(token).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Self::start_result(order, payment, json!({})))
    }

    async fn release_remote_lease(
        pool: &PgPool,
        payment_id: &str,
        token: &str,
        error: Option<&str>,
    ) -> AppResult<()> {
        sqlx::query("UPDATE payment_remote_operations SET lease_token=NULL,lease_kind=NULL,lease_until=NULL,last_error=$3,updated_at=NOW() WHERE payment_id=$1 AND lease_token=$2")
            .bind(payment_id).bind(token).bind(error).execute(pool).await?;
        Ok(())
    }

    pub async fn cancel_order(
        pool: &PgPool,
        order_id: &str,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
    ) -> AppResult<OrderResponse> {
        Self::cancel_order_inner(pool, order_id, current_owner, current_name, is_admin, None).await
    }

    pub async fn cancel_order_using(
        pool: &PgPool,
        order_id: &str,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
        gateway: &dyn PaymentProvider,
    ) -> AppResult<OrderResponse> {
        Self::cancel_order_inner(
            pool,
            order_id,
            current_owner,
            current_name,
            is_admin,
            Some(gateway),
        )
        .await
    }

    async fn cancel_order_inner(
        pool: &PgPool,
        order_id: &str,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
        gateway: Option<&dyn PaymentProvider>,
    ) -> AppResult<OrderResponse> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *tx)
            .await?;
        let order = Self::load_order_for_update(&mut tx, order_id).await?;
        Self::authorize_order(&mut tx, &order, current_owner, current_name, is_admin).await?;
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
            let provider_type = Self::normalize_provider_type(&provider.provider_type);
            if !matches!(provider_type.as_str(), "dummy" | "balance") {
                if provider_type != "stripe" {
                    return Err(AppError::Conflict(
                        "This provider cannot confirm cancellation of a pending checkout".into(),
                    ));
                }
                tx.rollback().await?;
                let canceled = Self::remote_order_action(
                    pool,
                    order_id,
                    current_owner,
                    current_name,
                    is_admin,
                    gateway,
                    true,
                    false,
                )
                .await?;
                if !canceled.order.state.eq_ignore_ascii_case("canceled") {
                    return Err(AppError::Conflict(
                        "The payment settled before cancellation; refresh its status".into(),
                    ));
                }
                return Ok(canceled.order);
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

    pub async fn reconcile_order_payment(
        pool: &PgPool,
        order_id: &str,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
    ) -> AppResult<PaymentStartResult> {
        Self::remote_order_action(
            pool,
            order_id,
            current_owner,
            current_name,
            is_admin,
            None,
            false,
            false,
        )
        .await
    }

    pub async fn reconcile_order_payment_using(
        pool: &PgPool,
        order_id: &str,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
        gateway: &dyn PaymentProvider,
    ) -> AppResult<PaymentStartResult> {
        Self::remote_order_action(
            pool,
            order_id,
            current_owner,
            current_name,
            is_admin,
            Some(gateway),
            false,
            false,
        )
        .await
    }

    fn validate_remote_payment(
        payment: &Payment,
        result: &NotifyResult,
        require_amount: bool,
    ) -> AppResult<()> {
        if payment.out_order_id.as_deref() != Some(result.order_id.as_str()) {
            return Err(AppError::Authentication(
                "Provider response references another checkout".into(),
            ));
        }
        let paid = Self::map_provider_payment_state(&result.payment_status) == "paid";
        if (paid || require_amount) && (result.amount.is_none() || result.currency.is_none()) {
            return Err(AppError::Authentication(
                "Provider settlement must include its amount and currency".into(),
            ));
        }
        if let Some(amount) = result.amount {
            crate::services::ProductService::validate_price(amount, false)?;
            if (amount - payment.amount).abs() > 0.000001 {
                return Err(AppError::Authentication(
                    "Provider settlement amount does not match checkout".into(),
                ));
            }
        }
        if let Some(currency) = result.currency.as_deref() {
            if !payment
                .currency
                .as_deref()
                .unwrap_or("USD")
                .eq_ignore_ascii_case(currency)
            {
                return Err(AppError::Authentication(
                    "Provider settlement currency does not match checkout".into(),
                ));
            }
        }
        Ok(())
    }

    async fn claim_remote_operation(
        tx: &mut Transaction<'_, Postgres>,
        payment: &Payment,
        cancel: bool,
    ) -> AppResult<Option<String>> {
        // Legacy checkouts with an external ID are safe to query, but their
        // missing original POST payload is never fabricated for re-creation.
        sqlx::query("INSERT INTO payment_remote_operations(payment_id,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(&payment.id).bind(payment.created_at).execute(&mut **tx).await?;
        let leased: Option<bool>=sqlx::query_scalar("SELECT lease_until>clock_timestamp() FROM payment_remote_operations WHERE payment_id=$1 FOR UPDATE")
            .bind(&payment.id).fetch_one(&mut **tx).await?;
        if leased.unwrap_or(false) {
            return Ok(None);
        }
        let token = Uuid::new_v4().to_string();
        sqlx::query("UPDATE payment_remote_operations SET lease_token=$2,lease_kind=$3,lease_until=clock_timestamp()+INTERVAL '45 seconds',attempts=attempts+1,updated_at=NOW() WHERE payment_id=$1")
            .bind(&payment.id).bind(&token).bind(if cancel{"cancel"}else{"reconcile"}).execute(&mut **tx).await?;
        Ok(Some(token))
    }

    async fn claim_capture_key(
        pool: &PgPool,
        order_id: &str,
        payment_id: &str,
        token: &str,
    ) -> AppResult<Option<String>> {
        let mut tx = pool.begin().await?;
        Self::load_order_for_update(&mut tx, order_id).await?;
        let payment = Self::load_payment_for_update(&mut tx, payment_id).await?;
        if Self::is_terminal_payment_state(&payment.state) {
            return Ok(None);
        }
        let key: Option<String>=sqlx::query_scalar("UPDATE payment_remote_operations SET capture_retry_until=COALESCE(capture_retry_until,clock_timestamp()+INTERVAL '5 hours'),lease_until=clock_timestamp()+INTERVAL '45 seconds',updated_at=NOW() WHERE payment_id=$1 AND lease_token=$2 AND (capture_retry_until IS NULL OR capture_retry_until>clock_timestamp()) RETURNING capture_key")
            .bind(payment_id).bind(token).fetch_optional(&mut *tx).await?;
        let key=key.ok_or_else(||AppError::Conflict("Capture lease or idempotency window has expired; reconcile with the provider before retrying".into()))?;
        tx.commit().await?;
        Ok(Some(key))
    }

    async fn current_result(
        pool: &PgPool,
        order_id: &str,
        attach: Value,
    ) -> AppResult<PaymentStartResult> {
        let mut tx = pool.begin().await?;
        let order = Self::load_order_for_update(&mut tx, order_id).await?;
        let payment = Self::load_payment_for_update(
            &mut tx,
            order
                .payment_id
                .as_deref()
                .ok_or_else(|| AppError::NotFound("Order payment is missing".into()))?,
        )
        .await?;
        tx.commit().await?;
        Ok(Self::start_result(order, payment, attach))
    }

    async fn remote_order_action(
        pool: &PgPool,
        order_id: &str,
        current_owner: &str,
        current_name: &str,
        is_admin: bool,
        gateway: Option<&dyn PaymentProvider>,
        cancel: bool,
        background: bool,
    ) -> AppResult<PaymentStartResult> {
        let mut tx = pool.begin().await?;
        let order = Self::load_order_for_update(&mut tx, order_id).await?;
        if !background {
            Self::authorize_order(&mut tx, &order, current_owner, current_name, is_admin).await?;
        } else {
            // A server worker reconciles an already accepted payment, including
            // users disabled since checkout. It never fabricates a JWT/admin or
            // authorizes a new purchase; immutable order/payment identities and
            // the provider proof remain mandatory.
            let pinned: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM orders o JOIN users u ON u.id=o.buyer_id AND u.owner=o.owner WHERE o.id=$1)").bind(order_id).fetch_one(&mut *tx).await?;
            if !pinned || cancel {
                return Err(AppError::Authorization(
                    "Background reconciliation requires a pinned existing buyer".into(),
                ));
            }
        }
        let payment_id = order
            .payment_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::Validation("This order has no payment to reconcile".into()))?;
        let payment = Self::load_payment_for_update(&mut tx, payment_id).await?;
        if Self::is_terminal_payment_state(&payment.state) {
            tx.commit().await?;
            return Ok(Self::start_result(order, payment, json!({})));
        }
        let provider = Self::load_provider_by_id_tx(
            &mut tx,
            payment
                .provider_id
                .as_deref()
                .ok_or_else(|| AppError::Validation("Checkout provider is missing".into()))?,
        )
        .await?;
        Self::check_provider_identity(&order, &payment, &provider)?;
        let external = payment
            .out_order_id
            .as_deref()
            .filter(|s| !s.is_empty() && *s != payment.id)
            .map(str::to_owned);
        let Some(external) = external else {
            if cancel {
                return Err(AppError::Conflict(
                    "Recover the original checkout before requesting remote cancellation".into(),
                ));
            }
            if background {
                let Some((request, token, attempt)) =
                    Self::claim_checkout_create(&mut tx, &payment, &provider).await?
                else {
                    tx.commit().await?;
                    return Ok(Self::start_result(order, payment, json!({"retryAfter":45})));
                };
                tx.commit().await?;
                return Self::dispatch_checkout(
                    pool, order, payment, provider, request, token, attempt, gateway,
                )
                .await;
            }
            tx.rollback().await?;
            return Self::start_order_payment_inner(
                pool,
                order_id,
                None,
                current_owner,
                current_name,
                is_admin,
                None,
                gateway,
            )
            .await;
        };
        if cancel && Self::normalize_provider_type(&provider.provider_type) != "stripe" {
            return Err(AppError::Conflict(
                "This provider does not support remote order cancellation".into(),
            ));
        }
        let native = if gateway.is_none() {
            Some(build_payment_provider(&provider)?)
        } else {
            None
        };
        let driver = gateway
            .or_else(|| native.as_deref())
            .ok_or_else(|| AppError::Internal("Payment transport unavailable".into()))?;
        let Some(token) = Self::claim_remote_operation(&mut tx, &payment, cancel).await? else {
            if cancel {
                return Err(AppError::Conflict(
                    "Another payment operation is in progress; cancellation is not yet confirmed"
                        .into(),
                ));
            }
            tx.commit().await?;
            return Ok(Self::start_result(order, payment, json!({"retryAfter":45})));
        };
        tx.commit().await?;
        let work = async {
            let mut remote = if cancel {
                driver
                    .cancel_payment(&external, &payment.id, &format!("cancel_{}", payment.id))
                    .await?
            } else {
                driver.query_payment(&external, &payment.id).await?
            };
            Self::validate_remote_payment(&payment, &remote.result, remote.capture_required)?;
            if cancel
                && Self::map_provider_payment_state(&remote.result.payment_status) != "canceled"
            {
                return Err(AppError::Conflict(
                    "Provider did not confirm checkout cancellation".into(),
                ));
            }
            if remote.capture_required {
                let Some(key) =
                    Self::claim_capture_key(pool, order_id, &payment.id, &token).await?
                else {
                    return Ok(None);
                };
                remote = driver.capture_payment(&external, &payment.id, &key).await?;
                Self::validate_remote_payment(&payment, &remote.result, false)?;
            }
            if let Some(url) = remote.pay_url.as_deref() {
                validate_checkout_url(
                    &Self::normalize_provider_type(&provider.provider_type),
                    url,
                )?;
            }
            Ok::<_, AppError>(Some(remote))
        };
        let remote = match tokio::time::timeout(std::time::Duration::from_secs(30), work).await {
            Ok(Ok(remote)) => remote,
            other => {
                let error = match other {
                    Ok(Err(error)) => error,
                    _ => AppError::Internal(
                        "Provider reconciliation timed out; the payment remains pending".into(),
                    ),
                };
                Self::release_remote_lease(pool, &payment.id, &token, Some(&error.to_string()))
                    .await?;
                return Err(error);
            }
        };
        if let Some(remote) = remote {
            if let Some(url) = remote.pay_url {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
                    .execute(&mut *tx)
                    .await?;
                Self::load_order_for_update(&mut tx, order_id).await?;
                let current = Self::load_payment_for_update(&mut tx, &payment.id).await?;
                if !Self::is_terminal_payment_state(&current.state) {
                    sqlx::query("UPDATE payments SET pay_url=$2,updated_at=NOW() WHERE id=$1 AND EXISTS(SELECT 1 FROM payment_remote_operations WHERE payment_id=$1 AND lease_token=$3)")
                        .bind(&payment.id).bind(url).bind(&token).execute(&mut *tx).await?;
                }
                tx.commit().await?;
            }
            if let Err(error) = Self::apply_payment_state_inner(
                pool,
                &payment.id,
                &remote.result.payment_status,
                remote.result.raw_state.as_deref(),
                remote.result.invoice_url.as_deref(),
                true,
                Some(&token),
            )
            .await
            {
                Self::release_remote_lease(pool, &payment.id, &token, Some(&error.to_string()))
                    .await?;
                return Err(error);
            }
        }
        Self::release_remote_lease(pool, &payment.id, &token, None).await?;
        Self::current_result(pool, order_id, json!({"reconciled":true})).await
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
        Self::apply_payment_state_inner(
            pool,
            payment_id,
            state,
            message,
            invoice_url,
            verified,
            None,
        )
        .await
    }

    async fn apply_payment_state_inner(
        pool: &PgPool,
        payment_id: &str,
        state: &str,
        message: Option<&str>,
        invoice_url: Option<&str>,
        verified: bool,
        expected_lease: Option<&str>,
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
        if let Some(token) = expected_lease {
            let current: Option<String> = sqlx::query_scalar(
                "SELECT lease_token FROM payment_remote_operations WHERE payment_id=$1 FOR UPDATE",
            )
            .bind(payment_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
            if current.as_deref() != Some(token) {
                return Err(AppError::Conflict(
                    "Payment operation lease changed; refresh its current state".into(),
                ));
            }
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
        .bind(&user.id)
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

        let has_buyer: bool =
            sqlx::query_scalar("SELECT buyer_id IS NOT NULL FROM orders WHERE id=$1")
                .bind(&order.id)
                .fetch_one(&mut **tx)
                .await?;
        let user = if has_buyer {
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
            // A scheduled renewal belongs to its original subscription even
            // when another subscription for the same plan was created later.
            let renewal_target: Option<String> = sqlx::query_scalar(
                "SELECT subscription_id FROM subscription_renewal_work WHERE order_id=$1",
            )
            .bind(&order.id)
            .fetch_optional(&mut **tx)
            .await?;
            let existing=sqlx::query_as::<_,crate::models::Subscription>("SELECT * FROM subscriptions WHERE owner=$1 AND user_id=$2 AND plan_id=$3 AND pricing_id=$4 AND (($5::text IS NOT NULL AND id=$5) OR ($5::text IS NULL AND is_deleted=false AND lower(state) IN ('active','expired'))) ORDER BY end_date DESC NULLS FIRST LIMIT 1 FOR UPDATE")
                .bind(&order.owner).bind(&user.id).bind(plan_id).bind(pricing_id).bind(&renewal_target).fetch_optional(&mut **tx).await?;
            if renewal_target.is_some() && existing.is_none() {
                return Err(AppError::Conflict("The paid renewal's original subscription identity changed; reconciliation is required".into()));
            }

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
                sqlx::query("UPDATE subscriptions SET end_date=$2,state=CASE WHEN $4::boolean AND (is_deleted OR lower(state) NOT IN ('active','expired')) THEN state ELSE 'active' END,period=$3,updated_at=NOW() WHERE id=$1")
                    .bind(&id).bind(end).bind(period).bind(renewal_target.is_some()).execute(&mut **tx).await?;
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

    async fn authorize_order(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
        owner: &str,
        name: &str,
        admin: bool,
    ) -> AppResult<()> {
        if admin && owner == "built-in" {
            return Ok(());
        }
        if order.owner != owner {
            return Err(AppError::Authorization(
                "Unauthorized order operation".into(),
            ));
        }
        if admin {
            return Ok(());
        }
        let pinned: Option<String> = sqlx::query_scalar("SELECT buyer_id FROM orders WHERE id=$1")
            .bind(&order.id)
            .fetch_one(&mut **tx)
            .await?;
        let allowed = if let Some(id) = pinned {
            sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND owner=$2 AND name=$3 AND is_deleted=false AND is_forbidden=false)")
                .bind(id).bind(owner).bind(name).fetch_one(&mut **tx).await?
        } else {
            false
        };
        if !allowed {
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
        sqlx::query_as::<_,User>("SELECT u.* FROM users u JOIN orders o ON o.buyer_id=u.id AND o.owner=u.owner WHERE o.id=$1 AND o.owner=$2 AND u.is_deleted=false FOR UPDATE OF u")
            .bind(&order.id).bind(&order.owner).fetch_optional(&mut **tx).await?
            .ok_or_else(||AppError::NotFound("The original order buyer is unavailable".into()))
    }
}
