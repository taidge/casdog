//! Durable renewal consent and work. Only Balance is charged without a browser.
//! Other gateways require a new explicit checkout; no off-session mandate is
//! inferred from a previous successful payment or a legacy auto_renew flag.
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{Order, Plan, Pricing, Product, Provider, Subscription, User};
use crate::services::PaymentFlowService;

pub struct SubscriptionRenewalService;

#[derive(Debug, Serialize)]
pub struct RenewalConsent {
    pub enabled: bool,
    pub mode: Option<String>,
    pub currency: Option<String>,
    pub max_amount_cents: Option<i64>,
    pub state: Option<String>,
    pub order_id: Option<String>,
    pub last_error: Option<String>,
}

#[derive(sqlx::FromRow)]
struct Authorization {
    subscription_id: String,
    owner: String,
    user_id: String,
    product_id: String,
    provider_id: String,
    provider_fingerprint: String,
    plan_id: String,
    pricing_id: String,
    role_id: Option<String>,
    period: String,
    currency: String,
    max_amount_cents: i64,
    mode: String,
    enabled: bool,
}

struct Catalogue {
    user: User,
    product: Product,
    plan: Plan,
    pricing: Pricing,
    provider: Provider,
    role_id: Option<String>,
    period: String,
    currency: String,
    amount_cents: i64,
    mode: String,
}

fn conflict(message: &str) -> AppError {
    AppError::Conflict(message.into())
}
fn fingerprint(p: &Provider) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&serde_json::json!([
                p.id,
                p.provider_type,
                p.client_id,
                p.client_secret,
                p.host
            ]))
            .expect("serializable provider identity")
        )
    )
}

impl SubscriptionRenewalService {
    /// Enabling is the beneficiary's own explicit consent. Administrators may
    /// stop renewals but cannot authorize spending another account's wallet.
    pub async fn set_auto_renew(
        pool: &PgPool,
        id: &str,
        owner: &str,
        user_id: &str,
        admin: bool,
        enabled: bool,
    ) -> AppResult<RenewalConsent> {
        Self::set_auto_renew_with_quote(pool, id, owner, user_id, admin, enabled, None).await
    }

    /// An interactive UI supplies its displayed price/currency. A concurrent
    /// increase must fail rather than silently expanding the wallet mandate.
    /// We bind the actual current price (even when lower than the quoted cap),
    /// so future increases still require another explicit consent.
    pub async fn set_auto_renew_with_quote(
        pool: &PgPool,
        id: &str,
        owner: &str,
        user_id: &str,
        admin: bool,
        enabled: bool,
        quote: Option<(i64, &str)>,
    ) -> AppResult<RenewalConsent> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('casdog.renewal_consent','on',true)")
            .execute(&mut *tx)
            .await?;
        let previous: Option<Authorization> = sqlx::query_as(
            "SELECT * FROM subscription_renewal_authorizations WHERE subscription_id=$1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let sub: Subscription = sqlx::query_as(
            "SELECT * FROM subscriptions WHERE id=$1 AND is_deleted=false FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;
        if sub.owner != owner && !(admin && owner == "built-in") {
            return Err(AppError::Authorization(
                "Subscription belongs to another tenant".into(),
            ));
        }
        if enabled && (sub.user_id != user_id || sub.owner != owner)
            || !enabled && !admin && sub.user_id != user_id
        {
            return Err(AppError::Authorization(
                "Only the beneficiary can authorize recurring payments".into(),
            ));
        }
        if enabled {
            let source: Option<(String,String)>=sqlx::query_as("SELECT r.product_id,p.provider_id FROM order_benefits b JOIN orders o ON o.id=b.order_id AND o.owner=$2 AND o.buyer_id=$3 AND lower(o.state)='paid' JOIN order_stock_reservations r ON r.order_id=o.id JOIN payments p ON p.id=o.payment_id AND p.owner=o.owner AND lower(p.state)='paid' WHERE b.subscription_id=$1 AND b.user_id=$3 AND b.fulfilled_at IS NOT NULL ORDER BY b.fulfilled_at DESC LIMIT 1")
                .bind(id).bind(&sub.owner).bind(&sub.user_id).fetch_optional(&mut *tx).await?;
            let (product_id, provider_id) = source
                .ok_or_else(|| conflict("Auto renewal requires a proven paid plan purchase"))?;
            let catalog = Self::catalogue(&mut tx, &sub, &product_id, &provider_id).await?;
            if let Some((cap, currency)) = quote {
                if !(0..=900_000_000_000_000).contains(&cap)
                    || currency.len() != 3
                    || !currency.bytes().all(|b| b.is_ascii_alphabetic())
                {
                    return Err(AppError::Validation("Invalid renewal quote".into()));
                }
                if catalog.amount_cents > cap || !catalog.currency.eq_ignore_ascii_case(currency) {
                    return Err(conflict(
                        "Renewal quote changed; review the current price and currency before authorizing",
                    ));
                }
            }

            sqlx::query("INSERT INTO subscription_renewal_authorizations(subscription_id,owner,user_id,product_id,provider_id,provider_fingerprint,plan_id,pricing_id,role_id,period,currency,max_amount_cents,mode,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,true) ON CONFLICT(subscription_id) DO UPDATE SET owner=excluded.owner,user_id=excluded.user_id,product_id=excluded.product_id,provider_id=excluded.provider_id,provider_fingerprint=excluded.provider_fingerprint,plan_id=excluded.plan_id,pricing_id=excluded.pricing_id,role_id=excluded.role_id,period=excluded.period,currency=excluded.currency,max_amount_cents=excluded.max_amount_cents,mode=excluded.mode,enabled=true,authorized_at=NOW(),updated_at=NOW()")
                .bind(id).bind(&sub.owner).bind(&sub.user_id).bind(product_id).bind(provider_id).bind(fingerprint(&catalog.provider)).bind(&sub.plan_id).bind(&sub.pricing_id).bind(&catalog.role_id).bind(&catalog.period).bind(&catalog.currency).bind(catalog.amount_cents).bind(catalog.mode).execute(&mut *tx).await?;
            // Re-enable retries the same uncharged order, never creates another
            // order for this due date. Changed snapshots remain blocked.
            sqlx::query("UPDATE subscription_renewal_work SET next_attempt_at=NOW(),state=CASE WHEN state IN ('blocked','retry','canceled') THEN 'retry' ELSE state END,updated_at=NOW() WHERE subscription_id=$1 AND state IN ('blocked','retry','canceled')")
                .bind(id).execute(&mut *tx).await?;
        } else if previous.is_some() {
            sqlx::query("UPDATE subscription_renewal_authorizations SET enabled=false,updated_at=NOW() WHERE subscription_id=$1").bind(id).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE subscriptions SET auto_renew=$2,updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(enabled)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Self::status(pool, id).await
    }

    pub async fn status(pool: &PgPool, id: &str) -> AppResult<RenewalConsent> {
        let row: Option<(bool,String,String,i64)>=sqlx::query_as("SELECT a.enabled AND s.auto_renew AND NOT s.is_deleted,a.mode,a.currency,a.max_amount_cents FROM subscription_renewal_authorizations a JOIN subscriptions s ON s.id=a.subscription_id WHERE a.subscription_id=$1").bind(id).fetch_optional(pool).await?;
        let work:Option<(String,Option<String>,Option<String>)>=sqlx::query_as("SELECT state,order_id,last_error FROM subscription_renewal_work WHERE subscription_id=$1 ORDER BY due_at DESC LIMIT 1").bind(id).fetch_optional(pool).await?;
        let (enabled, mode, currency, max) = row
            .map(|(e, m, c, a)| (e, Some(m), Some(c), Some(a)))
            .unwrap_or((false, None, None, None));
        let (state, order_id, last_error) = work
            .map(|(s, o, e)| (Some(s), o, e))
            .unwrap_or((None, None, None));
        Ok(RenewalConsent {
            enabled,
            mode,
            currency,
            max_amount_cents: max,
            state,
            order_id,
            last_error,
        })
    }

    async fn catalogue(
        conn: &mut PgConnection,
        sub: &Subscription,
        product_id: &str,
        provider_id: &str,
    ) -> AppResult<Catalogue> {
        if sub.is_deleted
            || !matches!(
                sub.state.to_ascii_lowercase().as_str(),
                "active" | "expired"
            )
            || sub.end_date.is_none()
        {
            return Err(conflict(
                "Only finite active or expired subscriptions can renew",
            ));
        }
        // A disabled tenant cannot initiate new recurring billing. The SHARE
        // lock is held through the actual Balance debit, so organization
        // suspension and charging have a definite database ordering. Accepted
        // external payments use reconciliation, which deliberately skips this
        // new-purchase preflight and keeps their real accounting evidence.
        let organization:Option<String>=sqlx::query_scalar("SELECT id FROM organizations WHERE name=$1 AND is_deleted=false AND disable_signin=false FOR SHARE")
            .bind(&sub.owner).fetch_optional(&mut *conn).await?;
        if organization.is_none() {
            return Err(conflict(
                "Renewal organization is unavailable or sign-in is disabled",
            ));
        }
        let user:User=sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND is_deleted=false AND is_forbidden=false").bind(&sub.user_id).bind(&sub.owner).fetch_optional(&mut *conn).await?.ok_or_else(|| conflict("Renewal beneficiary is unavailable"))?;
        let product: Product =
            sqlx::query_as("SELECT * FROM products WHERE id=$1 AND owner=$2 AND is_deleted=false")
                .bind(product_id)
                .bind(&sub.owner)
                .fetch_optional(&mut *conn)
                .await?
                .ok_or_else(|| conflict("Renewal product is unavailable"))?;
        let plan:Plan=sqlx::query_as("SELECT * FROM plans WHERE id=$1 AND owner=$2 AND is_deleted=false AND is_enabled=true FOR SHARE").bind(&sub.plan_id).bind(&sub.owner).fetch_optional(&mut *conn).await?.ok_or_else(|| conflict("Renewal plan is unavailable"))?;
        let pricing:Pricing=sqlx::query_as("SELECT * FROM pricings WHERE id=$1 AND owner=$2 AND is_deleted=false AND is_enabled=true FOR SHARE").bind(&sub.pricing_id).bind(&sub.owner).fetch_optional(&mut *conn).await?.ok_or_else(|| conflict("Renewal pricing is unavailable"))?;
        if product.plan_id.as_deref() != Some(&plan.id)
            || product.is_recharge
            || !matches!(
                product.state.to_ascii_lowercase().as_str(),
                "active" | "published" | "on sale"
            )
            || product.quantity == 0
        {
            return Err(conflict("Renewal product is not for sale"));
        }
        let members: Vec<String> =
            serde_json::from_str(pricing.plans.as_deref().unwrap_or("[]"))
                .map_err(|_| conflict("Renewal pricing has invalid plan references"))?;
        if !members.iter().any(|r| {
            r == &plan.id || r == &plan.name || r == &format!("{}/{}", sub.owner, plan.name)
        }) {
            return Err(conflict("Plan no longer belongs to this pricing"));
        }
        let period = sub.period.clone().unwrap_or_default().to_ascii_lowercase();
        let price = match period.as_str() {
            "monthly" => plan.price_per_month,
            "yearly" => plan.price_per_year,
            _ => return Err(conflict("Unsupported renewal period")),
        };
        let amount_cents = crate::services::ProductService::validate_price(price, false)?;
        let currency = product
            .currency
            .clone()
            .unwrap_or_else(|| "USD".into())
            .to_ascii_uppercase();
        if !plan
            .currency
            .as_deref()
            .unwrap_or("USD")
            .eq_ignore_ascii_case(&currency)
        {
            return Err(conflict("Renewal currencies differ"));
        }
        let provider: Provider = sqlx::query_as(
            "SELECT * FROM providers WHERE id=$1 AND owner=$2 AND category='Payment' FOR SHARE",
        )
        .bind(provider_id)
        .bind(&sub.owner)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| conflict("Renewal provider is unavailable"))?;
        let mode=match provider.provider_type.to_ascii_lowercase().as_str(){"balance"=>{PaymentFlowService::validate_balance_currency(&serde_json::json!({"balance_currency":user.balance_currency,"currency":user.currency}),&currency)?;"balance"},"stripe"|"paypal"=>"checkout_required",_=>return Err(conflict("This provider cannot renew subscriptions"))}.to_owned();
        let role_id = if let Some(reference) = plan.role.as_deref().filter(|r| !r.is_empty()) {
            Some(sqlx::query_scalar::<_,String>("SELECT id FROM roles WHERE owner=$1 AND is_deleted=false AND is_enabled=true AND (id=$2 OR name=$2 OR owner||'/'||name=$2) ORDER BY (id=$2) DESC LIMIT 1 FOR SHARE")
                .bind(&sub.owner).bind(reference).fetch_optional(&mut *conn).await?.ok_or_else(||conflict("Renewal role is unavailable"))?)
        } else {
            None
        };
        Ok(Catalogue {
            user,
            product,
            plan,
            pricing,
            provider,
            role_id,
            period,
            currency,
            amount_cents,
            mode,
        })
    }

    fn validate_consent(a: &Authorization, c: &Catalogue, s: &Subscription) -> AppResult<()> {
        if !a.enabled
            || a.owner != s.owner
            || a.user_id != s.user_id
            || a.plan_id != s.plan_id
            || Some(&a.pricing_id) != s.pricing_id.as_ref()
            || a.role_id != c.role_id
            || a.period != c.period
            || a.currency != c.currency
            || a.mode != c.mode
            || a.provider_fingerprint != fingerprint(&c.provider)
            || c.amount_cents > a.max_amount_cents
        {
            return Err(conflict(
                "Renewal details changed; explicit consent is required again",
            ));
        }
        Ok(())
    }

    /// Claims are durable; work uniqueness is the subscription's exact old end
    /// date. A process can die at any point and another pool reuses its order.
    pub async fn run_once(pool: &PgPool, limit: i64) -> AppResult<usize> {
        sqlx::query("INSERT INTO subscription_renewal_work(id,subscription_id,due_at) SELECT gen_random_uuid()::text,s.id,s.end_date FROM subscriptions s JOIN subscription_renewal_authorizations a ON a.subscription_id=s.id AND a.enabled=true WHERE s.auto_renew=true AND s.is_deleted=false AND lower(s.state) IN ('active','expired') AND s.end_date<=clock_timestamp()+interval '24 hours' AND s.end_date IS NOT NULL ON CONFLICT(subscription_id,due_at) DO NOTHING").execute(pool).await?;
        let mut processed = 0;
        for _ in 0..limit.clamp(1, 100) {
            let token = Uuid::new_v4().to_string();
            let mut tx = pool.begin().await?;
            let id:Option<String>=sqlx::query_scalar("SELECT id FROM subscription_renewal_work WHERE state IN ('queued','processing','retry','blocked') AND next_attempt_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<clock_timestamp()) ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await?;
            let Some(id) = id else {
                tx.commit().await?;
                break;
            };
            sqlx::query("UPDATE subscription_renewal_work SET state='processing',lease_token=$2,lease_until=clock_timestamp()+interval '90 seconds',attempts=attempts+1,updated_at=NOW() WHERE id=$1").bind(&id).bind(&token).execute(&mut *tx).await?;
            tx.commit().await?;
            let result = Self::process(pool, &id, &token).await;
            if let Err(error) = result {
                // Preserve the one existing order on insufficient funds or an
                // interrupted worker; the next attempt cannot duplicate debit.
                sqlx::query("UPDATE subscription_renewal_work SET state='retry',last_error=$3,lease_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+interval '5 minutes',updated_at=NOW() WHERE id=$1 AND lease_token=$2").bind(&id).bind(&token).bind(error.to_string()).execute(pool).await?;
            }
            processed += 1;
        }
        Ok(processed)
    }

    async fn process(pool: &PgPool, id: &str, token: &str) -> AppResult<()> {
        let mut tx = pool.begin().await?;
        let (subscription_id,due_at,existing):(String,DateTime<Utc>,Option<String>)=sqlx::query_as("SELECT subscription_id,due_at,order_id FROM subscription_renewal_work WHERE id=$1 AND lease_token=$2 AND lease_until>clock_timestamp() FOR UPDATE").bind(id).bind(token).fetch_optional(&mut *tx).await?.ok_or_else(||conflict("Renewal work lease expired"))?;
        let a: Authorization = sqlx::query_as(
            "SELECT * FROM subscription_renewal_authorizations WHERE subscription_id=$1 FOR UPDATE",
        )
        .bind(&subscription_id)
        .fetch_one(&mut *tx)
        .await?;
        let sub: Subscription = sqlx::query_as("SELECT * FROM subscriptions WHERE id=$1")
            .bind(&subscription_id)
            .fetch_one(&mut *tx)
            .await?;
        let auto: bool = sqlx::query_scalar("SELECT auto_renew FROM subscriptions WHERE id=$1")
            .bind(&subscription_id)
            .fetch_one(&mut *tx)
            .await?;
        let existing_state: Option<String> = if let Some(order_id) = &existing {
            sqlx::query_scalar("SELECT state FROM orders WHERE id=$1")
                .bind(order_id)
                .fetch_optional(&mut *tx)
                .await?
        } else {
            None
        };
        let done = if existing_state
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("paid"))
        {
            Some("paid")
        } else if existing_state
            .as_deref()
            .is_some_and(|s| !s.eq_ignore_ascii_case("created"))
        {
            Some("failed")
        } else if !auto || !a.enabled {
            Some("canceled")
        } else if sub.end_date != Some(due_at) {
            Some("superseded")
        } else {
            None
        };
        if let Some(state) = done {
            sqlx::query("UPDATE subscription_renewal_work SET state=$3,lease_token=NULL,lease_until=NULL,last_error=NULL,updated_at=NOW() WHERE id=$1 AND lease_token=$2").bind(id).bind(token).bind(state).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(());
        }
        let c = match Self::catalogue(&mut tx, &sub, &a.product_id, &a.provider_id)
            .await
            .and_then(|c| {
                Self::validate_consent(&a, &c, &sub)?;
                Ok(c)
            }) {
            Ok(c) => c,
            Err(error) => {
                sqlx::query("UPDATE subscription_renewal_work SET state='blocked',last_error=$3,lease_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+interval '5 minutes',updated_at=NOW() WHERE id=$1 AND lease_token=$2").bind(id).bind(token).bind(error.to_string()).execute(&mut *tx).await?;
                tx.commit().await?;
                return Ok(());
            }
        };
        let order_id = if let Some(order_id) = existing {
            order_id
        } else {
            let order_id = Uuid::new_v4().to_string();
            sqlx::query("INSERT INTO orders(id,owner,name,display_name,product_name,product_display_name,quantity,price,currency,state,\"user\",provider,plan_name,pricing_name,tag) VALUES($1,$2,$3,$4,$5,$4,1,$6,$7,'Created',$8,$9,$10,$11,'Subscription renewal')")
                .bind(&order_id).bind(&sub.owner).bind(format!("renew-{id}")).bind(&c.product.display_name).bind(&c.product.name).bind(c.amount_cents as f64/100.0).bind(&c.currency).bind(&c.user.id).bind(&c.provider.id).bind(&c.plan.name).bind(&c.pricing.name).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO order_benefits(order_id,kind,user_id,amount_cents,plan_id,pricing_id,period,role_id) VALUES($1,'plan',$2,$3,$4,$5,$6,$7)").bind(&order_id).bind(&sub.user_id).bind(c.amount_cents).bind(&sub.plan_id).bind(&sub.pricing_id).bind(&c.period).bind(&c.role_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE subscription_renewal_work SET order_id=$3,updated_at=NOW() WHERE id=$1 AND lease_token=$2").bind(id).bind(token).bind(&order_id).execute(&mut *tx).await?;
            order_id
        };
        if c.mode == "checkout_required" {
            sqlx::query("UPDATE subscription_renewal_work SET state='action_required',last_error='A new browser checkout is required; no off-session payment mandate exists',lease_token=NULL,lease_until=NULL,updated_at=NOW() WHERE id=$1 AND lease_token=$2").bind(id).bind(token).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(());
        }
        tx.commit().await?;
        PaymentFlowService::pay_subscription_renewal(pool, id, token, &order_id).await?;
        sqlx::query("UPDATE subscription_renewal_work SET state='paid',last_error=NULL,lease_token=NULL,lease_until=NULL,updated_at=NOW() WHERE id=$1 AND lease_token=$2").bind(id).bind(token).execute(pool).await?;
        Ok(())
    }

    /// Called after order/product/buyer locks and before the atomic wallet debit.
    /// Consent revocation and period changes cannot race the actual charge.
    pub(crate) async fn validate_balance_charge(
        tx: &mut Transaction<'_, Postgres>,
        id: &str,
        token: &str,
        order: &Order,
        provider: &Provider,
    ) -> AppResult<()> {
        let (subscription_id,due_at):(String,DateTime<Utc>)=sqlx::query_as("SELECT subscription_id,due_at FROM subscription_renewal_work WHERE id=$1 AND order_id=$3 AND lease_token=$2 AND lease_until>clock_timestamp()").bind(id).bind(token).bind(&order.id).fetch_optional(&mut **tx).await?.ok_or_else(||conflict("Renewal work lease expired"))?;
        let a: Authorization = sqlx::query_as(
            "SELECT * FROM subscription_renewal_authorizations WHERE subscription_id=$1 FOR UPDATE",
        )
        .bind(&subscription_id)
        .fetch_one(&mut **tx)
        .await?;
        let sub: Subscription =
            sqlx::query_as("SELECT * FROM subscriptions WHERE id=$1 FOR UPDATE")
                .bind(&subscription_id)
                .fetch_one(&mut **tx)
                .await?;
        let auto: bool = sqlx::query_scalar("SELECT auto_renew FROM subscriptions WHERE id=$1")
            .bind(&subscription_id)
            .fetch_one(&mut **tx)
            .await?;
        if !auto
            || sub.end_date != Some(due_at)
            || order.owner != a.owner
            || provider.id != a.provider_id
            || a.mode != "balance"
        {
            return Err(conflict("Renewal consent or subscription period changed"));
        }
        let c = Self::catalogue(tx, &sub, &a.product_id, &a.provider_id).await?;
        Self::validate_consent(&a, &c, &sub)?;
        let (buyer,beneficiary,amount,plan,pricing,period,role):(Option<String>,String,i64,Option<String>,Option<String>,Option<String>,Option<String>)=sqlx::query_as("SELECT o.buyer_id,b.user_id,b.amount_cents,b.plan_id,b.pricing_id,b.period,b.role_id FROM orders o JOIN order_benefits b ON b.order_id=o.id AND b.kind='plan' WHERE o.id=$1").bind(&order.id).fetch_one(&mut **tx).await?;
        if buyer.as_deref() != Some(&a.user_id)
            || beneficiary != a.user_id
            || amount != c.amount_cents
            || plan.as_deref() != Some(&a.plan_id)
            || pricing.as_deref() != Some(&a.pricing_id)
            || period.as_deref() != Some(&a.period)
            || role != a.role_id
            || crate::services::ProductService::validate_price(order.price, false)? != amount
            || !order
                .currency
                .as_deref()
                .unwrap_or("USD")
                .eq_ignore_ascii_case(&a.currency)
            || order.product_name.as_deref() != Some(&c.product.name)
        {
            return Err(conflict(
                "Renewal order snapshot changed; no debit was made",
            ));
        }
        Ok(())
    }
}
