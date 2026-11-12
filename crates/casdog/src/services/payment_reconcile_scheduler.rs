//! Shared PostgreSQL queues make reconciliation and renewals safe across server
//! replicas. Provider calls keep PaymentFlowService's separate 45-second lease
//! and original idempotency keys even if a queue worker dies or its lease ends.
use super::subscription_renewal_service::SubscriptionRenewalService;
use crate::error::AppResult;
use crate::services::PaymentFlowService;
use crate::services::providers::payment_provider::PaymentProvider;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PaymentReconcileScheduler;

impl PaymentReconcileScheduler {
    pub async fn run_once(pool: &PgPool, limit: i64) -> AppResult<usize> {
        Self::run_once_with_gateway(pool, limit, None).await
    }

    /// Explicit provider transport injection for real HTTP integration fixtures.
    /// Production scheduler always uses the official factory endpoints.
    pub async fn run_once_using(
        pool: &PgPool,
        limit: i64,
        gateway: &dyn PaymentProvider,
    ) -> AppResult<usize> {
        Self::run_once_with_gateway(pool, limit, Some(gateway)).await
    }

    async fn run_once_with_gateway(
        pool: &PgPool,
        limit: i64,
        gateway: Option<&dyn PaymentProvider>,
    ) -> AppResult<usize> {
        // Retain retry times when re-discovering work. A failed transport never
        // turns the original accepted checkout into a new checkout or releases
        // reserved stock. Legacy confirmed remote IDs may also be reconciled.
        sqlx::query("INSERT INTO payment_reconcile_queue(payment_id) SELECT DISTINCT p.id FROM payments p JOIN orders o ON o.payment_id=p.id AND o.owner=p.owner AND o.buyer_id IS NOT NULL JOIN providers pr ON pr.id=p.provider_id AND pr.owner=p.owner AND lower(pr.type) IN ('stripe','paypal') LEFT JOIN payment_remote_operations op ON op.payment_id=p.id WHERE p.is_deleted=false AND lower(p.state) NOT IN ('paid','failed','canceled','cancelled','timeout','expired','error') AND (op.payment_id IS NOT NULL OR (p.out_order_id IS NOT NULL AND p.out_order_id<>'' AND p.out_order_id<>p.id)) ON CONFLICT(payment_id) DO NOTHING").execute(pool).await?;
        sqlx::query("DELETE FROM payment_reconcile_queue q USING payments p WHERE p.id=q.payment_id AND lower(p.state) IN ('paid','failed','canceled','cancelled','timeout','expired','error') AND (q.lease_until IS NULL OR q.lease_until<clock_timestamp())").execute(pool).await?;
        let mut count = 0;
        for _ in 0..limit.clamp(1, 100) {
            let token = Uuid::new_v4().to_string();
            let mut tx = pool.begin().await?;
            let item:Option<(String,String)>=sqlx::query_as("SELECT q.payment_id,o.id FROM payment_reconcile_queue q JOIN payments p ON p.id=q.payment_id JOIN orders o ON o.payment_id=p.id AND o.owner=p.owner AND o.buyer_id IS NOT NULL WHERE q.next_attempt_at<=clock_timestamp() AND (q.lease_until IS NULL OR q.lease_until<clock_timestamp()) AND lower(p.state) NOT IN ('paid','failed','canceled','cancelled','timeout','expired','error') ORDER BY q.next_attempt_at,q.payment_id FOR UPDATE OF q SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await?;
            let Some((payment_id, order_id)) = item else {
                tx.commit().await?;
                break;
            };
            sqlx::query("UPDATE payment_reconcile_queue SET lease_token=$2,lease_until=clock_timestamp()+interval '90 seconds',attempts=attempts+1,updated_at=NOW() WHERE payment_id=$1").bind(&payment_id).bind(&token).execute(&mut *tx).await?;
            tx.commit().await?;
            let result =
                PaymentFlowService::reconcile_in_background(pool, &order_id, gateway).await;
            let error = result.as_ref().err().map(ToString::to_string);
            let terminal = result.as_ref().is_ok_and(|r| {
                matches!(
                    r.payment.state.to_ascii_lowercase().as_str(),
                    "paid" | "failed" | "canceled" | "cancelled" | "timeout" | "expired" | "error"
                )
            });
            if terminal {
                sqlx::query(
                    "DELETE FROM payment_reconcile_queue WHERE payment_id=$1 AND lease_token=$2",
                )
                .bind(&payment_id)
                .bind(&token)
                .execute(pool)
                .await?;
            } else {
                sqlx::query("UPDATE payment_reconcile_queue SET next_attempt_at=clock_timestamp()+interval '60 seconds',lease_token=NULL,lease_until=NULL,last_error=$3,updated_at=NOW() WHERE payment_id=$1 AND lease_token=$2").bind(&payment_id).bind(&token).bind(error).execute(pool).await?;
            }
            count += 1;
        }
        // Keep the externally completed renewal's public status current without
        // charging or creating another order. Fulfillment already committed.
        sqlx::query("UPDATE subscription_renewal_work w SET state=CASE WHEN lower(o.state)='paid' THEN 'paid' ELSE 'failed' END,last_error=NULL,updated_at=NOW() FROM orders o WHERE w.order_id=o.id AND w.state='action_required' AND lower(o.state) IN ('paid','failed','canceled','cancelled','timeout','expired')").execute(pool).await?;
        Ok(count)
    }

    pub async fn start_scheduler(pool: PgPool, interval: std::time::Duration) {
        let mut ticker = tokio::time::interval(interval.max(std::time::Duration::from_secs(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(error) = SubscriptionRenewalService::run_once(&pool, 20).await {
                tracing::warn!("Subscription renewal tick failed: {}", error);
            }
            if let Err(error) = Self::run_once(&pool, 20).await {
                tracing::warn!("Payment reconciliation tick failed: {}", error);
            }
            if pool.is_closed() {
                break;
            }
        }
    }
}
