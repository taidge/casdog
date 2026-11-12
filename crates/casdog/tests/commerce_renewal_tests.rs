//! Real PostgreSQL regressions for consent, due work, wallet debits and the
//! reconciliation scheduler. No global clock/env mutation or real gateways.
use casdog::services::providers::payment_provider::PaymentProvider;
use casdog::services::{
    PaymentFlowService, payment_reconcile_scheduler::PaymentReconcileScheduler as Reconcile,
    subscription_renewal_service::SubscriptionRenewalService as Renew,
};
use chrono::{DateTime, Utc};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::collections::HashMap;

struct Fixture {
    pool: PgPool,
    owner: String,
    user: String,
    admin: String,
    product: String,
    provider: String,
    plan: String,
    pricing: String,
    role: String,
    subscription: String,
}
impl Fixture {
    async fn new() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            casdog::config::AppConfig::load().unwrap();
        });
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect(
                &std::env::var("CASDOG_TEST_DATABASE_URL").expect("set CASDOG_TEST_DATABASE_URL"),
            )
            .await
            .unwrap();
        let owner = format!("renew-{}", uuid::Uuid::new_v4());
        let ids: Vec<String> = (0..8).map(|_| uuid::Uuid::new_v4().to_string()).collect();
        let mut f = Self {
            pool,
            owner,
            user: ids[0].clone(),
            admin: ids[1].clone(),
            product: ids[2].clone(),
            provider: ids[3].clone(),
            plan: ids[4].clone(),
            pricing: ids[5].clone(),
            role: ids[6].clone(),
            subscription: String::new(),
        };
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
        for (id, name, admin) in [(&f.user, "buyer", false), (&f.admin, "admin", true)] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin,balance) VALUES($1,$2,$3,$3,'unused',$4,100)").bind(id).bind(&f.owner).bind(name).bind(admin).execute(&f.pool).await.unwrap();
        }
        sqlx::query("INSERT INTO roles(id,owner,name,display_name,is_enabled) VALUES($1,$2,'premium','Premium',true)").bind(&f.role).bind(&f.owner).execute(&f.pool).await.unwrap();
        sqlx::query("INSERT INTO plans(id,owner,name,display_name,price_per_month,price_per_year,currency,role,is_enabled) VALUES($1,$2,'premium','Premium',10,100,'USD',$3,true)").bind(&f.plan).bind(&f.owner).bind(&f.role).execute(&f.pool).await.unwrap();
        sqlx::query("INSERT INTO pricings(id,owner,name,display_name,plans,is_enabled) VALUES($1,$2,'public','Public',$3,true)").bind(&f.pricing).bind(&f.owner).bind(json!([f.plan]).to_string()).execute(&f.pool).await.unwrap();
        sqlx::query("INSERT INTO products(id,owner,name,display_name,price,quantity,currency,plan_id) VALUES($1,$2,'membership','Membership',10,-1,'USD',$3)").bind(&f.product).bind(&f.owner).bind(&f.plan).execute(&f.pool).await.unwrap();
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES($1,$2,'wallet','Wallet','Payment','Balance')").bind(&f.provider).bind(&f.owner).execute(&f.pool).await.unwrap();
        // Use the normal buy-product handler and the atomic paid benefit path.
        let app = f.app();
        let mut res=TestClient::post(format!("http://localhost/api/buy-product?id={}&providerName={}&pricingName=public&planName=premium",f.product,f.provider)).add_header("Authorization",format!("Bearer {}",f.token(false)),true).send(&app).await;
        let status = res.status_code;
        assert_eq!(
            status,
            Some(StatusCode::OK),
            "{}",
            res.take_string().await.unwrap_or_default()
        );
        f.subscription = sqlx::query_scalar("SELECT id FROM subscriptions WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
        f
    }
    fn app(&self) -> Service {
        Service::new(casdog::routes::create_router())
            .hoop(salvo::affix_state::AffixList::new().inject(self.pool.clone()))
    }
    fn token(&self, admin: bool) -> String {
        let c = casdog::config::AppConfig::get();
        let now = Utc::now();
        jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({"sub":if admin{&self.admin}else{&self.user},"owner":self.owner,"name":if admin{"admin"}else{"buyer"},"is_admin":admin,"iat":now.timestamp(),"exp":now.timestamp()+3600,"issued_at_ms":now.timestamp_millis(),"iss":c.jwt.issuer}),&jsonwebtoken::EncodingKey::from_secret(c.jwt.secret.as_bytes())).unwrap()
    }
    async fn enable(&self) -> Value {
        let mut res = TestClient::post(format!(
            "http://localhost/api/set-subscription-auto-renew?id={}&autoRenew=true",
            self.subscription
        ))
        .add_header(
            "Authorization",
            format!("Bearer {}", self.token(false)),
            true,
        )
        .send(&self.app())
        .await;
        let status = res.status_code;
        if status != Some(StatusCode::OK) {
            panic!(
                "enable {status:?}: {}",
                res.take_string().await.unwrap_or_default()
            );
        }
        res.take_json().await.unwrap()
    }
    async fn due(&self) -> DateTime<Utc> {
        sqlx::query_scalar("UPDATE subscriptions SET end_date=clock_timestamp()+interval '1 hour' WHERE id=$1 RETURNING end_date").bind(&self.subscription).fetch_one(&self.pool).await.unwrap()
    }
    async fn wallet(&self) -> f64 {
        sqlx::query_scalar("SELECT balance FROM users WHERE id=$1")
            .bind(&self.user)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE owner=$1"))
            .bind(&self.owner)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn second_pool(&self) -> PgPool {
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap()
    }
    async fn cleanup(&self) {
        let pending:Vec<String>=sqlx::query_scalar("SELECT payment_id FROM orders WHERE owner=$1 AND payment_id IS NOT NULL AND lower(state) IN ('created','processing')").bind(&self.owner).fetch_all(&self.pool).await.unwrap();
        for id in pending {
            PaymentFlowService::manual_notify_payment(&self.pool, &id, "Failed", None, None)
                .await
                .unwrap();
        }
        let mut tx = self.pool.begin().await.unwrap();
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *tx)
            .await
            .unwrap();
        for sql in [
            "DELETE FROM subscriptions WHERE owner=$1",
            "DELETE FROM order_benefits WHERE order_id IN(SELECT id FROM orders WHERE owner=$1)",
            "DELETE FROM transactions WHERE owner=$1",
            "DELETE FROM orders WHERE owner=$1",
            "DELETE FROM payments WHERE owner=$1",
            "DELETE FROM products WHERE owner=$1",
            "DELETE FROM providers WHERE owner=$1",
            "DELETE FROM plans WHERE owner=$1",
            "DELETE FROM pricings WHERE owner=$1",
            "DELETE FROM roles WHERE owner=$1",
            "DELETE FROM users WHERE owner=$1",
        ] {
            sqlx::query(sql)
                .bind(&self.owner)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM organizations WHERE name=$1")
            .bind(&self.owner)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires migration036 and CASDOG_TEST_DATABASE_URL"]
async fn balance_due_work_is_single_debit_single_period_across_pools_and_restart() {
    let f = Fixture::new().await;
    let consent = f.enable().await;
    assert_eq!(consent["data2"]["mode"], "balance");
    assert_eq!(consent["data2"]["max_amount_cents"], 1000);
    let due = f.due().await;
    let duplicate = uuid::Uuid::new_v4().to_string();
    let duplicate_end:DateTime<Utc>=sqlx::query_scalar("INSERT INTO subscriptions(id,owner,name,display_name,user_id,plan_id,pricing_id,start_date,end_date,period,state) VALUES($1,$2,'separate-manual','Separate',$3,$4,$5,NOW(),NOW()+interval '6 months','monthly','active') RETURNING end_date").bind(&duplicate).bind(&f.owner).bind(&f.user).bind(&f.plan).bind(&f.pricing).fetch_one(&f.pool).await.unwrap();

    let second = f.second_pool().await;
    let (a, b) = tokio::join!(Renew::run_once(&f.pool, 10), Renew::run_once(&second, 10));
    a.unwrap();
    b.unwrap();
    assert_eq!(f.wallet().await, 80.0);
    assert_eq!(f.count("orders").await, 2);
    assert_eq!(f.count("payments").await, 2);
    assert_eq!(f.count("transactions").await, 2);
    let end: DateTime<Utc> = sqlx::query_scalar("SELECT end_date FROM subscriptions WHERE id=$1")
        .bind(&f.subscription)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(end, due.checked_add_months(chrono::Months::new(1)).unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, DateTime<Utc>>("SELECT end_date FROM subscriptions WHERE id=$1")
            .bind(&duplicate)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        duplicate_end
    );
    let (orders,grants):(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM subscription_renewal_work WHERE subscription_id=$1),(SELECT count(*) FROM subscription_grants WHERE subscription_id=$1)").bind(&f.subscription).fetch_one(&f.pool).await.unwrap();
    assert_eq!((orders, grants), (1, 2));
    // Simulate a crash after the debit committed but before the work ack.
    sqlx::query("UPDATE subscription_renewal_work SET state='processing',lease_token='dead-process',lease_until=NOW()-interval '1 second',next_attempt_at=NOW() WHERE subscription_id=$1").bind(&f.subscription).execute(&f.pool).await.unwrap();
    Renew::run_once(&second, 10).await.unwrap();
    assert_eq!(
        Renew::status(&f.pool, &f.subscription)
            .await
            .unwrap()
            .state
            .as_deref(),
        Some("paid")
    );
    assert_eq!(f.wallet().await, 80.0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_roles WHERE user_id=$1")
            .bind(&f.user)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    f.cleanup().await;
    second.close().await;
}

#[tokio::test]
#[ignore = "requires migration036 and CASDOG_TEST_DATABASE_URL"]
async fn insufficient_balance_retries_same_order_and_optout_stops_pending_work() {
    let f = Fixture::new().await;
    f.enable().await;
    f.due().await;
    sqlx::query("UPDATE users SET balance=0 WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    Renew::run_once(&f.pool, 10).await.unwrap();
    let first = Renew::status(&f.pool, &f.subscription).await.unwrap();
    assert_eq!(first.state.as_deref(), Some("retry"));
    let order = first.order_id.unwrap();
    assert_eq!(f.count("payments").await, 1);
    assert_eq!(f.count("orders").await, 2);
    for _ in 0..2 {
        sqlx::query(
            "UPDATE subscription_renewal_work SET next_attempt_at=NOW() WHERE subscription_id=$1",
        )
        .bind(&f.subscription)
        .execute(&f.pool)
        .await
        .unwrap();
        Renew::run_once(&f.pool, 10).await.unwrap();
    }
    assert_eq!(f.count("orders").await, 2);
    Renew::set_auto_renew(&f.pool, &f.subscription, &f.owner, &f.user, false, false)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET balance=50 WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE subscription_renewal_work SET next_attempt_at=NOW() WHERE subscription_id=$1",
    )
    .bind(&f.subscription)
    .execute(&f.pool)
    .await
    .unwrap();
    Renew::run_once(&f.pool, 10).await.unwrap();
    assert_eq!(f.wallet().await, 50.0);
    assert_eq!(
        Renew::status(&f.pool, &f.subscription)
            .await
            .unwrap()
            .state
            .as_deref(),
        Some("canceled")
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM orders WHERE id=$1")
            .bind(order)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        "Created"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migration036 and CASDOG_TEST_DATABASE_URL"]
async fn current_catalog_and_consent_limits_block_debit_without_permanent_role_grants() {
    for change in [
        "price", "plan", "pricing", "role", "user", "provider", "currency",
    ] {
        let f = Fixture::new().await;
        f.enable().await;
        f.due().await;
        let (sql, id) = match change {
            "price" => ("UPDATE plans SET price_per_month=11 WHERE id=$1", &f.plan),
            "plan" => ("UPDATE plans SET is_enabled=false WHERE id=$1", &f.plan),
            "pricing" => (
                "UPDATE pricings SET is_enabled=false WHERE id=$1",
                &f.pricing,
            ),
            "role" => ("UPDATE roles SET is_enabled=false WHERE id=$1", &f.role),
            "user" => ("UPDATE users SET is_forbidden=true WHERE id=$1", &f.user),
            "provider" => (
                "UPDATE providers SET type='Stripe' WHERE id=$1",
                &f.provider,
            ),
            _ => ("UPDATE products SET currency='EUR' WHERE id=$1", &f.product),
        };
        sqlx::query(sql).bind(id).execute(&f.pool).await.unwrap();
        Renew::run_once(&f.pool, 10).await.unwrap();
        let state = Renew::status(&f.pool, &f.subscription).await.unwrap();
        assert_eq!(state.state.as_deref(), Some("blocked"), "{change}");
        assert_eq!(f.wallet().await, 90.0);
        assert_eq!(f.count("orders").await, 1);
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires migration036 and CASDOG_TEST_DATABASE_URL"]
async fn renewal_consent_requires_beneficiary_and_finite_proven_purchase_legacy_flags_do_not_charge()
 {
    let f = Fixture::new().await;
    f.due().await;
    let res = TestClient::post(format!(
        "http://localhost/api/set-subscription-auto-renew?id={}&autoRenew=true",
        f.subscription
    ))
    .add_header("Authorization", format!("Bearer {}", f.token(true)), true)
    .send(&f.app())
    .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    assert!(
        Renew::set_auto_renew(&f.pool, &f.subscription, "foreign", &f.user, true, true)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE subscriptions SET auto_renew=true WHERE id=$1")
            .bind(&f.subscription)
            .execute(&f.pool)
            .await
            .is_err()
    );
    // Even an imported old flag is not an authorization row.
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('casdog.renewal_consent','on',true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE subscriptions SET auto_renew=true WHERE id=$1")
        .bind(&f.subscription)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    Renew::run_once(&f.pool, 10).await.unwrap();
    assert_eq!(f.count("orders").await, 1);
    assert_eq!(f.wallet().await, 90.0);
    sqlx::query("UPDATE subscriptions SET end_date=NULL WHERE id=$1")
        .bind(&f.subscription)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        Renew::set_auto_renew(&f.pool, &f.subscription, &f.owner, &f.user, false, true)
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migration036 and CASDOG_TEST_DATABASE_URL"]
async fn external_renewal_is_one_explicit_action_order_and_never_background_offsession_charge() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE providers SET type='PayPal',client_id='client',client_secret='secret',host='sandbox' WHERE id=$1").bind(&f.provider).execute(&f.pool).await.unwrap();
    // The original paid ledger provides evidence; current provider identity and
    // the checkout-required mode are explicitly accepted by the beneficiary.
    let consent = f.enable().await;
    assert_eq!(consent["data2"]["mode"], "checkout_required");
    f.due().await;
    for _ in 0..3 {
        Renew::run_once(&f.pool, 10).await.unwrap();
    }
    let status = Renew::status(&f.pool, &f.subscription).await.unwrap();
    assert_eq!(status.state.as_deref(), Some("action_required"));
    assert_eq!(f.wallet().await, 90.0);
    assert_eq!(f.count("orders").await, 2);
    assert_eq!(f.count("payments").await, 1);
    let order = status.order_id.unwrap();
    let gateway = RecoveryGateway::new().await;
    let driver = gateway.paypal();
    let checkout = PaymentFlowService::start_order_payment_using(
        &f.pool, &order, None, &f.owner, "buyer", false, None, &driver,
    )
    .await
    .unwrap();
    assert!(!checkout.auto_paid);
    gateway.status(&checkout.payment.id, "APPROVED");
    let second = f.second_pool().await;
    let (a, b) = tokio::join!(
        Reconcile::run_once_using(&f.pool, 10, &driver),
        Reconcile::run_once_using(&second, 10, &driver)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(gateway.state.lock().unwrap().captures, 1);
    assert_eq!(
        Renew::status(&f.pool, &f.subscription)
            .await
            .unwrap()
            .state
            .as_deref(),
        Some("paid")
    );
    assert_eq!(f.count("transactions").await, 2);
    assert_eq!(f.wallet().await, 90.0);
    Reconcile::run_once_using(&f.pool, 10, &driver)
        .await
        .unwrap();
    Renew::run_once(&f.pool, 10).await.unwrap();
    assert_eq!(gateway.state.lock().unwrap().captures, 1);
    assert_eq!(f.count("orders").await, 2);
    f.cleanup().await;
    second.close().await;
}

#[derive(Clone)]
struct MockCheckout {
    local: String,
    external: String,
    currency: String,
    minor: i64,
    status: String,
    capture_pending: bool,
}
#[derive(Default)]
struct RecoveryGatewayState {
    records: HashMap<String, MockCheckout>,
    create_bodies: Vec<Vec<u8>>,
    create_keys: Vec<String>,
    capture_keys: Vec<String>,
    creates: usize,
    captures: usize,
    queries: usize,
    expires: usize,
    reject_create_once: bool,
    reject_capture_once: bool,
    drop_capture_once: bool,
    wrong_amount: bool,
    wrong_currency: bool,
    wrong_reference: bool,
    capture_pending: bool,
}
struct RecoveryGateway {
    base: String,
    state: std::sync::Arc<std::sync::Mutex<RecoveryGatewayState>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for RecoveryGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn read_gateway_request(
    stream: &mut tokio::net::TcpStream,
) -> (String, HashMap<String, String>, Vec<u8>) {
    use tokio::io::AsyncReadExt;
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    let end = loop {
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        data.extend_from_slice(&buffer[..count]);
        assert!(data.len() < 65536);
        if let Some(p) = data.windows(4).position(|v| v == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..end]);
    let path = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    let headers: HashMap<String, String> = head
        .lines()
        .skip(1)
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect();
    let length = headers
        .get("content-length")
        .map(|v| v.parse::<usize>().unwrap())
        .unwrap_or(0);
    while data.len() < end + length {
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        data.extend_from_slice(&buffer[..count]);
    }
    (path, headers, data[end..end + length].to_vec())
}
fn remote_json(record: &MockCheckout, state: &RecoveryGatewayState, paypal: bool) -> Value {
    let local = if state.wrong_reference {
        "another_payment"
    } else {
        &record.local
    };
    let currency = if state.wrong_currency {
        "EUR"
    } else {
        &record.currency
    };
    let minor = record.minor + if state.wrong_amount { 1 } else { 0 };
    if paypal {
        let money = json!({"currency_code":currency,"value":format!("{:.2}",minor as f64/100.0)});
        let mut unit = json!({"custom_id":local,"reference_id":local,"amount":money});
        if record.status == "COMPLETED" {
            unit["payments"] = json!({"captures":[{"id":"CAPTURE123","status":if record.capture_pending {"PENDING"}else{"COMPLETED"},"final_capture":true,"amount":money}]});
        }
        json!({"id":record.external,"intent":"CAPTURE","status":record.status,"purchase_units":[unit],"links":[{"rel":"approve","href":format!("https://www.sandbox.paypal.com/checkoutnow?token={}",record.external)}]})
    } else {
        json!({"id":record.external,"client_reference_id":local,"amount_total":minor,"currency":currency.to_ascii_lowercase(),"status":record.status,"payment_status":if record.status=="complete" {"paid"}else{"unpaid"},"url":if record.status=="open" {Some(format!("https://checkout.stripe.com/c/pay/{}",record.external))}else{None::<String>},"invoice":null})
    }
}
impl RecoveryGateway {
    async fn new() -> Self {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = std::sync::Arc::new(std::sync::Mutex::new(RecoveryGatewayState::default()));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (path, headers, body) = read_gateway_request(&mut stream).await;
                let (code, response, drop_reply) = {
                    let mut state = shared.lock().unwrap();
                    let mut code = 200;
                    let mut drop_reply = false;
                    let response = if path == "/v1/oauth2/token" {
                        assert!(headers["authorization"].starts_with("Basic "));
                        json!({"access_token":"gateway_token","expires_in":3600})
                    } else if path == "/v1/checkout/sessions" || path == "/v2/checkout/orders" {
                        let paypal = path.starts_with("/v2");
                        let key = headers[if paypal {
                            "paypal-request-id"
                        } else {
                            "idempotency-key"
                        }]
                        .clone();
                        state.create_keys.push(key.clone());
                        state.create_bodies.push(body.clone());
                        if state.reject_create_once {
                            state.reject_create_once = false;
                            code = 400;
                            json!({"error":"temporary_validation_rejection"})
                        } else {
                            if !state.records.contains_key(&key) {
                                let (currency, minor) = if paypal {
                                    let value: Value = serde_json::from_slice(&body).unwrap();
                                    assert_eq!(value["intent"], "CAPTURE");
                                    assert_eq!(value["purchase_units"][0]["custom_id"], key);
                                    (
                                        value["purchase_units"][0]["amount"]["currency_code"]
                                            .as_str()
                                            .unwrap()
                                            .to_owned(),
                                        (value["purchase_units"][0]["amount"]["value"]
                                            .as_str()
                                            .unwrap()
                                            .parse::<f64>()
                                            .unwrap()
                                            * 100.0)
                                            .round() as i64,
                                    )
                                } else {
                                    let url = reqwest::Url::parse(&format!(
                                        "http://test/?{}",
                                        std::str::from_utf8(&body).unwrap()
                                    ))
                                    .unwrap();
                                    let form: HashMap<_, _> = url
                                        .query_pairs()
                                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                                        .collect();
                                    assert_eq!(form["client_reference_id"], key);
                                    (
                                        form["line_items[0][price_data][currency]"]
                                            .to_ascii_uppercase(),
                                        form["line_items[0][price_data][unit_amount]"]
                                            .parse::<i64>()
                                            .unwrap(),
                                    )
                                };
                                state.creates += 1;
                                let external = if paypal {
                                    format!("PAYPAL{:016}", state.creates)
                                } else {
                                    format!("cs_recovery_{}", state.creates)
                                };
                                state.records.insert(
                                    key.clone(),
                                    MockCheckout {
                                        local: key.clone(),
                                        external,
                                        currency,
                                        minor,
                                        status: if paypal { "CREATED" } else { "open" }.into(),
                                        capture_pending: false,
                                    },
                                );
                            }
                            let record = state.records.get(&key).unwrap();
                            if paypal {
                                json!({"id":record.external,"status":record.status,"links":[{"rel":"approve","href":format!("https://www.sandbox.paypal.com/checkoutnow?token={}",record.external)}]})
                            } else {
                                json!({"id":record.external,"url":format!("https://checkout.stripe.com/c/pay/{}",record.external),"invoice":null})
                            }
                        }
                    } else {
                        let paypal = path.starts_with("/v2");
                        assert_eq!(
                            headers["authorization"],
                            if paypal {
                                "Bearer gateway_token"
                            } else {
                                "Bearer sk_gateway"
                            }
                        );
                        let external = if paypal {
                            path.strip_prefix("/v2/checkout/orders/")
                                .unwrap()
                                .split('/')
                                .next()
                                .unwrap()
                        } else {
                            path.strip_prefix("/v1/checkout/sessions/")
                                .unwrap()
                                .split('/')
                                .next()
                                .unwrap()
                        };
                        let local = state
                            .records
                            .values()
                            .find(|r| r.external == external)
                            .unwrap()
                            .local
                            .clone();
                        if path.ends_with("/capture") {
                            let key = headers["paypal-request-id"].clone();
                            assert_ne!(key, local);
                            assert!(key.len() <= 38);
                            state.capture_keys.push(key);
                            if state.reject_capture_once {
                                state.reject_capture_once = false;
                                code = 500;
                                json!({"error":"temporary_gateway_failure"})
                            } else {
                                let pending = state.capture_pending;
                                let record = state.records.get_mut(&local).unwrap();
                                if record.status != "COMPLETED" {
                                    record.status = "COMPLETED".into();
                                    record.capture_pending = pending;
                                    state.captures += 1;
                                }
                                if state.drop_capture_once {
                                    state.drop_capture_once = false;
                                    drop_reply = true;
                                }
                                remote_json(state.records.get(&local).unwrap(), &state, true)
                            }
                        } else if path.ends_with("/expire") {
                            state.expires += 1;
                            let record = state.records.get_mut(&local).unwrap();
                            if record.status == "complete" {
                                code = 409;
                                json!({"error":"already_paid"})
                            } else {
                                record.status = "expired".into();
                                remote_json(state.records.get(&local).unwrap(), &state, false)
                            }
                        } else {
                            state.queries += 1;
                            remote_json(state.records.get(&local).unwrap(), &state, paypal)
                        }
                    };
                    (code, response.to_string(), drop_reply)
                };
                if drop_reply {
                    continue;
                }
                stream.write_all(format!("HTTP/1.1 {code} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).as_bytes()).await.unwrap();
            }
        });
        Self { base, state, task }
    }
    fn stripe(&self) -> casdog::services::providers::stripe_payment::StripePaymentProvider {
        casdog::services::providers::stripe_payment::StripePaymentProvider::new(
            "sk_gateway".into(),
            None,
        )
        .with_api_base(&format!("{}/v1", self.base))
        .unwrap()
    }
    fn paypal(&self) -> casdog::services::providers::paypal_payment::PayPalPaymentProvider {
        casdog::services::providers::paypal_payment::PayPalPaymentProvider::new(
            "client".into(),
            "secret".into(),
            "sandbox".into(),
            None,
        )
        .with_api_base(&self.base)
        .unwrap()
    }
    fn status(&self, local: &str, status: &str) {
        let mut state = self.state.lock().unwrap();
        let record = state.records.get_mut(local).unwrap();
        record.status = status.into();
        record.capture_pending = false;
    }
}

struct LoseCreate {
    inner: casdog::services::providers::stripe_payment::StripePaymentProvider,
    lost: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl casdog::services::providers::payment_provider::PaymentProvider for LoseCreate {
    async fn pay(
        &self,
        r: &casdog::services::providers::payment_provider::PayRequest,
    ) -> casdog::error::AppResult<casdog::services::providers::payment_provider::PayResponse> {
        let response = self.inner.pay(r).await?;
        if !self.lost.swap(true, std::sync::atomic::Ordering::SeqCst) {
            Err(casdog::error::AppError::Internal(
                "Simulated process died after remote creation".into(),
            ))
        } else {
            Ok(response)
        }
    }
    async fn notify(
        &self,
        b: &[u8],
        h: &HashMap<String, String>,
        id: Option<&str>,
    ) -> casdog::error::AppResult<casdog::services::providers::payment_provider::NotifyResult> {
        self.inner.notify(b, h, id).await
    }
    async fn get_invoice(&self, id: &str) -> casdog::error::AppResult<String> {
        self.inner.get_invoice(id).await
    }
    async fn query_payment(
        &self,
        id: &str,
        local: &str,
    ) -> casdog::error::AppResult<casdog::services::providers::payment_provider::RemotePayment>
    {
        self.inner.query_payment(id, local).await
    }
}

#[tokio::test]
#[ignore = "requires migration036 and CASDOG_TEST_DATABASE_URL"]
async fn background_queue_recovers_unknown_checkout_reuses_key_and_rejects_wrong_money_before_paid()
{
    let f = Fixture::new().await;
    let gateway = RecoveryGateway::new().await;
    sqlx::query("UPDATE providers SET type='Stripe',client_secret='sk_gateway' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    let order = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO orders(id,owner,name,display_name,product_name,quantity,price,currency,\"user\",provider,plan_name,pricing_name) VALUES($1,$2,$1,'Membership','membership',1,10,'USD','buyer',$3,'premium','public')").bind(&order).bind(&f.owner).bind(&f.provider).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO order_benefits(order_id,kind,user_id,amount_cents,plan_id,pricing_id,period,role_id) VALUES($1,'plan',$2,1000,$3,$4,'monthly',$5)").bind(&order).bind(&f.user).bind(&f.plan).bind(&f.pricing).bind(&f.role).execute(&f.pool).await.unwrap();
    let lost = LoseCreate {
        inner: gateway.stripe(),
        lost: std::sync::atomic::AtomicBool::new(false),
    };
    assert!(
        PaymentFlowService::start_order_payment_using(
            &f.pool, &order, None, &f.owner, "buyer", false, None, &lost
        )
        .await
        .is_err()
    );
    let payment: String = sqlx::query_scalar("SELECT payment_id FROM orders WHERE id=$1")
        .bind(&order)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(gateway.state.lock().unwrap().creates, 1);
    let original = gateway.state.lock().unwrap().create_bodies[0].clone();
    // Profile changes or a disabled account cannot redirect an already accepted
    // payment. Recovery uses the original request and pinned buyer, no JWT.
    sqlx::query(
        "UPDATE users SET name='renamed',email='changed@example.com',is_forbidden=true WHERE id=$1",
    )
    .bind(&f.user)
    .execute(&f.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE organizations SET disable_signin=true WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    let driver = gateway.stripe();
    let second = f.second_pool().await;
    let (a, b) = tokio::join!(
        Reconcile::run_once_using(&f.pool, 10, &driver),
        Reconcile::run_once_using(&second, 10, &driver)
    );
    a.unwrap();
    b.unwrap();
    {
        let state = gateway.state.lock().unwrap();
        assert_eq!(state.creates, 1);
        assert_eq!(state.create_keys, vec![payment.clone(), payment.clone()]);
        assert_eq!(state.create_bodies[1], original);
    }
    gateway.status(&payment, "complete");
    gateway.state.lock().unwrap().wrong_amount = true;
    sqlx::query("UPDATE payment_reconcile_queue SET next_attempt_at=NOW() WHERE payment_id=$1")
        .bind(&payment)
        .execute(&f.pool)
        .await
        .unwrap();
    Reconcile::run_once_using(&f.pool, 10, &driver)
        .await
        .unwrap();
    assert_eq!(f.count("transactions").await, 1);
    assert_eq!(f.wallet().await, 90.0);
    let error: Option<String> =
        sqlx::query_scalar("SELECT last_error FROM payment_reconcile_queue WHERE payment_id=$1")
            .bind(&payment)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(error.unwrap().to_lowercase().contains("amount"));
    gateway.state.lock().unwrap().wrong_amount = false;
    sqlx::query("UPDATE payment_reconcile_queue SET next_attempt_at=NOW() WHERE payment_id=$1")
        .bind(&payment)
        .execute(&f.pool)
        .await
        .unwrap();
    Reconcile::run_once_using(&second, 10, &driver)
        .await
        .unwrap();
    Reconcile::run_once_using(&f.pool, 10, &driver)
        .await
        .unwrap();
    assert_eq!(f.count("transactions").await, 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM payment_reconcile_queue WHERE payment_id=$1"
        )
        .bind(&payment)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(f.wallet().await, 90.0);
    assert!(
        casdog::services::SubscriptionService::active_role_names(&f.pool, &f.owner, "renamed")
            .await
            .unwrap()
            .is_empty()
    );
    f.cleanup().await;
    second.close().await;
}

#[tokio::test]
#[ignore = "requires migration036 and CASDOG_TEST_DATABASE_URL"]
async fn displayed_renewal_quote_cannot_authorize_a_concurrent_price_increase() {
    let f = Fixture::new().await;
    // Store displayed $10; an administrator changes the price before consent.
    sqlx::query("UPDATE plans SET price_per_month=11 WHERE id=$1")
        .bind(&f.plan)
        .execute(&f.pool)
        .await
        .unwrap();
    for (query, status) in [
        ("maxAmountCents=1000&currency=USD", StatusCode::CONFLICT),
        ("maxAmountCents=1100&currency=EUR", StatusCode::CONFLICT),
        ("maxAmountCents=1100", StatusCode::BAD_REQUEST),
        ("currency=USD", StatusCode::BAD_REQUEST),
        ("maxAmountCents=-1&currency=USD", StatusCode::BAD_REQUEST),
        (
            "maxAmountCents=1100.0&currency=USD",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let res = TestClient::post(format!(
            "http://localhost/api/set-subscription-auto-renew?id={}&autoRenew=true&{query}",
            f.subscription
        ))
        .add_header("Authorization", format!("Bearer {}", f.token(false)), true)
        .send(&f.app())
        .await;
        assert_eq!(res.status_code, Some(status), "{query}");
        assert!(
            !Renew::status(&f.pool, &f.subscription)
                .await
                .unwrap()
                .enabled
        );
    }
    // If price fell, bind the lower actual price, not a hidden future allowance.
    let mut res=TestClient::post(format!("http://localhost/api/set-subscription-auto-renew?id={}&autoRenew=true&maxAmountCents=1200&currency=usd",f.subscription)).add_header("Authorization",format!("Bearer {}",f.token(false)),true).send(&f.app()).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let data: Value = res.take_json().await.unwrap();
    assert_eq!(data["data2"]["max_amount_cents"], 1100);
    f.due().await;
    Renew::run_once(&f.pool, 10).await.unwrap();
    assert_eq!(f.wallet().await, 79.0);
    assert_eq!(f.count("transactions").await, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migration036 and CASDOG_TEST_DATABASE_URL"]
async fn disabled_or_deleted_organization_blocks_new_debits_and_restores_same_due_work() {
    for flag in ["is_deleted", "disable_signin"] {
        let f = Fixture::new().await;
        f.enable().await;
        let due = f.due().await;
        sqlx::query(&format!(
            "UPDATE organizations SET {flag}=true WHERE name=$1"
        ))
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
        Renew::run_once(&f.pool, 10).await.unwrap();
        let blocked = Renew::status(&f.pool, &f.subscription).await.unwrap();
        assert_eq!(blocked.state.as_deref(), Some("blocked"));
        assert!(blocked.last_error.unwrap().contains("organization"));
        assert!(blocked.order_id.is_none());
        assert_eq!(f.wallet().await, 90.0);
        assert_eq!(f.count("orders").await, 1);
        assert_eq!(f.count("payments").await, 1);
        let work: String =
            sqlx::query_scalar("SELECT id FROM subscription_renewal_work WHERE subscription_id=$1")
                .bind(&f.subscription)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        sqlx::query(&format!(
            "UPDATE organizations SET {flag}=false WHERE name=$1"
        ))
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
        // Advance the durable retry deadline instead of sleeping five minutes.
        sqlx::query("UPDATE subscription_renewal_work SET next_attempt_at=NOW() WHERE id=$1")
            .bind(&work)
            .execute(&f.pool)
            .await
            .unwrap();
        Renew::run_once(&f.pool, 10).await.unwrap();
        assert_eq!(f.wallet().await, 80.0);
        assert_eq!(f.count("orders").await, 2);
        assert_eq!(f.count("payments").await, 2);
        assert_eq!(
            Renew::status(&f.pool, &f.subscription)
                .await
                .unwrap()
                .state
                .as_deref(),
            Some("paid")
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT id FROM subscription_renewal_work WHERE subscription_id=$1"
            )
            .bind(&f.subscription)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            work
        );
        assert_eq!(
            sqlx::query_scalar::<_, DateTime<Utc>>(
                "SELECT end_date FROM subscriptions WHERE id=$1"
            )
            .bind(&f.subscription)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            due.checked_add_months(chrono::Months::new(1)).unwrap()
        );
        f.cleanup().await;
    }
}
