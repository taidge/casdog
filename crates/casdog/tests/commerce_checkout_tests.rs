//! Real PostgreSQL regressions for checkout inventory, settlement and entry points.
use casdog::services::PaymentFlowService;
use hmac::{Hmac, Mac};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::collections::HashMap;

#[derive(Clone)]
struct Identity {
    id: String,
    owner: String,
    name: String,
    admin: bool,
}
#[handler]
async fn identify(depot: &mut Depot) {
    if let Some(p) = depot.obtain::<Option<Identity>>().unwrap().clone() {
        depot.insert("user_id", p.id);
        depot.insert("user_owner", p.owner);
        depot.insert("user_name", p.name);
        depot.insert("is_admin", p.admin);
    }
}
fn service(pool: &PgPool, identity: Option<Identity>) -> Service {
    Service::new(
        Router::with_path("api")
            .push(casdog::handlers::parity_operations::routes())
            .push(casdog::handlers::casdoor_compat::routes())
            .push(
                Router::with_path("notify-payment").post(casdog::handlers::payment::notify_payment),
            )
            .push(Router::with_path("products").post(casdog::handlers::product::create_product))
            .push(
                Router::with_path("products/{id}")
                    .get(casdog::handlers::product::get_product)
                    .put(casdog::handlers::product::update_product),
            ),
    )
    .hoop(
        salvo::affix_state::AffixList::new()
            .inject(pool.clone())
            .inject(identity),
    )
    .hoop(identify)
}
async fn database() -> PgPool {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        casdog::config::AppConfig::load().unwrap();
    });
    PgPoolOptions::new()
        .max_connections(12)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").expect("set CASDOG_TEST_DATABASE_URL"))
        .await
        .unwrap()
}
struct Fixture {
    pool: PgPool,
    owner: String,
    buyer: Identity,
    admin: Identity,
    product: String,
    provider: String,
}
impl Fixture {
    async fn new(quantity: i32) -> Self {
        let pool = database().await;
        let owner = format!("checkout-{}", uuid::Uuid::new_v4());
        sqlx::query("INSERT INTO organizations(id,owner,name,display_name,is_deleted,disable_signin) VALUES($1,$2,$2,'Checkout',false,false)")
            .bind(uuid::Uuid::new_v4().to_string()).bind(&owner).execute(&pool).await.unwrap();
        let buyer = Identity {
            id: uuid::Uuid::new_v4().to_string(),
            owner: owner.clone(),
            name: "buyer".into(),
            admin: false,
        };
        let admin = Identity {
            id: uuid::Uuid::new_v4().to_string(),
            owner: owner.clone(),
            name: "admin".into(),
            admin: true,
        };
        for p in [&buyer, &admin] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin,balance) VALUES($1,$2,$3,$3,'unused',$4,100)")
                .bind(&p.id).bind(&p.owner).bind(&p.name).bind(p.admin).execute(&pool).await.unwrap();
        }
        let product = uuid::Uuid::new_v4().to_string();
        let provider = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO products(id,owner,name,display_name,price,quantity,currency) VALUES($1,$2,'book','Book',20,$3,'USD')")
            .bind(&product).bind(&owner).bind(quantity).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES($1,$2,'checkout','Checkout','Payment','Dummy')")
            .bind(&provider).bind(&owner).execute(&pool).await.unwrap();
        Self {
            pool,
            owner,
            buyer,
            admin,
            product,
            provider,
        }
    }
    async fn order(&self, quantity: i32) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO orders(id,owner,name,display_name,product_name,quantity,price,currency,\"user\") VALUES($1,$2,$1,'Book','book',$3,20,'USD','buyer')")
            .bind(&id).bind(&self.owner).bind(quantity).execute(&self.pool).await.unwrap();
        id
    }
    async fn start(
        &self,
        id: &str,
    ) -> casdog::error::AppResult<casdog::services::payment_flow_service::PaymentStartResult> {
        PaymentFlowService::start_order_payment(
            &self.pool,
            id,
            Some(&self.provider),
            &self.owner,
            "buyer",
            false,
            None,
        )
        .await
    }
    async fn stock(&self) -> (i32, i32) {
        sqlx::query_as("SELECT quantity,sold FROM products WHERE id=$1")
            .bind(&self.product)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn cleanup(&self) {
        // Resolve any intentionally pending checkout before removing its history.
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM orders WHERE owner=$1 AND lower(state) IN ('created','processing')",
        )
        .bind(&self.owner)
        .fetch_all(&self.pool)
        .await
        .unwrap();
        for id in ids {
            PaymentFlowService::cancel_order(&self.pool, &id, &self.owner, "admin", true)
                .await
                .unwrap();
        }
        sqlx::query(
            "DELETE FROM coupon_usages WHERE order_id IN (SELECT id FROM orders WHERE owner=$1)",
        )
        .bind(&self.owner)
        .execute(&self.pool)
        .await
        .unwrap();
        let mut cleanup = self.pool.begin().await.unwrap();
        sqlx::query("SELECT set_config('casdog.checkout_write','on',true)")
            .execute(&mut *cleanup)
            .await
            .unwrap();
        sqlx::query("DELETE FROM subscriptions WHERE owner=$1")
            .bind(&self.owner)
            .execute(&mut *cleanup)
            .await
            .unwrap();
        sqlx::query(
            "DELETE FROM order_benefits WHERE order_id IN(SELECT id FROM orders WHERE owner=$1)",
        )
        .bind(&self.owner)
        .execute(&mut *cleanup)
        .await
        .unwrap();
        cleanup.commit().await.unwrap();
        for table in [
            "transactions",
            "orders",
            "payments",
            "products",
            "providers",
            "coupons",
            "plans",
            "pricings",
            "roles",
            "users",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1"))
                .bind(&self.owner)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM organizations WHERE name=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn async_checkout_reserves_last_item_reuses_payment_and_releases_once() {
    let f = Fixture::new(1).await;
    let order = f.order(1).await;
    let competing = f.order(1).await;
    let foreign_provider = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES($1,'foreign-checkout','payment','Payment','Payment','Balance')")
        .bind(&foreign_provider).execute(&f.pool).await.unwrap();
    assert!(
        PaymentFlowService::start_order_payment(
            &f.pool,
            &order,
            Some(&foreign_provider),
            &f.owner,
            "buyer",
            false,
            None
        )
        .await
        .is_err()
    );
    sqlx::query("DELETE FROM providers WHERE id=$1")
        .bind(&foreign_provider)
        .execute(&f.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(f.start(&order), f.start(&order));
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.payment.id, b.payment.id);
    assert_eq!(f.stock().await, (0, 0));
    assert!(f.start(&competing).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM payments WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    // A tenant admin cannot operate another tenant's order through the service.
    assert!(
        PaymentFlowService::cancel_order(&f.pool, &order, "another-tenant", "admin", true)
            .await
            .is_err()
    );
    for _ in 0..2 {
        PaymentFlowService::cancel_order(&f.pool, &order, &f.owner, "buyer", false)
            .await
            .unwrap();
        assert_eq!(f.stock().await, (1, 0));
    }
    // Dummy is explicitly local-only and cannot charge after cancellation.
    let late =
        PaymentFlowService::manual_notify_payment(&f.pool, &a.payment.id, "Paid", None, None)
            .await
            .unwrap();
    assert_eq!(late.payment.state, "canceled");
    assert_eq!(f.stock().await, (1, 0));
    assert!(f.start(&order).await.is_err());
    let next = f.start(&competing).await.unwrap();
    let settled =
        PaymentFlowService::manual_notify_payment(&f.pool, &next.payment.id, "Paid", None, None)
            .await
            .unwrap();
    assert!(settled.transaction_name.is_some());
    for state in ["Paid", "Failed", "Pending", "Paid"] {
        let repeated =
            PaymentFlowService::manual_notify_payment(&f.pool, &next.payment.id, state, None, None)
                .await
                .unwrap();
        assert_eq!(repeated.payment.state, "paid");
        assert!(repeated.transaction_name.is_none());
    }
    assert_eq!(f.stock().await, (0, 1));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    assert!(
        PaymentFlowService::cancel_order(&f.pool, &competing, &f.owner, "buyer", false)
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn buy_product_manual_settlement_requires_tenant_admin_and_legacy_cannot_bypass() {
    let f = Fixture::new(2).await;
    let admin = service(&f.pool, Some(f.admin.clone()));
    let buyer = service(&f.pool, Some(f.buyer.clone()));
    let anonymous = service(&f.pool, None);
    let foreign = service(
        &f.pool,
        Some(Identity {
            owner: "foreign".into(),
            ..f.admin.clone()
        }),
    );
    let coupon=TestClient::post("http://localhost/api/add-coupon")
        .json(&json!({"owner":f.owner,"name":"discount","code":"SAVE","discountType":"fixed","discount":5,"quantity":1,"maxUsagePerUser":1,"currency":"USD"}))
        .send(&admin).await;
    assert_eq!(coupon.status_code, Some(StatusCode::OK));
    let mut response = TestClient::post(format!(
        "http://localhost/api/buy-product?id={}&providerName={}&couponCode=SAVE",
        f.product, f.provider
    ))
    .send(&buyer)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let checkout: Value = response.take_json().await.unwrap();
    let payment = checkout["data"]["id"].as_str().unwrap();
    let order = checkout["order"]["id"].as_str().unwrap();
    assert_eq!(checkout["order"]["price"], 15.0);
    assert_eq!(f.stock().await, (1, 0));
    let notification = json!({"id":payment,"state":"Paid"});
    for (svc, status) in [
        (&anonymous, StatusCode::UNAUTHORIZED),
        (&buyer, StatusCode::FORBIDDEN),
        (&foreign, StatusCode::FORBIDDEN),
    ] {
        let res = TestClient::post("http://localhost/api/notify-payment")
            .json(&notification)
            .send(svc)
            .await;
        assert_eq!(res.status_code, Some(status));
    }
    // Public callbacks cannot use the always-successful development provider.
    let res = TestClient::post("http://localhost/api/notify-payment")
        .json(&json!({"id":payment}))
        .send(&anonymous)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::UNAUTHORIZED));
    for (kind, id, patch) in [
        ("order", order, json!({"state":"Paid"})),
        ("order", order, json!({"price":0.0})),
        ("order", order, json!({"quantity":99})),
        ("payment", payment, json!({"state":"paid"})),
        ("payment", payment, json!({"amount":0.0})),
    ] {
        let res = TestClient::post(format!("http://localhost/api/update-{kind}?id={id}"))
            .json(&patch)
            .send(&admin)
            .await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::CONFLICT),
            "legacy {kind} mutation must use checkout lifecycle"
        );
    }
    let res = TestClient::post(format!("http://localhost/api/delete-order?id={order}"))
        .json(&json!({}))
        .send(&admin)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
    // Nonfinancial administration stays available while checkout is pending.
    let res = TestClient::post(format!("http://localhost/api/update-order?id={order}"))
        .json(&json!({"displayName":"Edited title"}))
        .send(&admin)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let res = TestClient::post("http://localhost/api/notify-payment")
        .json(&notification)
        .send(&admin)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let res = TestClient::post("http://localhost/api/notify-payment")
        .json(&json!({"id":payment,"state":"Failed"}))
        .send(&admin)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    assert_eq!(f.stock().await, (1, 1));
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM orders WHERE id=$1")
            .bind(order)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        "Paid"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT used_count FROM coupons WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, f64>("SELECT balance FROM users WHERE id=$1")
            .bind(&f.buyer.id)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        100.0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    f.cleanup().await;
}

fn stripe_headers(body: &[u8], timestamp: i64) -> HashMap<String, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec_checkout_test").unwrap();
    mac.update(format!("{timestamp}.").as_bytes());
    mac.update(body);
    HashMap::from([(
        "stripe-signature".into(),
        format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        ),
    )])
}
fn stripe_event(id: &str, event_type: &str, amount: i64, currency: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"type":event_type,"data":{"object":{"id":id,"amount_total":amount,"currency":currency,"payment_status":"paid"}}})).unwrap()
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn signed_notifications_validate_amount_currency_time_and_settle_once() {
    let f = Fixture::new(2).await;
    let order = f.order(1).await;
    let checkout = f.start(&order).await.unwrap();
    let expiring_order = f.order(1).await;
    let expiring = f.start(&expiring_order).await.unwrap();
    // The deterministic checkout exercises the normal stock reservation path;
    // configure its provider as Stripe for local signed-webhook verification.
    sqlx::query(
        "UPDATE providers SET type='Stripe',client_secret='sk_test_unused',metadata=$2 WHERE id=$1",
    )
    .bind(&f.provider)
    .bind(json!({"webhookSecret":"whsec_checkout_test"}).to_string())
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(
        PaymentFlowService::cancel_order(&f.pool, &order, &f.owner, "buyer", false)
            .await
            .is_err()
    );
    assert_eq!(f.stock().await, (0, 0));
    let now = chrono::Utc::now().timestamp();
    for (amount, currency, when) in [
        (1999, "usd", now),
        (2000, "eur", now),
        (2000, "usd", now - 301),
    ] {
        let body = stripe_event(
            &checkout.payment.id,
            "checkout.session.completed",
            amount,
            currency,
        );
        assert!(
            PaymentFlowService::notify_payment(
                &f.pool,
                &checkout.payment.id,
                &stripe_headers(&body, when),
                &body
            )
            .await
            .is_err()
        );
        assert_eq!(f.stock().await, (0, 0));
    }
    let body = stripe_event(
        &checkout.payment.id,
        "checkout.session.completed",
        2000,
        "usd",
    );
    assert!(
        PaymentFlowService::notify_payment(&f.pool, &checkout.payment.id, &HashMap::new(), &body)
            .await
            .is_err()
    );
    let headers = stripe_headers(&body, now);
    let (a, b) = tokio::join!(
        PaymentFlowService::notify_payment(&f.pool, &checkout.payment.id, &headers, &body),
        PaymentFlowService::notify_payment(&f.pool, &checkout.payment.id, &headers, &body),
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.payment.state, "paid");
    assert_eq!(b.payment.state, "paid");
    assert_ne!(a.transaction_name.is_some(), b.transaction_name.is_some());
    let late = stripe_event(
        &checkout.payment.id,
        "checkout.session.expired",
        2000,
        "usd",
    );
    let result = PaymentFlowService::notify_payment(
        &f.pool,
        &checkout.payment.id,
        &stripe_headers(&late, now),
        &late,
    )
    .await
    .unwrap();
    assert_eq!(result.payment.state, "paid");
    assert_eq!(f.stock().await, (0, 1));
    let expired = stripe_event(
        &expiring.payment.id,
        "checkout.session.expired",
        2000,
        "usd",
    );
    for _ in 0..2 {
        let result = PaymentFlowService::notify_payment(
            &f.pool,
            &expiring.payment.id,
            &stripe_headers(&expired, now),
            &expired,
        )
        .await
        .unwrap();
        assert_eq!(result.payment.state, "failed");
        assert_eq!(f.stock().await, (1, 1));
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn failed_notification_releases_durable_stock_and_coupon_exactly_once() {
    let f = Fixture::new(1).await;
    let buyer = service(&f.pool, Some(f.buyer.clone()));
    let admin = service(&f.pool, Some(f.admin.clone()));
    let res=TestClient::post("http://localhost/api/add-coupon").json(&json!({"owner":f.owner,"name":"discount","code":"SAVE","discountType":"fixed","discount":5,"quantity":1})).send(&admin).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let mut res = TestClient::post(format!(
        "http://localhost/api/buy-product?id={}&providerName={}&couponCode=SAVE",
        f.product, f.provider
    ))
    .send(&buyer)
    .await;
    let data: Value = res.take_json().await.unwrap();
    let payment = data["data"]["id"].as_str().unwrap();
    assert_eq!(f.stock().await, (0, 0));
    for state in ["Failed", "Failed", "Paid"] {
        let result = PaymentFlowService::manual_notify_payment(&f.pool, payment, state, None, None)
            .await
            .unwrap();
        assert_eq!(result.payment.state, "failed");
        assert_eq!(f.stock().await, (1, 0));
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM coupon_usages WHERE order_id=$1")
            .bind(data["order"]["id"].as_str().unwrap())
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT used_count FROM coupons WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    let res = TestClient::post(format!(
        "http://localhost/api/buy-product?id={}&providerName={}&couponCode=SAVE",
        f.product, f.provider
    ))
    .send(&buyer)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    f.cleanup().await;
}

#[tokio::test]
async fn external_providers_reject_notifications_without_verification_configuration() {
    use casdog::services::providers::{
        payment_provider::PaymentProvider, paypal_payment::PayPalPaymentProvider,
        stripe_payment::StripePaymentProvider,
    };
    let stripe = StripePaymentProvider::new("unused".into(), None);
    assert!(stripe.notify(b"{}", &HashMap::new(), None).await.is_err());
    let paypal =
        PayPalPaymentProvider::new("unused".into(), "unused".into(), "sandbox".into(), None);
    assert!(paypal.notify(b"{}", &HashMap::new(), None).await.is_err());
}

fn token(p: &Identity) -> String {
    let config = casdog::config::AppConfig::get();
    let now = chrono::Utc::now();
    jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({
        "sub":p.id,"owner":p.owner,"name":p.name,"is_admin":p.admin,
        "iat":now.timestamp(),"exp":now.timestamp()+3600,"issued_at_ms":now.timestamp_millis(),"iss":config.jwt.issuer,
    }),&jsonwebtoken::EncodingKey::from_secret(config.jwt.secret.as_bytes())).unwrap()
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn real_router_accepts_signed_public_webhooks_and_authenticates_manual_notifications() {
    let f = Fixture::new(2).await;
    let order = f.order(1).await;
    let payment = f.start(&order).await.unwrap().payment;
    let app = Service::new(casdog::routes::create_router())
        .hoop(salvo::affix_state::AffixList::new().inject(f.pool.clone()));
    for (identity, status) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(&f.buyer), StatusCode::FORBIDDEN),
    ] {
        let mut request = TestClient::post("http://localhost/api/notify-payment")
            .json(&json!({"id":payment.id,"state":"Paid"}));
        if let Some(p) = identity {
            request = request.add_header("Authorization", format!("Bearer {}", token(p)), true);
        }
        assert_eq!(request.send(&app).await.status_code, Some(status));
    }
    let outsider = Identity {
        owner: format!("checkout-other-{}", uuid::Uuid::new_v4()),
        id: uuid::Uuid::new_v4().to_string(),
        ..f.admin.clone()
    };
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,'admin','Admin','unused',true)")
        .bind(&outsider.id).bind(&outsider.owner).execute(&f.pool).await.unwrap();
    let res = TestClient::post("http://localhost/api/payments/notify")
        .add_header(
            "Authorization",
            format!("Bearer {}", token(&outsider)),
            true,
        )
        .json(&json!({"id":payment.id,"state":"Paid"}))
        .send(&app)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let res = TestClient::post("http://localhost/api/payments/notify")
        .add_header("Authorization", format!("Bearer {}", token(&f.admin)), true)
        .json(&json!({"id":payment.id,"state":"Paid"}))
        .send(&app)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let second_order = f.order(1).await;
    let second = f.start(&second_order).await.unwrap().payment;
    sqlx::query(
        "UPDATE providers SET type='Stripe',client_secret='sk_test_unused',metadata=$2 WHERE id=$1",
    )
    .bind(&f.provider)
    .bind(json!({"webhookSecret":"whsec_checkout_test"}).to_string())
    .execute(&f.pool)
    .await
    .unwrap();
    let peer = Identity {
        id: uuid::Uuid::new_v4().to_string(),
        name: "other-buyer".into(),
        ..f.buyer.clone()
    };
    let foreign_buyer = Identity {
        id: uuid::Uuid::new_v4().to_string(),
        owner: outsider.owner.clone(),
        ..f.buyer.clone()
    };
    for p in [&peer, &foreign_buyer] {
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,$3,'unused',false)")
            .bind(&p.id).bind(&p.owner).bind(&p.name).execute(&f.pool).await.unwrap();
    }
    let pay_paths = [
        format!("pay-order?id={second_order}"),
        format!("orders/{second_order}/pay"),
    ];
    let cancel_paths = [
        format!("cancel-order?id={second_order}"),
        format!("orders/{second_order}/cancel"),
    ];
    for p in [&peer, &foreign_buyer, &outsider] {
        for path in pay_paths.iter().chain(cancel_paths.iter()) {
            let res = TestClient::post(format!("http://localhost/api/{path}"))
                .add_header("Authorization", format!("Bearer {}", token(p)), true)
                .send(&app)
                .await;
            assert_eq!(
                res.status_code,
                Some(StatusCode::FORBIDDEN),
                "{} {path}",
                p.owner
            );
            assert_eq!(f.stock().await, (0, 1));
            let snapshot: (String, i32, f64, String) =
                sqlx::query_as("SELECT state,quantity,price,payment_id FROM orders WHERE id=$1")
                    .bind(&second_order)
                    .fetch_one(&f.pool)
                    .await
                    .unwrap();
            assert_eq!(snapshot, ("Created".into(), 1, 20.0, second.id.clone()));
        }
    }
    for path in &pay_paths {
        let mut res = TestClient::post(format!("http://localhost/api/{path}"))
            .add_header("Authorization", format!("Bearer {}", token(&f.buyer)), true)
            .send(&app)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK), "{path}");
        assert_eq!(
            res.take_json::<Value>().await.unwrap()["payment"]["id"],
            second.id
        );
        assert_eq!(f.stock().await, (0, 1));
    }
    for path in &cancel_paths {
        let res = TestClient::post(format!("http://localhost/api/{path}"))
            .add_header("Authorization", format!("Bearer {}", token(&f.buyer)), true)
            .send(&app)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::CONFLICT), "{path}");
        assert_eq!(f.stock().await, (0, 1));
    }
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM orders WHERE id=$1")
            .bind(&second_order)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        "Created"
    );
    assert_eq!(f.stock().await, (0, 1));
    let mut body: Value = serde_json::from_slice(&stripe_event(
        &second.id,
        "checkout.session.completed",
        2000,
        "usd",
    ))
    .unwrap();
    body["id"] = json!("evt_provider_event_id");
    let body = serde_json::to_vec(&body).unwrap();
    let headers = stripe_headers(&body, chrono::Utc::now().timestamp());
    let res = TestClient::post(format!(
        "http://localhost/api/notify-payment/{}/{}",
        f.owner, second.name
    ))
    .add_header("Content-Type", "application/json", true)
    .add_header(
        "stripe-signature",
        headers["stripe-signature"].clone(),
        true,
    )
    .body(body.clone())
    .send(&app)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    // A single shared Stripe webhook address resolves our internal reference,
    // rather than confusing the provider's event ID with a local payment ID.
    let mut flat: Value = serde_json::from_slice(&body).unwrap();
    flat["data"]["object"]["client_reference_id"] = json!(second.id);
    let flat = serde_json::to_vec(&flat).unwrap();
    let flat_headers = stripe_headers(&flat, chrono::Utc::now().timestamp());
    let res = TestClient::post("http://localhost/api/notify-payment")
        .add_header("Content-Type", "application/json", true)
        .add_header(
            "stripe-signature",
            flat_headers["stripe-signature"].clone(),
            true,
        )
        .body(flat)
        .send(&app)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    assert_eq!(f.stock().await, (0, 2));
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(&outsider.id)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(&foreign_buyer.id)
        .execute(&f.pool)
        .await
        .unwrap();
    f.cleanup().await;
}

async fn isolated_checkout_schema(
    pool: &PgPool,
) -> (sqlx::pool::PoolConnection<sqlx::Postgres>, String) {
    let schema = format!("checkout_migration_{}", uuid::Uuid::new_v4().simple());
    let mut connection = pool.acquire().await.unwrap();
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema},public;
        CREATE TABLE products (LIKE public.products INCLUDING ALL);
        CREATE TABLE orders (LIKE public.orders INCLUDING ALL);
        CREATE TABLE payments (LIKE public.payments INCLUDING ALL);"
    ))
    .execute(&mut *connection)
    .await
    .unwrap();
    (connection, schema)
}
async fn drop_checkout_schema(connection: &mut sqlx::PgConnection, schema: &str) {
    assert!(
        schema.starts_with("checkout_migration_")
            && schema
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
    );
    sqlx::raw_sql(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE;"
    ))
    .execute(connection)
    .await
    .unwrap();
}
const CHECKOUT_MIGRATION: &str = include_str!("../../../migrations/028_checkout_reservations.sql");

async fn add_legacy(app: &Service, kind: &str, body: Value) -> Value {
    let mut res = TestClient::post(format!("http://localhost/api/add-{kind}"))
        .json(&body)
        .send(app)
        .await;
    let status = res.status_code;
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    res.take_json::<Value>().await.unwrap()["object"].clone()
}
struct PlanSetup {
    plan: String,
    pricing: String,
    role: String,
}
async fn configure_plan(f: &Fixture, app: &Service) -> PlanSetup {
    let role = add_legacy(
        app,
        "role",
        json!({"owner":f.owner,"name":"premium","displayName":"Premium"}),
    )
    .await;
    let plan=add_legacy(app,"plan",json!({"owner":f.owner,"name":"premium","displayName":"Premium plan","pricePerMonth":10,"pricePerYear":100,"currency":"USD","role":role["id"]})).await;
    let pricing = add_legacy(
        app,
        "pricing",
        json!({"owner":f.owner,"name":"public","displayName":"Public pricing","plans":["premium"]}),
    )
    .await;
    let res = TestClient::put(format!("http://localhost/api/products/{}", f.product))
        .json(&json!({"planId":plan["id"],"price":0.01}))
        .send(app)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    PlanSetup {
        plan: plan["id"].as_str().unwrap().into(),
        pricing: pricing["id"].as_str().unwrap().into(),
        role: role["id"].as_str().unwrap().into(),
    }
}
async fn buy(f: &Fixture, app: &Service, product: &str, provider: &str, extra: &str) -> Value {
    let mut res = TestClient::post(format!(
        "http://localhost/api/buy-product?id={product}&providerName={provider}&{extra}"
    ))
    .send(app)
    .await;
    let status = res.status_code;
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "tenant {}: {}",
        f.owner,
        res.take_string().await.unwrap_or_default()
    );
    res.take_json().await.unwrap()
}
async fn balance(f: &Fixture) -> f64 {
    sqlx::query_scalar("SELECT balance FROM users WHERE id=$1")
        .bind(&f.buyer.id)
        .fetch_one(&f.pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn priced_plan_balance_purchase_and_concurrent_renewals_extend_one_subscription() {
    use casdog::services::SubscriptionService;
    let f = Fixture::new(10).await;
    let admin = service(&f.pool, Some(f.admin.clone()));
    let buyer = service(&f.pool, Some(f.buyer.clone()));
    let plan = configure_plan(&f, &admin).await;
    sqlx::query("UPDATE providers SET type='Balance' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET balance=500 WHERE id=$1")
        .bind(&f.buyer.id)
        .execute(&f.pool)
        .await
        .unwrap();
    let first = buy(
        &f,
        &buyer,
        &f.product,
        &f.provider,
        "pricingName=public&planName=premium&period=monthly&paymentEnv=Web",
    )
    .await;
    assert_eq!(first["autoPaid"], true);
    assert_eq!(first["order"]["price"], 10.0); // The product's 0.01 cannot override a priced plan.
    let subscription = first["data2"]["benefit"]["subscriptionId"]
        .as_str()
        .unwrap();
    let (start, end): (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT start_date,end_date FROM subscriptions WHERE id=$1")
            .bind(subscription)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        end,
        start.checked_add_months(chrono::Months::new(1)).unwrap()
    );
    assert_eq!(
        SubscriptionService::active_role_names(&f.pool, &f.owner, "buyer")
            .await
            .unwrap(),
        vec![format!("{}/premium", f.owner)]
    );
    assert_eq!(
        SubscriptionService::active_roles_for_user_id(&f.pool, &f.buyer.id)
            .await
            .unwrap()[0]
            .id,
        plan.role
    );
    let yearly = buy(
        &f,
        &buyer,
        &f.product,
        &f.provider,
        "pricingName=public&planName=premium&period=yearly",
    )
    .await;
    assert_eq!(yearly["order"]["price"], 100.0);
    assert_eq!(yearly["data2"]["benefit"]["subscriptionId"], subscription);
    let after_year = end.checked_add_months(chrono::Months::new(12)).unwrap();
    let extra = "pricingName=public&planName=premium&period=monthly";
    let (a, b) = tokio::join!(
        buy(&f, &buyer, &f.product, &f.provider, extra),
        buy(&f, &buyer, &f.product, &f.provider, extra)
    );
    assert_eq!(a["data2"]["benefit"]["subscriptionId"], subscription);
    assert_eq!(b["data2"]["benefit"]["subscriptionId"], subscription);
    let actual: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT end_date FROM subscriptions WHERE id=$1")
            .bind(subscription)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        actual,
        after_year
            .checked_add_months(chrono::Months::new(1))
            .unwrap()
            .checked_add_months(chrono::Months::new(1))
            .unwrap()
    );
    assert_eq!(balance(&f).await, 370.0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM subscriptions WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM subscription_grants WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        4
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_roles WHERE user_id=$1")
            .bind(&f.buyer.id)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    PaymentFlowService::manual_notify_payment(
        &f.pool,
        first["data"]["id"].as_str().unwrap(),
        "Paid",
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(balance(&f).await, 370.0);
    assert_eq!(f.stock().await, (6, 4));
    for (table, id, column, disabled) in [
        ("roles", plan.role.as_str(), "is_enabled", false),
        ("plans", plan.plan.as_str(), "is_enabled", false),
        ("users", f.buyer.id.as_str(), "is_forbidden", true),
    ] {
        sqlx::query(&format!("UPDATE {table} SET {column}=$2 WHERE id=$1"))
            .bind(id)
            .bind(disabled)
            .execute(&f.pool)
            .await
            .unwrap();
        assert!(
            SubscriptionService::active_role_names(&f.pool, &f.owner, "buyer")
                .await
                .unwrap()
                .is_empty()
        );
        sqlx::query(&format!("UPDATE {table} SET {column}=$2 WHERE id=$1"))
            .bind(id)
            .bind(!disabled)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE subscriptions SET state='suspended' WHERE id=$1")
        .bind(subscription)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        SubscriptionService::active_role_names(&f.pool, &f.owner, "buyer")
            .await
            .unwrap()
            .is_empty()
    );
    let res = TestClient::post(format!(
        "http://localhost/api/buy-product?id={}&providerName={}&{extra}",
        f.product, f.provider
    ))
    .send(&buyer)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
    sqlx::query("UPDATE subscriptions SET state='active',end_date=clock_timestamp()-INTERVAL '1 second' WHERE id=$1").bind(subscription).execute(&f.pool).await.unwrap();
    assert!(
        SubscriptionService::active_role_names(&f.pool, &f.owner, "buyer")
            .await
            .unwrap()
            .is_empty()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn plan_checkout_rejects_wrong_tenant_binding_pricing_and_subcent_prices_before_charging() {
    let f = Fixture::new(5).await;
    let admin = service(&f.pool, Some(f.admin.clone()));
    let buyer = service(&f.pool, Some(f.buyer.clone()));
    let plan = configure_plan(&f, &admin).await;
    let foreign_owner = format!("foreign-{}", uuid::Uuid::new_v4());
    let foreign_plan = uuid::Uuid::new_v4().to_string();
    let foreign_role = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO roles(id,owner,name,display_name) VALUES($1,$2,'foreign','Foreign')")
        .bind(&foreign_role)
        .bind(&foreign_owner)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO plans(id,owner,name,display_name,price_per_month) VALUES($1,$2,'foreign','Foreign',1)").bind(&foreign_plan).bind(&foreign_owner).execute(&f.pool).await.unwrap();
    for (extra, status) in [
        ("pricingName=public".to_string(), StatusCode::BAD_REQUEST),
        (
            "pricingName=public&planName=premium&period=weekly".to_string(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "pricingName=public&planName=premium&customPrice=0.01".to_string(),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("pricingName=public&planName={foreign_plan}"),
            StatusCode::FORBIDDEN,
        ),
        (
            "pricingName=public&planName=premium&userName=admin".to_string(),
            StatusCode::FORBIDDEN,
        ),
        (String::new(), StatusCode::BAD_REQUEST),
    ] {
        let res = TestClient::post(format!(
            "http://localhost/api/buy-product?id={}&providerName={}&{extra}",
            f.product, f.provider
        ))
        .send(&buyer)
        .await;
        assert_eq!(res.status_code, Some(status), "{extra}");
    }
    for patch in [
        json!({"isEnabled":false}),
        json!({"isEnabled":true,"plans":[]}),
    ] {
        let res = TestClient::post(format!(
            "http://localhost/api/update-pricing?id={}",
            plan.pricing
        ))
        .json(&patch)
        .send(&admin)
        .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        let res=TestClient::post(format!("http://localhost/api/buy-product?id={}&providerName={}&pricingName=public&planName=premium",f.product,f.provider)).send(&buyer).await;
        assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
    }
    sqlx::query("UPDATE pricings SET plans='[\"premium\"]',is_enabled=true WHERE id=$1")
        .bind(&plan.pricing)
        .execute(&f.pool)
        .await
        .unwrap();
    for (price, role, status) in [
        (0.005, plan.role.as_str(), StatusCode::BAD_REQUEST),
        (10.0, foreign_role.as_str(), StatusCode::FORBIDDEN),
    ] {
        sqlx::query("UPDATE plans SET price_per_month=$2,role=$3 WHERE id=$1")
            .bind(&plan.plan)
            .bind(price)
            .bind(role)
            .execute(&f.pool)
            .await
            .unwrap();
        let res=TestClient::post(format!("http://localhost/api/buy-product?id={}&providerName={}&pricingName=public&planName=premium",f.product,f.provider)).send(&buyer).await;
        assert_eq!(res.status_code, Some(status));
    }
    sqlx::query("UPDATE plans SET price_per_month=10,role=$2 WHERE id=$1")
        .bind(&plan.plan)
        .bind(&plan.role)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO subscriptions(id,owner,name,user_id,plan_id,pricing_id,start_date,end_date,state) VALUES($1,$2,'lifetime',$3,$4,$5,clock_timestamp()-INTERVAL '1 day',NULL,'active')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(&f.buyer.id).bind(&plan.plan).bind(&plan.pricing).execute(&f.pool).await.unwrap();
    let mut res=TestClient::post(format!("http://localhost/api/buy-product?id={}&providerName={}&pricingName=public&planName=premium",f.product,f.provider)).send(&buyer).await;
    let status = res.status_code;
    let body = res.take_string().await.unwrap();
    assert_eq!(status, Some(StatusCode::BAD_REQUEST));
    assert!(body.contains("lifetime"), "{body}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM orders WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM payments WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(balance(&f).await, 100.0);
    assert_eq!(f.stock().await, (5, 0));
    f.cleanup().await;
    sqlx::query("DELETE FROM plans WHERE id=$1")
        .bind(foreign_plan)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM roles WHERE id=$1")
        .bind(foreign_role)
        .execute(&f.pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn plan_checkout_snapshots_role_and_price_and_only_paid_grants_access() {
    use casdog::services::SubscriptionService;
    let f = Fixture::new(5).await;
    let admin = service(&f.pool, Some(f.admin.clone()));
    let buyer = service(&f.pool, Some(f.buyer.clone()));
    let plan = configure_plan(&f, &admin).await;
    let extra = "pricingName=public&planName=premium";
    for state in ["Failed", "Canceled"] {
        let checkout = buy(&f, &buyer, &f.product, &f.provider, extra).await;
        let payment = checkout["data"]["id"].as_str().unwrap();
        PaymentFlowService::manual_notify_payment(&f.pool, payment, state, None, None)
            .await
            .unwrap();
        assert!(
            SubscriptionService::active_role_names(&f.pool, &f.owner, "buyer")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM subscriptions WHERE owner=$1")
                .bind(&f.owner)
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(balance(&f).await, 100.0);
    }
    let checkout = buy(&f, &buyer, &f.product, &f.provider, extra).await;
    let payment = checkout["data"]["id"].as_str().unwrap();
    assert!(
        SubscriptionService::active_role_names(&f.pool, &f.owner, "buyer")
            .await
            .unwrap()
            .is_empty()
    );
    let replacement = add_legacy(
        &admin,
        "role",
        json!({"owner":f.owner,"name":"replacement","displayName":"Replacement"}),
    )
    .await;
    sqlx::query("UPDATE plans SET price_per_month=999,role=$2 WHERE id=$1")
        .bind(&plan.plan)
        .bind(replacement["id"].as_str().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    let tamper = sqlx::query("UPDATE order_benefits SET amount_cents=1 WHERE order_id=$1")
        .bind(checkout["order"]["id"].as_str().unwrap())
        .execute(&f.pool)
        .await
        .unwrap_err();
    assert_eq!(
        tamper.as_database_error().unwrap().constraint(),
        Some("checkout_lifecycle")
    );
    sqlx::query(
        "UPDATE providers SET type='Stripe',client_secret='unused',metadata=$2 WHERE id=$1",
    )
    .bind(&f.provider)
    .bind(json!({"webhookSecret":"whsec_checkout_test"}).to_string())
    .execute(&f.pool)
    .await
    .unwrap();
    let body = stripe_event(payment, "checkout.session.completed", 1000, "usd");
    for _ in 0..2 {
        PaymentFlowService::notify_payment(
            &f.pool,
            payment,
            &stripe_headers(&body, chrono::Utc::now().timestamp()),
            &body,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        SubscriptionService::active_role_names(&f.pool, &f.owner, "buyer")
            .await
            .unwrap(),
        vec![format!("{}/premium", f.owner)]
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT role_id FROM subscription_grants WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        plan.role
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(balance(&f).await, 100.0);
    assert_eq!(f.stock().await, (4, 1));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn recharge_configuration_rejects_invalid_amounts_and_signed_payment_credits_original_user_once()
 {
    let f = Fixture::new(1).await;
    let admin = service(&f.pool, Some(f.admin.clone()));
    let buyer = service(&f.pool, Some(f.buyer.clone()));
    let mut created=TestClient::post("http://localhost/api/products")
        .json(&json!({"owner":f.owner,"name":"recharge","display_name":"Recharge","price":0,"quantity":0,"isRecharge":true,"rechargeOptions":[10,25.50],"disableCustomRecharge":true}))
        .send(&admin).await;
    assert_eq!(created.status_code, Some(StatusCode::OK));
    let product: Value = created.take_json().await.unwrap();
    let product = product["id"].as_str().unwrap();
    let mut get = TestClient::get(format!("http://localhost/api/products/{product}"))
        .send(&admin)
        .await;
    assert_eq!(
        get.take_json::<Value>().await.unwrap()["recharge_options"],
        json!([10.0, 25.5])
    );
    let balance_provider=add_legacy(&admin,"provider",json!({"owner":f.owner,"name":"balance","displayName":"Balance","category":"Payment","type":"Balance"})).await;
    for extra in [
        "customPrice=0",
        "customPrice=-1",
        "customPrice=0.005",
        "customPrice=NaN",
        "customPrice=30",
        "customPrice=10&couponCode=SAVE",
        "customPrice=10&userName=admin",
        "customPrice=10&paymentEnv=WechatBrowser",
    ] {
        let res = TestClient::post(format!(
            "http://localhost/api/buy-product?id={product}&providerName={}&{extra}",
            f.provider
        ))
        .send(&buyer)
        .await;
        assert!(
            matches!(
                res.status_code,
                Some(StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN)
            ),
            "{extra}"
        );
    }
    let res = TestClient::post(format!(
        "http://localhost/api/buy-product?id={product}&providerName={}&customPrice=10",
        balance_provider["id"].as_str().unwrap()
    ))
    .send(&buyer)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
    for state in ["Failed", "Canceled"] {
        let checkout = buy(&f, &buyer, product, &f.provider, "customPrice=10").await;
        PaymentFlowService::manual_notify_payment(
            &f.pool,
            checkout["data"]["id"].as_str().unwrap(),
            state,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(balance(&f).await, 100.0);
    }
    let one = buy(&f, &buyer, product, &f.provider, "customPrice=25.50").await;
    let two = buy(&f, &buyer, product, &f.provider, "customPrice=10").await;
    assert_eq!(balance(&f).await, 100.0);
    // The pending purchase pins the original UUID even after that account is
    // renamed and a new account takes its old username.
    sqlx::query("UPDATE users SET name='renamed-buyer' WHERE id=$1")
        .bind(&f.buyer.id)
        .execute(&f.pool)
        .await
        .unwrap();
    let new_user = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,balance) VALUES($1,$2,'buyer','New buyer','unused',0)").bind(&new_user).bind(&f.owner).execute(&f.pool).await.unwrap();
    let res=TestClient::put(format!("http://localhost/api/products/{product}")).json(&json!({"isRecharge":false,"price":999,"rechargeOptions":[],"disableCustomRecharge":false})).send(&admin).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let real = Service::new(casdog::routes::create_router())
        .hoop(salvo::affix_state::AffixList::new().inject(f.pool.clone()));
    let res = TestClient::delete(format!("http://localhost/api/products/{product}"))
        .add_header("Authorization", format!("Bearer {}", token(&f.admin)), true)
        .send(&real)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    sqlx::query(
        "UPDATE providers SET type='Stripe',client_secret='unused',metadata=$2 WHERE id=$1",
    )
    .bind(&f.provider)
    .bind(json!({"webhookSecret":"whsec_checkout_test"}).to_string())
    .execute(&f.pool)
    .await
    .unwrap();
    let p1 = one["data"]["id"].as_str().unwrap();
    let p2 = two["data"]["id"].as_str().unwrap();
    let body1 = stripe_event(p1, "checkout.session.completed", 2550, "usd");
    let body2 = stripe_event(p2, "checkout.session.completed", 1000, "usd");
    let h1 = stripe_headers(&body1, chrono::Utc::now().timestamp());
    let h2 = stripe_headers(&body2, chrono::Utc::now().timestamp());
    let (a, b) = tokio::join!(
        PaymentFlowService::notify_payment(&f.pool, p1, &h1, &body1),
        PaymentFlowService::notify_payment(&f.pool, p2, &h2, &body2)
    );
    a.unwrap();
    b.unwrap();
    PaymentFlowService::notify_payment(&f.pool, p1, &h1, &body1)
        .await
        .unwrap();
    assert_eq!(balance(&f).await, 135.5);
    assert_eq!(
        sqlx::query_scalar::<_, f64>("SELECT balance FROM users WHERE id=$1")
            .bind(&new_user)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0.0
    );
    let ledger: Vec<(String,i64)>=sqlx::query_as("SELECT category,COUNT(*) FROM transactions WHERE owner=$1 GROUP BY category ORDER BY category")
        .bind(&f.owner).fetch_all(&f.pool).await.unwrap();
    assert_eq!(ledger, vec![("purchase".into(), 2), ("recharge".into(), 2)]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM transactions WHERE owner=$1 AND product_id=$2"
        )
        .bind(&f.owner)
        .bind(product)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        4
    );
    let stock: (i32, i32) = sqlx::query_as("SELECT quantity,sold FROM products WHERE id=$1")
        .bind(product)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(stock, (0, 2));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and schema creation"]
async fn migration_backfills_aggregate_finite_and_unlimited_stock_preserving_terminal_history() {
    let pool = database().await;
    let (mut connection, schema) = isolated_checkout_schema(&pool).await;
    sqlx::raw_sql("INSERT INTO products(id,owner,name,quantity,sold) VALUES
        ('finite','tenant','finite',3,7),('unlimited','tenant','unlimited',-1,2),('foreign','other','finite',999,0);
        INSERT INTO payments(id,owner,name,amount,state) VALUES
        ('p1','tenant','p1',20,'created'),('p2','tenant','p2',20,'pending'),('p3','tenant','p3',20,'created'),
        ('paid','tenant','paid',20,'paid'),('deleted','tenant','deleted',20,'pending');
        INSERT INTO orders(id,owner,name,product_name,quantity,price,payment_id,state,is_deleted) VALUES
        ('o1','tenant','o1','finite',2,20,'p1','Created',false),
        ('o2','tenant','o2','finite',1,20,'p2','Processing',false),
        ('o3','tenant','o3','unlimited',4,20,'p3','Created',false),
        ('old-paid','tenant','old-paid','finite',99,20,'paid','Paid',false),
        ('old-deleted','tenant','old-deleted','finite',99,20,'deleted','Created',true);")
        .execute(&mut *connection).await.unwrap();
    sqlx::raw_sql(CHECKOUT_MIGRATION)
        .execute(&mut *connection)
        .await
        .unwrap();
    let products: Vec<(String, i32, i32)> =
        sqlx::query_as("SELECT id,quantity,sold FROM products ORDER BY id")
            .fetch_all(&mut *connection)
            .await
            .unwrap();
    assert_eq!(
        products,
        vec![
            ("finite".into(), 0, 7),
            ("foreign".into(), 999, 0),
            ("unlimited".into(), -1, 2)
        ]
    );
    let reservations: Vec<(String,i32,bool,String)>=sqlx::query_as("SELECT order_id,quantity,finite_stock,state FROM order_stock_reservations ORDER BY order_id")
        .fetch_all(&mut *connection).await.unwrap();
    assert_eq!(
        reservations,
        vec![
            ("o1".into(), 2, true, "reserved".into()),
            ("o2".into(), 1, true, "reserved".into()),
            ("o3".into(), 4, false, "reserved".into())
        ]
    );
    let history: Vec<(String, String)> =
        sqlx::query_as("SELECT id,state FROM orders WHERE id LIKE 'old-%' ORDER BY id")
            .fetch_all(&mut *connection)
            .await
            .unwrap();
    assert_eq!(
        history,
        vec![
            ("old-deleted".into(), "Created".into()),
            ("old-paid".into(), "Paid".into())
        ]
    );
    drop_checkout_schema(&mut connection, &schema).await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and schema creation"]
async fn migration_rejects_invalid_legacy_checkout_and_rolls_back_all_ddl_and_inventory() {
    let pool = database().await;
    for failure in [
        "stock",
        "quantity",
        "missing-product",
        "foreign-payment",
        "missing-payment",
        "deleted-payment",
        "subcent",
        "amount",
        "currency",
    ] {
        let (mut connection, schema) = isolated_checkout_schema(&pool).await;
        let stock = if failure == "stock" { 1 } else { 100 };
        sqlx::query("INSERT INTO products(id,owner,name,quantity) VALUES('ample','tenant','ample',5),('scarce','tenant','scarce',$1)")
            .bind(stock).execute(&mut *connection).await.unwrap();
        sqlx::raw_sql("INSERT INTO payments(id,owner,name,amount,state) VALUES('good','tenant','good',20,'created');
            INSERT INTO orders(id,owner,name,product_name,quantity,price,payment_id,state)
            VALUES('good','tenant','good','ample',2,20,'good','Created');")
            .execute(&mut *connection).await.unwrap();
        let price = if failure == "subcent" { 20.005 } else { 20.0 };
        if failure != "missing-payment" {
            sqlx::query("INSERT INTO payments(id,owner,name,amount,currency,state,is_deleted) VALUES('bad',$1,'bad',$2,$3,'created',$4)")
                .bind(if failure=="foreign-payment" {"foreign"} else {"tenant"})
                .bind(if failure=="amount" {19.0} else {price})
                .bind(if failure=="currency" {"EUR"} else {"USD"})
                .bind(failure=="deleted-payment").execute(&mut *connection).await.unwrap();
        }
        sqlx::query("INSERT INTO orders(id,owner,name,product_name,quantity,price,payment_id,state) VALUES('bad','tenant','bad',$1,$2,$3,'bad','Created')")
            .bind(if failure=="missing-product" {"missing"} else {"scarce"})
            .bind(if failure=="quantity" {0} else {2}).bind(price)
            .execute(&mut *connection).await.unwrap();
        let error = sqlx::raw_sql(CHECKOUT_MIGRATION)
            .execute(&mut *connection)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().constraint(),
            Some("checkout_migration"),
            "{failure}: {error}"
        );
        let inventory: Vec<(String, i32)> =
            sqlx::query_as("SELECT id,quantity FROM products ORDER BY id")
                .fetch_all(&mut *connection)
                .await
                .unwrap();
        assert_eq!(
            inventory,
            vec![("ample".into(), 5), ("scarce".into(), stock)],
            "{failure}"
        );
        let table: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(format!("{schema}.order_stock_reservations"))
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        assert!(table.is_none(), "{failure}: migration DDL must roll back");
        let functions: i64=sqlx::query_scalar("SELECT COUNT(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1")
            .bind(&schema).fetch_one(&mut *connection).await.unwrap();
        assert_eq!(
            functions, 0,
            "{failure}: migration functions must roll back"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM orders WHERE state='Created'")
                .fetch_one(&mut *connection)
                .await
                .unwrap(),
            2,
            "{failure}"
        );
        drop_checkout_schema(&mut connection, &schema).await;
    }
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn plan_and_recharge_flow_work_with_one_database_connection() {
    let f = Fixture::new(2).await;
    let single = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let admin = service(&single, Some(f.admin.clone()));
    let buyer = service(&single, Some(f.buyer.clone()));
    configure_plan(&f, &admin).await;
    sqlx::query("UPDATE providers SET type='Balance' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        buy(
            &f,
            &buyer,
            &f.product,
            &f.provider,
            "pricingName=public&planName=premium",
        ),
    )
    .await
    .expect("single-connection plan checkout deadlocked");
    let mut connection = single.acquire().await.unwrap();
    assert_eq!(
        casdog::services::SubscriptionService::active_role_names_conn(
            &mut connection,
            &f.owner,
            "buyer"
        )
        .await
        .unwrap(),
        vec![format!("{}/premium", f.owner)]
    );
    drop(connection);
    let mut res=TestClient::post("http://localhost/api/products")
        .json(&json!({"owner":f.owner,"name":"recharge","display_name":"Recharge","isRecharge":true,"quantity":0}))
        .send(&admin).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let product: Value = res.take_json().await.unwrap();
    sqlx::query("UPDATE providers SET type='Dummy' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    let checkout = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        buy(
            &f,
            &buyer,
            product["id"].as_str().unwrap(),
            &f.provider,
            "customPrice=10",
        ),
    )
    .await
    .expect("single-connection recharge checkout deadlocked");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        PaymentFlowService::manual_notify_payment(
            &single,
            checkout["data"]["id"].as_str().unwrap(),
            "Paid",
            None,
            None,
        ),
    )
    .await
    .expect("single-connection recharge settlement deadlocked")
    .unwrap();
    assert_eq!(balance(&f).await, 100.0);
    f.cleanup().await;
    single.close().await;
}

async fn assert_paid_access(
    pool: &PgPool,
    user_id: &str,
    app_id: &str,
    role_id: &str,
    subject: &str,
    object: &str,
    roles: &casdog::services::RoleService,
    casbin: &casdog::services::CasbinService,
    allowed: bool,
) {
    let mut connection = pool.acquire().await.unwrap();
    let login = casdog::services::CheckService::check_login_permission_conn(
        &mut connection,
        user_id,
        app_id,
    )
    .await;
    assert_eq!(login.is_ok(), allowed, "application login: {login:?}");
    drop(connection);
    let memberships = roles.get_user_roles(user_id).await.unwrap();
    assert_eq!(
        memberships.iter().any(|r| r.id == role_id),
        allowed,
        "role membership"
    );
    assert_eq!(
        casbin
            .check_permission(subject, object, "read")
            .await
            .unwrap(),
        allowed,
        "Casbin permission"
    );
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn paid_plan_authorizes_application_diesel_and_casbin_and_revokes_without_cached_grouping() {
    use casdog::models::{EnforceRequest, EnforceRequestItem, PolicyRequest};
    use casdog::services::{CasbinService, RoleService};
    let f = Fixture::new(2).await;
    let admin = service(&f.pool, Some(f.admin.clone()));
    let buyer = service(&f.pool, Some(f.buyer.clone()));
    let plan = configure_plan(&f, &admin).await;
    let app = uuid::Uuid::new_v4().to_string();
    let permission = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris) VALUES($1,$2,'premium-app','Premium app',$2,$1,'unused','[]')")
        .bind(&app).bind(&f.owner).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO permissions(id,owner,name,display_name,resource_type,resources,actions,effect) VALUES($1,$2,'premium-login','Premium login','Application',$3,'login','allow')")
        .bind(&permission).bind(&f.owner).bind(&app).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO role_permissions(id,role_id,permission_id) VALUES($1,$2,$3)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&plan.role)
        .bind(&permission)
        .execute(&f.pool)
        .await
        .unwrap();
    let diesel = casdog::diesel_pool::create_diesel_pool(
        &std::env::var("CASDOG_TEST_DATABASE_URL").unwrap(),
    )
    .await
    .unwrap();
    let roles = RoleService::new(diesel);
    let casbin = CasbinService::with_pool(f.pool.clone()).await.unwrap();
    let object = format!("paid-{}", uuid::Uuid::new_v4());
    let subject = format!("{}/buyer", f.owner);
    let qualified_role = format!("{}/premium", f.owner);
    let policy = |sub: &str, obj: &str, effect: &str| PolicyRequest {
        ptype: "p".into(),
        v0: sub.into(),
        v1: obj.into(),
        v2: effect.into(),
        v3: None,
        v4: None,
    };
    casbin
        .add_policy(policy(&qualified_role, &object, "read"))
        .await
        .unwrap();
    // Check with a held single-connection pool slot to ensure the login decision
    // never acquires a second SQLx connection internally.
    let single = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    assert_paid_access(
        &single,
        &f.buyer.id,
        &app,
        &plan.role,
        &subject,
        &object,
        &roles,
        &casbin,
        false,
    )
    .await;
    sqlx::query("UPDATE providers SET type='Balance' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    let bought = buy(
        &f,
        &buyer,
        &f.product,
        &f.provider,
        "pricingName=public&planName=premium",
    )
    .await;
    assert_eq!(bought["autoPaid"], true);
    let subscription = bought["data2"]["benefit"]["subscriptionId"]
        .as_str()
        .unwrap();
    assert_paid_access(
        &single,
        &f.buyer.id,
        &app,
        &plan.role,
        &subject,
        &object,
        &roles,
        &casbin,
        true,
    )
    .await;
    assert!(
        casbin
            .enforce(EnforceRequest {
                sub: subject.clone(),
                obj: object.clone(),
                act: "read".into()
            })
            .await
            .unwrap()
            .allowed
    );
    assert_eq!(
        casbin.get_roles_for_user(&subject).await.unwrap(),
        vec![qualified_role.clone()]
    );
    // Another application instance can revoke or restore its policy. A valid
    // subscription must not keep a stale allow policy cached in this instance.
    let second_instance = CasbinService::with_pool(f.pool.clone()).await.unwrap();
    assert!(
        second_instance
            .remove_policy(policy(&qualified_role, &object, "read"))
            .await
            .unwrap()
    );
    assert!(
        !casbin
            .check_permission(&subject, &object, "read")
            .await
            .unwrap()
    );
    assert!(
        !casbin
            .get_policies()
            .await
            .unwrap()
            .data
            .iter()
            .any(|p| p.ptype == "p" && p.v0 == qualified_role && p.v1 == object && p.v2 == "read")
    );
    assert!(
        second_instance
            .add_policy(policy(&qualified_role, &object, "read"))
            .await
            .unwrap()
    );
    assert!(
        casbin
            .check_permission(&subject, &object, "read")
            .await
            .unwrap()
    );
    assert!(
        casbin
            .get_policies()
            .await
            .unwrap()
            .data
            .iter()
            .any(|p| p.ptype == "p" && p.v0 == qualified_role && p.v1 == object && p.v2 == "read")
    );
    // Another tenant buys its own role with the same unqualified name. Its valid
    // paid membership must not match our qualified role policy.
    let foreign = Fixture::new(1).await;
    let foreign_admin = service(&foreign.pool, Some(foreign.admin.clone()));
    let foreign_buyer = service(&foreign.pool, Some(foreign.buyer.clone()));
    let foreign_plan = configure_plan(&foreign, &foreign_admin).await;
    sqlx::query("UPDATE providers SET type='Balance' WHERE id=$1")
        .bind(&foreign.provider)
        .execute(&foreign.pool)
        .await
        .unwrap();
    buy(
        &foreign,
        &foreign_buyer,
        &foreign.product,
        &foreign.provider,
        "pricingName=public&planName=premium",
    )
    .await;
    let foreign_subject = format!("{}/buyer", foreign.owner);
    assert!(
        !casbin
            .check_permission(&foreign_subject, &object, "read")
            .await
            .unwrap()
    );
    let foreign_memberships = roles.get_user_roles(&foreign.buyer.id).await.unwrap();
    assert_eq!(foreign_memberships.len(), 1);
    assert_eq!(foreign_memberships[0].id, foreign_plan.role);
    let batch = casbin
        .batch_enforce(vec![
            EnforceRequestItem {
                sub: subject.clone(),
                obj: object.clone(),
                act: "read".into(),
            },
            EnforceRequestItem {
                sub: foreign_subject.clone(),
                obj: object.clone(),
                act: "read".into(),
            },
        ])
        .await
        .unwrap();
    assert!(batch.results[0].allowed);
    assert!(!batch.results[1].allowed);
    let mut connection = single.acquire().await.unwrap();
    assert!(
        casdog::services::CheckService::check_login_permission_conn(
            &mut connection,
            &foreign.buyer.id,
            &app
        )
        .await
        .is_err()
    );
    drop(connection);
    // A user's explicit deny and a paid role's allow must be evaluated in the
    // same model invocation. OR-ing separate subject decisions would bypass deny.
    let model = casbin::DefaultModel::from_str(
        r#"
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, eft
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
[matchers]
m = (g(r.sub,p.sub) || r.sub == p.sub) && r.obj == p.obj && r.act == "read"
"#,
    )
    .await
    .unwrap();
    let deny = CasbinService::with_model_and_pool(model, f.pool.clone())
        .await
        .unwrap();
    let deny_object = format!("deny-{}", uuid::Uuid::new_v4());
    deny.add_policy(policy(&qualified_role, &deny_object, "allow"))
        .await
        .unwrap();
    deny.add_policy(policy(&subject, &deny_object, "deny"))
        .await
        .unwrap();
    assert!(
        !deny
            .check_permission(&subject, &deny_object, "read")
            .await
            .unwrap()
    );
    let (one, two, three) = tokio::join!(
        casbin.check_permission(&subject, &object, "read"),
        casbin.check_permission(&foreign_subject, &object, "read"),
        deny.check_permission(&subject, &deny_object, "read")
    );
    assert!(one.unwrap());
    assert!(!two.unwrap());
    assert!(!three.unwrap());
    for state in ["role", "plan", "suspended", "end-date", "grant-expired"] {
        let dates: (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) =
            sqlx::query_as("SELECT starts_at,ends_at FROM subscription_grants WHERE order_id=$1")
                .bind(bought["order"]["id"].as_str().unwrap())
                .fetch_one(&f.pool)
                .await
                .unwrap();
        match state {
            "role" => {
                sqlx::query("UPDATE roles SET is_enabled=false WHERE id=$1")
                    .bind(&plan.role)
                    .execute(&f.pool)
                    .await
                    .unwrap();
            }
            "plan" => {
                sqlx::query("UPDATE plans SET is_enabled=false WHERE id=$1")
                    .bind(&plan.plan)
                    .execute(&f.pool)
                    .await
                    .unwrap();
            }
            "suspended" => {
                sqlx::query("UPDATE subscriptions SET state='suspended' WHERE id=$1")
                    .bind(subscription)
                    .execute(&f.pool)
                    .await
                    .unwrap();
            }
            "end-date" => {
                sqlx::query("UPDATE subscriptions SET end_date=clock_timestamp()-INTERVAL '1 second' WHERE id=$1").bind(subscription).execute(&f.pool).await.unwrap();
            }
            _ => {
                sqlx::query("UPDATE subscription_grants SET starts_at=clock_timestamp()-INTERVAL '2 seconds',ends_at=clock_timestamp()-INTERVAL '1 second' WHERE order_id=$1")
                .bind(bought["order"]["id"].as_str().unwrap()).execute(&f.pool).await.unwrap();
            }
        }
        assert_paid_access(
            &single,
            &f.buyer.id,
            &app,
            &plan.role,
            &subject,
            &object,
            &roles,
            &casbin,
            false,
        )
        .await;
        assert!(
            casbin
                .get_roles_for_user(&subject)
                .await
                .unwrap()
                .is_empty(),
            "{state}"
        );
        sqlx::query("UPDATE roles SET is_enabled=true WHERE id=$1")
            .bind(&plan.role)
            .execute(&f.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE plans SET is_enabled=true WHERE id=$1")
            .bind(&plan.plan)
            .execute(&f.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE subscriptions SET state='active',end_date=$2 WHERE id=$1")
            .bind(subscription)
            .bind(dates.1)
            .execute(&f.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE subscription_grants SET starts_at=$2,ends_at=$3 WHERE order_id=$1")
            .bind(bought["order"]["id"].as_str().unwrap())
            .bind(dates.0)
            .bind(dates.1)
            .execute(&f.pool)
            .await
            .unwrap();
        assert_paid_access(
            &single,
            &f.buyer.id,
            &app,
            &plan.role,
            &subject,
            &object,
            &roles,
            &casbin,
            true,
        )
        .await;
    }
    for current in [&casbin, &deny, &second_instance] {
        assert!(
            !current
                .get_policies()
                .await
                .unwrap()
                .data
                .iter()
                .any(|p| p.ptype == "g" && (p.v0 == subject || p.v0 == foreign_subject))
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_roles WHERE user_id=$1 OR user_id=$2"
        )
        .bind(&f.buyer.id)
        .bind(&foreign.buyer.id)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM casbin_rule WHERE ptype='g' AND (v0=$1 OR v0=$2)"
        )
        .bind(&subject)
        .bind(&foreign_subject)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        0
    );
    casbin
        .remove_policy(policy(&qualified_role, &object, "read"))
        .await
        .unwrap();
    deny.remove_policy(policy(&qualified_role, &deny_object, "allow"))
        .await
        .unwrap();
    deny.remove_policy(policy(&subject, &deny_object, "deny"))
        .await
        .unwrap();
    sqlx::query("DELETE FROM permissions WHERE id=$1")
        .bind(permission)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM applications WHERE id=$1")
        .bind(app)
        .execute(&f.pool)
        .await
        .unwrap();
    foreign.cleanup().await;
    f.cleanup().await;
    single.close().await;
}

#[tokio::test]
async fn stripe_checkout_http_and_signed_notifications_use_charge_currency_units() {
    use casdog::services::providers::{
        payment_provider::{PayRequest, PaymentProvider},
        stripe_payment::StripePaymentProvider,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cases: Vec<(&str, f64, i32, i64)> = vec![
        ("USD", 10.01, 3, 1001),
        ("ISK", 5.0, 1, 500),
        ("UGX", 5.0, 1, 500),
        ("HUF", 1.23, 1, 123),
        ("TWD", 1.23, 1, 123),
    ];
    for currency in [
        "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "VND", "VUV", "XAF",
        "XOF", "XPF",
    ] {
        cases.push((currency, 500.0, 1, 500));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let expected = cases.clone();
    let server = tokio::spawn(async move {
        for (index, (currency, _, quantity, minor)) in expected.into_iter().enumerate() {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                assert!(request.len() < 65536);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            assert!(headers.starts_with("post /v1/checkout/sessions http/1.1"));
            assert!(headers.contains("authorization: bearer sk_transport_test"));
            assert!(headers.contains(&format!(
                "idempotency-key: currency_{}_{index}",
                currency.to_ascii_lowercase()
            )));
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:").map(str::trim))
                .unwrap()
                .parse::<usize>()
                .unwrap();
            while request.len() < header_end + length {
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
            }
            let body = std::str::from_utf8(&request[header_end..header_end + length]).unwrap();
            let parsed = reqwest::Url::parse(&format!("http://transport.test/?{body}")).unwrap();
            let form: HashMap<String, String> = parsed
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
            assert_eq!(
                form["line_items[0][price_data][unit_amount]"],
                minor.to_string(),
                "{currency}"
            );
            assert_eq!(
                form["line_items[0][price_data][currency]"],
                currency.to_ascii_lowercase()
            );
            assert_eq!(form["line_items[0][quantity]"], quantity.to_string());
            let response=json!({"id":format!("cs_currency_{index}"),"url":"https://checkout.stripe.com/c/pay/cs_transport_fixture","invoice":null}).to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).as_bytes()).await.unwrap();
        }
    });
    let provider = StripePaymentProvider::new(
        "sk_transport_test".into(),
        Some(json!({"webhookSecret":"whsec_checkout_test"}).to_string()),
    )
    .with_api_base(&endpoint)
    .unwrap();
    for (index, (currency, price, quantity, minor)) in cases.into_iter().enumerate() {
        let request = PayRequest {
            product_name: "money".into(),
            product_display_name: "Money".into(),
            provider_name: "stripe".into(),
            price,
            currency: currency.into(),
            quantity,
            return_url: "https://merchant.test/return".into(),
            order_id: format!("currency_{}_{index}", currency.to_ascii_lowercase()),
            payer_name: None,
            payer_email: None,
        };
        let paid = tokio::time::timeout(std::time::Duration::from_secs(5), provider.pay(&request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paid.order_id, format!("cs_currency_{index}"));
        let event = stripe_event(
            &paid.order_id,
            "checkout.session.completed",
            minor * quantity as i64,
            &currency.to_ascii_lowercase(),
        );
        let notification = provider
            .notify(
                &event,
                &stripe_headers(&event, chrono::Utc::now().timestamp()),
                Some(&paid.order_id),
            )
            .await
            .unwrap();
        assert!(
            (notification.amount.unwrap() - price * quantity as f64).abs() < 0.000001,
            "{currency}"
        );
        assert_eq!(notification.currency.as_deref(), Some(currency));
    }
    server.await.unwrap();
}

#[tokio::test]
async fn stripe_rejects_fractional_zero_units_and_unsupported_three_decimal_currency_before_http() {
    use casdog::services::providers::{
        payment_provider::{PayRequest, PaymentProvider},
        stripe_payment::StripePaymentProvider,
    };
    let provider = StripePaymentProvider::new(
        "unused".into(),
        Some(json!({"webhookSecret":"whsec_checkout_test"}).to_string()),
    )
    .with_api_base("http://127.0.0.1:9/v1")
    .unwrap();
    for (currency, price) in [
        ("JPY", 1.5),
        ("KRW", 0.01),
        ("ISK", 1.01),
        ("UGX", 1.5),
        ("BHD", 1.0),
        ("KWD", 1.001),
        ("USD", 0.005),
    ] {
        let request = PayRequest {
            product_name: "money".into(),
            product_display_name: "Money".into(),
            provider_name: "stripe".into(),
            price,
            currency: currency.into(),
            quantity: 1,
            return_url: "https://merchant.test/return".into(),
            order_id: "invalid_units".into(),
            payer_name: None,
            payer_email: None,
        };
        assert!(
            matches!(
                provider.pay(&request).await,
                Err(casdog::error::AppError::Validation(_))
            ),
            "{currency}: invalid units must fail before transport"
        );
    }
    for (currency, minor) in [("isk", 501), ("ugx", 501), ("jpy", -1), ("bhd", 1000)] {
        let event = stripe_event("cs_invalid", "checkout.session.completed", minor, currency);
        assert!(
            provider
                .notify(
                    &event,
                    &stripe_headers(&event, chrono::Utc::now().timestamp()),
                    Some("cs_invalid")
                )
                .await
                .is_err(),
            "{currency}"
        );
    }
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn zero_decimal_and_special_stripe_recharge_notifications_credit_exact_major_units() {
    for (currency, minor, incorrect) in [
        ("JPY", 500, 50000),
        ("KRW", 500, 50000),
        ("ISK", 50000, 500),
        ("UGX", 50000, 500),
    ] {
        let f = Fixture::new(1).await;
        let admin = service(&f.pool, Some(f.admin.clone()));
        let buyer = service(&f.pool, Some(f.buyer.clone()));
        sqlx::query("UPDATE users SET currency=$2,balance_currency=$2 WHERE id=$1")
            .bind(&f.buyer.id)
            .bind(currency)
            .execute(&f.pool)
            .await
            .unwrap();
        let mut res=TestClient::post("http://localhost/api/products").json(&json!({"owner":f.owner,"name":"recharge","display_name":"Recharge","currency":currency,"isRecharge":true,"quantity":0})).send(&admin).await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        let product: Value = res.take_json().await.unwrap();
        let checkout = buy(
            &f,
            &buyer,
            product["id"].as_str().unwrap(),
            &f.provider,
            "customPrice=500",
        )
        .await;
        let payment = checkout["data"]["id"].as_str().unwrap();
        sqlx::query(
            "UPDATE providers SET type='Stripe',client_secret='unused',metadata=$2 WHERE id=$1",
        )
        .bind(&f.provider)
        .bind(json!({"webhookSecret":"whsec_checkout_test"}).to_string())
        .execute(&f.pool)
        .await
        .unwrap();
        let wrong = stripe_event(
            payment,
            "checkout.session.completed",
            incorrect,
            &currency.to_ascii_lowercase(),
        );
        assert!(
            PaymentFlowService::notify_payment(
                &f.pool,
                payment,
                &stripe_headers(&wrong, chrono::Utc::now().timestamp()),
                &wrong
            )
            .await
            .is_err()
        );
        assert_eq!(balance(&f).await, 100.0);
        let valid = stripe_event(
            payment,
            "checkout.session.completed",
            minor,
            &currency.to_ascii_lowercase(),
        );
        for _ in 0..2 {
            PaymentFlowService::notify_payment(
                &f.pool,
                payment,
                &stripe_headers(&valid, chrono::Utc::now().timestamp()),
                &valid,
            )
            .await
            .unwrap();
        }
        assert_eq!(balance(&f).await, 600.0, "{currency}");
        assert_eq!(
            sqlx::query_scalar::<_, f64>(
                "SELECT amount FROM transactions WHERE owner=$1 AND category='recharge'"
            )
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            500.0
        );
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn catalog_soft_delete_retains_pending_paid_purchase_history_and_settles_snapshots() {
    for removed in ["products", "plans", "pricings"] {
        let f = Fixture::new(2).await;
        let admin = service(&f.pool, Some(f.admin.clone()));
        let buyer = service(&f.pool, Some(f.buyer.clone()));
        let plan = configure_plan(&f, &admin).await;
        let checkout = buy(
            &f,
            &buyer,
            &f.product,
            &f.provider,
            "pricingName=public&planName=premium",
        )
        .await;
        let payment = checkout["data"]["id"].as_str().unwrap();
        let order = checkout["order"]["id"].as_str().unwrap();
        let id = match removed {
            "products" => &f.product,
            "plans" => &plan.plan,
            _ => &plan.pricing,
        };
        let real = Service::new(casdog::routes::create_router())
            .hoop(salvo::affix_state::AffixList::new().inject(f.pool.clone()));
        let response = TestClient::delete(format!("http://localhost/api/{removed}/{id}"))
            .add_header("Authorization", format!("Bearer {}", token(&f.admin)), true)
            .send(&real)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK), "{removed}");
        let deleted: bool =
            sqlx::query_scalar(&format!("SELECT is_deleted FROM {removed} WHERE id=$1"))
                .bind(id)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert!(deleted);
        let res=TestClient::post(format!("http://localhost/api/buy-product?id={}&providerName={}&pricingName=public&planName=premium",f.product,f.provider)).send(&buyer).await;
        assert_eq!(res.status_code, Some(StatusCode::NOT_FOUND));
        sqlx::query(
            "UPDATE providers SET type='Stripe',client_secret='unused',metadata=$2 WHERE id=$1",
        )
        .bind(&f.provider)
        .bind(json!({"webhookSecret":"whsec_checkout_test"}).to_string())
        .execute(&f.pool)
        .await
        .unwrap();
        let body = stripe_event(payment, "checkout.session.completed", 1000, "usd");
        PaymentFlowService::notify_payment(
            &f.pool,
            payment,
            &stripe_headers(&body, chrono::Utc::now().timestamp()),
            &body,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT state FROM orders WHERE id=$1")
                .bind(order)
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            "Paid"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT product_id FROM transactions WHERE owner=$1")
                .bind(&f.owner)
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            f.product
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM order_benefits WHERE order_id=$1 AND fulfilled_at IS NOT NULL"
            )
            .bind(order)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM subscription_grants WHERE order_id=$1"
            )
            .bind(order)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            1
        );
        let active =
            casdog::services::SubscriptionService::active_role_names(&f.pool, &f.owner, "buyer")
                .await
                .unwrap();
        if removed == "plans" {
            assert!(active.is_empty());
        } else {
            assert_eq!(active, vec![format!("{}/premium", f.owner)]);
        }
        // Archiving the remaining catalog entries after payment also succeeds;
        // every order, benefit, SKU and ledger reference remains available.
        for (kind, id) in [
            ("products", &f.product),
            ("plans", &plan.plan),
            ("pricings", &plan.pricing),
        ] {
            if kind == removed {
                continue;
            }
            let res = TestClient::delete(format!("http://localhost/api/{kind}/{id}"))
                .add_header("Authorization", format!("Bearer {}", token(&f.admin)), true)
                .send(&real)
                .await;
            assert_eq!(res.status_code, Some(StatusCode::OK), "paid {kind}");
        }
        assert_eq!(balance(&f).await, 100.0);
        assert_eq!(f.stock().await, (1, 1));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions WHERE owner=$1")
                .bind(&f.owner)
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            1
        );
        f.cleanup().await;
    }
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
struct RecoveryGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    once: std::sync::atomic::AtomicBool,
}
struct RecoveryDriver {
    inner: std::sync::Arc<dyn casdog::services::providers::payment_provider::PaymentProvider>,
    before: std::sync::atomic::AtomicBool,
    after: std::sync::atomic::AtomicBool,
    gate: Option<std::sync::Arc<RecoveryGate>>,
}
#[async_trait::async_trait]
impl casdog::services::providers::payment_provider::PaymentProvider for RecoveryDriver {
    async fn pay(
        &self,
        r: &casdog::services::providers::payment_provider::PayRequest,
    ) -> casdog::error::AppResult<casdog::services::providers::payment_provider::PayResponse> {
        if self.before.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(casdog::error::AppError::Internal(
                "Simulated crash before request".into(),
            ));
        }
        let response = self.inner.pay(r).await?;
        if self.after.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(casdog::error::AppError::Internal(
                "Simulated lost create response".into(),
            ));
        }
        Ok(response)
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
        if let Some(gate) = &self.gate {
            if gate.once.swap(false, std::sync::atomic::Ordering::SeqCst) {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
        }
        self.inner.query_payment(id, local).await
    }
    async fn capture_payment(
        &self,
        id: &str,
        local: &str,
        key: &str,
    ) -> casdog::error::AppResult<casdog::services::providers::payment_provider::RemotePayment>
    {
        self.inner.capture_payment(id, local, key).await
    }
    async fn cancel_payment(
        &self,
        id: &str,
        local: &str,
        key: &str,
    ) -> casdog::error::AppResult<casdog::services::providers::payment_provider::RemotePayment>
    {
        self.inner.cancel_payment(id, local, key).await
    }
}

async fn configure_recovery_provider(f: &Fixture, paypal: bool) {
    sqlx::query("UPDATE providers SET type=$2,client_id=$3,client_secret=$4,host=$5 WHERE id=$1")
        .bind(&f.provider)
        .bind(if paypal { "PayPal" } else { "Stripe" })
        .bind(if paypal { Some("client") } else { None::<&str> })
        .bind(if paypal { "secret" } else { "sk_gateway" })
        .bind(if paypal {
            Some("sandbox")
        } else {
            None::<&str>
        })
        .execute(&f.pool)
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn durable_checkout_recovery_survives_crash_and_preserves_exact_idempotent_request() {
    use std::sync::{Arc, atomic::AtomicBool};
    for before in [true, false] {
        let f = Fixture::new(1).await;
        let gateway = RecoveryGateway::new().await;
        configure_recovery_provider(&f, false).await;
        let order = f.order(1).await;
        sqlx::query("UPDATE orders SET product_display_name='Original title',return_url='https://merchant.example.test/payment' WHERE id=$1").bind(&order).execute(&f.pool).await.unwrap();
        sqlx::query("UPDATE users SET email='original@example.test' WHERE id=$1")
            .bind(&f.buyer.id)
            .execute(&f.pool)
            .await
            .unwrap();
        let driver = RecoveryDriver {
            inner: Arc::new(gateway.stripe()),
            before: AtomicBool::new(before),
            after: AtomicBool::new(!before),
            gate: None,
        };
        assert!(
            PaymentFlowService::start_order_payment_using(
                &f.pool,
                &order,
                Some(&f.provider),
                &f.owner,
                "buyer",
                false,
                None,
                &driver
            )
            .await
            .is_err()
        );
        let payment: String = sqlx::query_scalar("SELECT payment_id FROM orders WHERE id=$1")
            .bind(&order)
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(f.stock().await, (0, 0));
        assert!(
            PaymentFlowService::cancel_order(&f.pool, &order, &f.owner, "buyer", false)
                .await
                .is_err()
        );
        let deadline: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "SELECT create_retry_until FROM payment_remote_operations WHERE payment_id=$1",
        )
        .bind(&payment)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE payment_remote_operations SET lease_token='crashed-process',lease_kind='create',lease_until=clock_timestamp()+INTERVAL '45 seconds' WHERE payment_id=$1").bind(&payment).execute(&f.pool).await.unwrap();
        let native = gateway.stripe();
        let busy = PaymentFlowService::start_order_payment_using(
            &f.pool, &order, None, &f.owner, "buyer", false, None, &native,
        )
        .await
        .unwrap();
        assert_eq!(busy.payment.id, payment);
        assert_eq!(busy.attach_info["retryAfter"], 45);
        assert!(busy.pay_url.is_none());
        sqlx::query("UPDATE payment_remote_operations SET lease_until=clock_timestamp()-INTERVAL '1 second',create_retry_until=clock_timestamp()-INTERVAL '1 second' WHERE payment_id=$1").bind(&payment).execute(&f.pool).await.unwrap();
        assert!(
            PaymentFlowService::start_order_payment_using(
                &f.pool, &order, None, &f.owner, "buyer", false, None, &native
            )
            .await
            .is_err()
        );
        sqlx::query(
            "UPDATE payment_remote_operations SET create_retry_until=$2 WHERE payment_id=$1",
        )
        .bind(&payment)
        .bind(deadline)
        .execute(&f.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE providers SET client_secret='rotated-to-another-account' WHERE id=$1")
            .bind(&f.provider)
            .execute(&f.pool)
            .await
            .unwrap();
        assert!(
            PaymentFlowService::start_order_payment_using(
                &f.pool, &order, None, &f.owner, "buyer", false, None, &native
            )
            .await
            .is_err()
        );
        sqlx::query("UPDATE providers SET client_secret='sk_gateway' WHERE id=$1")
            .bind(&f.provider)
            .execute(&f.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE orders SET product_display_name='Changed after crash',return_url='https://changed.example.test/' WHERE id=$1").bind(&order).execute(&f.pool).await.unwrap();
        sqlx::query("UPDATE users SET email='changed@example.test' WHERE id=$1")
            .bind(&f.buyer.id)
            .execute(&f.pool)
            .await
            .unwrap();
        // A rejected replay cannot release stock: an earlier request might have
        // succeeded even though its response never reached this application.
        gateway.state.lock().unwrap().reject_create_once = true;
        assert!(
            PaymentFlowService::start_order_payment_using(
                &f.pool, &order, None, &f.owner, "buyer", false, None, &native
            )
            .await
            .is_err()
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT state FROM payments WHERE id=$1")
                .bind(&payment)
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            "created"
        );
        assert_eq!(f.stock().await, (0, 0));
        let restored = PaymentFlowService::start_order_payment_using(
            &f.pool, &order, None, &f.owner, "buyer", false, None, &native,
        )
        .await
        .unwrap();
        assert_eq!(restored.payment.id, payment);
        assert!(
            restored
                .pay_url
                .unwrap()
                .starts_with("https://checkout.stripe.com/")
        );
        {
            let state = gateway.state.lock().unwrap();
            assert_eq!(state.creates, 1);
            assert!(state.create_keys.iter().all(|id| id == &payment));
            assert!(
                state
                    .create_bodies
                    .iter()
                    .all(|body| body == &state.create_bodies[0])
            );
            let form = String::from_utf8_lossy(&state.create_bodies[0]);
            assert!(form.contains("Original+title"));
            assert!(form.contains("original%40example.test"));
        }
        gateway.status(&payment, "complete");
        for invalid in ["amount", "currency", "reference"] {
            {
                let mut state = gateway.state.lock().unwrap();
                state.wrong_amount = invalid == "amount";
                state.wrong_currency = invalid == "currency";
                state.wrong_reference = invalid == "reference";
            }
            assert!(
                PaymentFlowService::reconcile_order_payment_using(
                    &f.pool, &order, &f.owner, "buyer", false, &native
                )
                .await
                .is_err()
            );
            assert_eq!(f.stock().await, (0, 0));
        }
        {
            let mut state = gateway.state.lock().unwrap();
            state.wrong_amount = false;
            state.wrong_currency = false;
            state.wrong_reference = false;
        }
        let paid = PaymentFlowService::reconcile_order_payment_using(
            &f.pool, &order, &f.owner, "buyer", false, &native,
        )
        .await
        .unwrap();
        assert!(paid.auto_paid);
        PaymentFlowService::reconcile_order_payment_using(
            &f.pool, &order, &f.owner, "buyer", false, &native,
        )
        .await
        .unwrap();
        assert_eq!(f.stock().await, (0, 1));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM payments WHERE owner=$1")
                .bind(&f.owner)
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions WHERE owner=$1")
                .bind(&f.owner)
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            1
        );
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn paypal_capture_retries_reuse_persistent_key_and_reconcile_a_lost_success_response() {
    let f = Fixture::new(1).await;
    let gateway = RecoveryGateway::new().await;
    configure_recovery_provider(&f, true).await;
    let driver = gateway.paypal();
    let order = f.order(1).await;
    let checkout = PaymentFlowService::start_order_payment_using(
        &f.pool,
        &order,
        Some(&f.provider),
        &f.owner,
        "buyer",
        false,
        None,
        &driver,
    )
    .await
    .unwrap();
    assert!(
        checkout
            .pay_url
            .unwrap()
            .starts_with("https://www.sandbox.paypal.com/")
    );
    let payment = checkout.payment.id;
    assert!(
        PaymentFlowService::cancel_order_using(&f.pool, &order, &f.owner, "buyer", false, &driver)
            .await
            .is_err()
    );
    gateway.status(&payment, "APPROVED");
    for invalid in ["amount", "currency", "reference"] {
        {
            let mut state = gateway.state.lock().unwrap();
            state.wrong_amount = invalid == "amount";
            state.wrong_currency = invalid == "currency";
            state.wrong_reference = invalid == "reference";
        }
        assert!(
            PaymentFlowService::reconcile_order_payment_using(
                &f.pool, &order, &f.owner, "buyer", false, &driver
            )
            .await
            .is_err()
        );
        assert_eq!(gateway.state.lock().unwrap().captures, 0);
    }
    {
        let mut state = gateway.state.lock().unwrap();
        state.wrong_amount = false;
        state.wrong_currency = false;
        state.wrong_reference = false;
        state.reject_capture_once = true;
    }
    assert!(
        PaymentFlowService::reconcile_order_payment_using(
            &f.pool, &order, &f.owner, "buyer", false, &driver
        )
        .await
        .is_err()
    );
    assert_eq!(f.stock().await, (0, 0));
    gateway.state.lock().unwrap().drop_capture_once = true;
    assert!(
        PaymentFlowService::reconcile_order_payment_using(
            &f.pool, &order, &f.owner, "buyer", false, &driver
        )
        .await
        .is_err()
    );
    assert_eq!(gateway.state.lock().unwrap().captures, 1);
    assert_eq!(f.stock().await, (0, 0));
    // After the capture retry window, a GET proving completion is still safe;
    // it must not attempt another capture just to recover its lost response.
    sqlx::query("UPDATE payment_remote_operations SET capture_retry_until=clock_timestamp()-INTERVAL '1 second' WHERE payment_id=$1").bind(&payment).execute(&f.pool).await.unwrap();
    let result = PaymentFlowService::reconcile_order_payment_using(
        &f.pool, &order, &f.owner, "buyer", false, &driver,
    )
    .await
    .unwrap();
    assert!(result.auto_paid);
    {
        let state = gateway.state.lock().unwrap();
        assert_eq!(state.captures, 1);
        assert_eq!(state.capture_keys.len(), 2);
        assert_eq!(state.capture_keys[0], state.capture_keys[1]);
    }
    assert_eq!(f.stock().await, (0, 1));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn concurrent_instances_capture_once_and_pending_capture_never_grants_paid() {
    use std::sync::{Arc, atomic::AtomicBool};
    let f = Fixture::new(1).await;
    let gateway = RecoveryGateway::new().await;
    configure_recovery_provider(&f, true).await;
    let native = Arc::new(gateway.paypal());
    let order = f.order(1).await;
    let checkout = PaymentFlowService::start_order_payment_using(
        &f.pool,
        &order,
        Some(&f.provider),
        &f.owner,
        "buyer",
        false,
        None,
        native.as_ref(),
    )
    .await
    .unwrap();
    let payment = checkout.payment.id;
    gateway.status(&payment, "APPROVED");
    gateway.state.lock().unwrap().capture_pending = true;
    let gate = Arc::new(RecoveryGate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        once: AtomicBool::new(true),
    });
    let blocking = RecoveryDriver {
        inner: native.clone(),
        before: AtomicBool::new(false),
        after: AtomicBool::new(false),
        gate: Some(gate.clone()),
    };
    let second = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let first = PaymentFlowService::reconcile_order_payment_using(
        &f.pool, &order, &f.owner, "buyer", false, &blocking,
    );
    let competing = async {
        gate.entered.notified().await;
        let result = PaymentFlowService::reconcile_order_payment_using(
            &second,
            &order,
            &f.owner,
            "buyer",
            false,
            native.as_ref(),
        )
        .await;
        gate.release.notify_one();
        result
    };
    let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(first, competing)
    })
    .await
    .unwrap();
    assert!(!a.unwrap().auto_paid);
    assert_eq!(b.unwrap().attach_info["retryAfter"], 45);
    assert_eq!(gateway.state.lock().unwrap().captures, 1);
    assert_eq!(f.stock().await, (0, 0));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    gateway.status(&payment, "COMPLETED");
    assert!(
        PaymentFlowService::reconcile_order_payment_using(
            &f.pool,
            &order,
            &f.owner,
            "buyer",
            false,
            native.as_ref()
        )
        .await
        .unwrap()
        .auto_paid
    );
    assert_eq!(f.stock().await, (0, 1));
    assert_eq!(gateway.state.lock().unwrap().captures, 1);
    f.cleanup().await;
    second.close().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn stripe_cancellation_releases_only_after_remote_expiry_and_paid_race_stays_reserved() {
    let f = Fixture::new(1).await;
    let gateway = RecoveryGateway::new().await;
    configure_recovery_provider(&f, false).await;
    let driver = gateway.stripe();
    let order = f.order(1).await;
    PaymentFlowService::start_order_payment_using(
        &f.pool,
        &order,
        Some(&f.provider),
        &f.owner,
        "buyer",
        false,
        None,
        &driver,
    )
    .await
    .unwrap();
    for _ in 0..2 {
        let canceled = PaymentFlowService::cancel_order_using(
            &f.pool, &order, &f.owner, "buyer", false, &driver,
        )
        .await
        .unwrap();
        assert_eq!(canceled.state, "Canceled");
        assert_eq!(f.stock().await, (1, 0));
    }
    assert_eq!(gateway.state.lock().unwrap().expires, 1);
    let next = f.order(1).await;
    let checkout = PaymentFlowService::start_order_payment_using(
        &f.pool,
        &next,
        Some(&f.provider),
        &f.owner,
        "buyer",
        false,
        None,
        &driver,
    )
    .await
    .unwrap();
    gateway.status(&checkout.payment.id, "complete");
    assert!(
        PaymentFlowService::cancel_order_using(&f.pool, &next, &f.owner, "buyer", false, &driver)
            .await
            .is_err()
    );
    assert_eq!(f.stock().await, (0, 0));
    assert!(
        PaymentFlowService::reconcile_order_payment_using(
            &f.pool, &next, "foreign", "admin", true, &driver
        )
        .await
        .is_err()
    );
    assert!(
        PaymentFlowService::reconcile_order_payment_using(
            &f.pool, &next, &f.owner, "buyer", false, &driver
        )
        .await
        .unwrap()
        .auto_paid
    );
    assert_eq!(f.stock().await, (0, 1));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn real_reconcile_routes_preserve_beneficiary_after_rename_and_deny_reused_username() {
    let f = Fixture::new(2).await;
    let admin = service(&f.pool, Some(f.admin.clone()));
    let buyer = service(&f.pool, Some(f.buyer.clone()));
    configure_plan(&f, &admin).await;
    sqlx::query("UPDATE providers SET type='Balance' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    let checkout = buy(
        &f,
        &buyer,
        &f.product,
        &f.provider,
        "pricingName=public&planName=premium",
    )
    .await;
    let order = checkout["order"]["id"].as_str().unwrap();
    sqlx::query("UPDATE users SET name='renamed-buyer' WHERE id=$1")
        .bind(&f.buyer.id)
        .execute(&f.pool)
        .await
        .unwrap();
    let replacement = Identity {
        id: uuid::Uuid::new_v4().to_string(),
        ..f.buyer.clone()
    };
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,$2,'buyer','Replacement','unused')").bind(&replacement.id).bind(&f.owner).execute(&f.pool).await.unwrap();
    let app = Service::new(casdog::routes::create_router())
        .hoop(salvo::affix_state::AffixList::new().inject(f.pool.clone()));
    for path in [
        format!("reconcile-order?id={order}"),
        format!("orders/{order}/reconcile"),
    ] {
        let response = TestClient::post(format!("http://localhost/api/{path}"))
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        let response = TestClient::post(format!("http://localhost/api/{path}"))
            .add_header(
                "Authorization",
                format!("Bearer {}", token(&replacement)),
                true,
            )
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
        let mut response = TestClient::post(format!("http://localhost/api/{path}"))
            .add_header("Authorization", format!("Bearer {}", token(&f.buyer)), true)
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response.take_json::<Value>().await.unwrap()["payment"]["id"],
            checkout["data"]["id"]
        );
    }
    assert!(
        PaymentFlowService::reconcile_order_payment(&f.pool, order, &f.owner, "buyer", false)
            .await
            .is_err()
    );
    assert!(
        PaymentFlowService::start_order_payment(
            &f.pool, order, None, &f.owner, "buyer", false, None
        )
        .await
        .is_err()
    );
    assert!(
        PaymentFlowService::reconcile_order_payment(
            &f.pool,
            order,
            &f.owner,
            "renamed-buyer",
            false
        )
        .await
        .unwrap()
        .auto_paid
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn ordinary_order_buyer_is_pinned_and_reused_username_cannot_read_pay_cancel_or_reconcile() {
    let f = Fixture::new(2).await;
    let app = Service::new(casdog::routes::create_router())
        .hoop(salvo::affix_state::AffixList::new().inject(f.pool.clone()));
    let forged = uuid::Uuid::new_v4().to_string();
    let response=TestClient::post("http://localhost/api/add-order")
        .add_header("Authorization",format!("Bearer {}",token(&f.admin)),true)
        .json(&json!({"id":forged,"owner":f.owner,"name":"forged-buyer","displayName":"Order","user":"buyer","buyerId":f.admin.id,"provider":f.provider,"productName":"book","quantity":1,"price":20,"currency":"USD"})).send(&app).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT buyer_id FROM orders WHERE id=$1")
            .bind(&forged)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        f.buyer.id
    );
    let order = f.order(1).await;
    let checkout = f.start(&order).await.unwrap();
    assert_eq!(
        checkout.payment.user_id.as_deref(),
        Some(f.buyer.id.as_str())
    );
    let error = sqlx::query("UPDATE orders SET buyer_id=$2 WHERE id=$1")
        .bind(&order)
        .bind(&f.admin.id)
        .execute(&f.pool)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().constraint(),
        Some("checkout_lifecycle")
    );
    sqlx::query("UPDATE users SET name='renamed-buyer' WHERE id=$1")
        .bind(&f.buyer.id)
        .execute(&f.pool)
        .await
        .unwrap();
    let replacement = Identity {
        id: uuid::Uuid::new_v4().to_string(),
        ..f.buyer.clone()
    };
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,$2,'buyer','Replacement','unused')").bind(&replacement.id).bind(&f.owner).execute(&f.pool).await.unwrap();
    for path in ["store/purchases", "get-user-orders", "get-user-payments"] {
        let mut response = TestClient::get(format!("http://localhost/api/{path}"))
            .add_header(
                "Authorization",
                format!("Bearer {}", token(&replacement)),
                true,
            )
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK), "{path}");
        assert!(
            response.take_json::<Value>().await.unwrap()["data"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{path}"
        );
        let mut response = TestClient::get(format!("http://localhost/api/{path}"))
            .add_header("Authorization", format!("Bearer {}", token(&f.buyer)), true)
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert!(
            !response.take_json::<Value>().await.unwrap()["data"]
                .as_array()
                .unwrap()
                .is_empty(),
            "original buyer lost {path}"
        );
    }
    for path in [
        format!("pay-order?id={order}"),
        format!("cancel-order?id={order}"),
        format!("reconcile-order?id={order}"),
        format!("orders/{order}/pay"),
        format!("orders/{order}/cancel"),
        format!("orders/{order}/reconcile"),
    ] {
        let response = TestClient::post(format!("http://localhost/api/{path}"))
            .add_header(
                "Authorization",
                format!("Bearer {}", token(&replacement)),
                true,
            )
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN), "{path}");
    }
    assert_eq!(f.stock().await, (1, 0));
    assert!(
        PaymentFlowService::start_order_payment(
            &f.pool,
            &order,
            None,
            &f.owner,
            "renamed-buyer",
            false,
            None
        )
        .await
        .is_ok()
    );
    let canceled =
        PaymentFlowService::cancel_order(&f.pool, &order, &f.owner, "renamed-buyer", false)
            .await
            .unwrap();
    assert_eq!(canceled.state, "Canceled");
    assert_eq!(f.stock().await, (2, 0));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and schema creation"]
async fn buyer_migration_uses_uuid_evidence_and_never_guesses_reused_historical_names() {
    let pool = database().await;
    let mut connection = pool.acquire().await.unwrap();
    let schema = format!("checkout_buyers_{}", uuid::Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema};SET search_path TO {schema},public;
        CREATE TABLE users(LIKE public.users INCLUDING ALL);
        CREATE TABLE orders(LIKE public.orders INCLUDING ALL);
        ALTER TABLE orders DROP COLUMN buyer_id;
        CREATE TABLE payments(LIKE public.payments INCLUDING ALL);
        CREATE TABLE transactions(LIKE public.transactions INCLUDING ALL);
        CREATE TABLE order_benefits(LIKE public.order_benefits INCLUDING ALL);"
    ))
    .execute(&mut *connection)
    .await
    .unwrap();
    let original = uuid::Uuid::new_v4().to_string();
    let bob = uuid::Uuid::new_v4().to_string();
    let victim = uuid::Uuid::new_v4().to_string();
    let collision = uuid::Uuid::new_v4().to_string();
    for (id, name, days) in [
        (&original, "renamed-alice", 30),
        (&bob, "alice", 40),
        (&victim, "victim", 50),
        (&collision, victim.as_str(), 50),
    ] {
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,created_at) VALUES($1,'tenant',$2,$2,'unused',clock_timestamp()-$3::bigint*INTERVAL '1 day')")
            .bind(id).bind(name).bind(days as i64).execute(&mut *connection).await.unwrap();
    }
    for (id, user) in [
        ("p-unresolved", "alice"),
        ("p-paid", "alice"),
        ("p-explicit", original.as_str()),
        ("p-collision", victim.as_str()),
    ] {
        sqlx::query("INSERT INTO payments(id,owner,name,user_id,amount,state) VALUES($1,'tenant',$1,$2,1,'created')").bind(id).bind(user).execute(&mut *connection).await.unwrap();
    }
    for (id, user, payment) in [
        ("unresolved", "alice", "p-unresolved"),
        ("paid", "alice", "p-paid"),
        ("explicit", "alice", "p-explicit"),
        ("collision", victim.as_str(), "p-collision"),
        ("benefit", "alice", ""),
    ] {
        sqlx::query("INSERT INTO orders(id,owner,name,\"user\",payment_id,price,created_at) VALUES($1,'tenant',$1,$2,NULLIF($3,''),1,clock_timestamp()-INTERVAL '10 days')")
            .bind(id).bind(user).bind(payment).execute(&mut *connection).await.unwrap();
    }
    sqlx::query("INSERT INTO transactions(id,owner,name,category,user_id,amount) VALUES('ledger','tenant','purchase_p-paid','purchase',$1,-1)").bind(&original).execute(&mut *connection).await.unwrap();
    sqlx::query("INSERT INTO order_benefits(order_id,kind,user_id,amount_cents) VALUES('benefit','recharge',$1,100)").bind(&original).execute(&mut *connection).await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/035_order_buyers.sql"))
        .execute(&mut *connection)
        .await
        .unwrap();
    for id in ["paid", "explicit", "benefit"] {
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT buyer_id FROM orders WHERE id=$1")
                .bind(id)
                .fetch_one(&mut *connection)
                .await
                .unwrap(),
            original,
            "{id}"
        );
    }
    for id in ["unresolved", "collision"] {
        assert!(
            sqlx::query_scalar::<_, Option<String>>("SELECT buyer_id FROM orders WHERE id=$1")
                .bind(id)
                .fetch_one(&mut *connection)
                .await
                .unwrap()
                .is_none(),
            "{id}"
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT user_id FROM payments WHERE id='p-paid'")
            .fetch_one(&mut *connection)
            .await
            .unwrap(),
        original
    );
    sqlx::query("UPDATE orders SET state='Processing' WHERE id='unresolved'")
        .execute(&mut *connection)
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT buyer_id FROM orders WHERE id='unresolved'"
        )
        .fetch_one(&mut *connection)
        .await
        .unwrap()
        .is_none()
    );
    sqlx::query("INSERT INTO orders(id,owner,name,\"user\",buyer_id) VALUES('new','tenant','new','renamed-alice',$1)").bind(&bob).execute(&mut *connection).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT buyer_id FROM orders WHERE id='new'")
            .fetch_one(&mut *connection)
            .await
            .unwrap(),
        original
    );
    let foreign = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,'foreign','foreign','Foreign','unused')").bind(&foreign).execute(&mut *connection).await.unwrap();
    let alias = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,'tenant',$2,'Alias','unused')").bind(&alias).bind(&foreign).execute(&mut *connection).await.unwrap();
    assert!(sqlx::query("INSERT INTO orders(id,owner,name,\"user\") VALUES('foreign-reference','tenant','foreign-reference',$1)").bind(&foreign).execute(&mut *connection).await.is_err());
    sqlx::query("INSERT INTO orders(id,owner,name,\"user\") VALUES('qualified-alias','tenant','qualified-alias',$1)").bind(format!("tenant/{foreign}")).execute(&mut *connection).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT buyer_id FROM orders WHERE id='qualified-alias'")
            .fetch_one(&mut *connection)
            .await
            .unwrap(),
        alias
    );
    sqlx::raw_sql(&format!(
        "SET search_path TO public;DROP SCHEMA {schema} CASCADE;"
    ))
    .execute(&mut *connection)
    .await
    .unwrap();
}
