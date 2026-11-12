use casdog::{config::AppConfig, diesel_pool::create_diesel_pool};
use jsonwebtoken::{EncodingKey, Header, encode};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

struct Fixture {
    pool: PgPool,
    service: Service,
    owner: String,
    user: String,
    other: String,
    product: String,
    plan: String,
    pricing: String,
    provider: String,
}
impl Fixture {
    async fn new() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            AppConfig::load().unwrap();
        });
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        let id = || uuid::Uuid::new_v4().to_string();
        let owner = format!("store-{}", id());
        let user = id();
        let other = id();
        let product = id();
        let plan = id();
        let pricing = id();
        let provider = id();
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
        )
        .bind(id())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        for (uid, name) in [(&user, "alice"), (&other, "bob")] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,balance,balance_currency) VALUES($1,$2,$3,$3,'unused',100,'USD')").bind(uid).bind(&owner).bind(name).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO plans(id,owner,name,display_name,price_per_month,price_per_year,currency,is_enabled) VALUES($1,$2,'premium','Premium',5,50,'USD',true)").bind(&plan).bind(&owner).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO pricings(id,owner,name,display_name,plans,is_enabled) VALUES($1,$2,'public','Public',$3,true)").bind(&pricing).bind(&owner).bind(json!([plan.clone()]).to_string()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO products(id,owner,name,display_name,price,currency,quantity,state,plan_id) VALUES($1,$2,'premium','Premium plan',5,'USD',-1,'Active',$3)").bind(&product).bind(&owner).bind(&plan).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,client_secret,metadata) VALUES($1,$2,'wallet','Wallet','Payment','Balance','DO_NOT_DISCLOSE','PRIVATE_METADATA')").bind(&provider).bind(&owner).execute(&pool).await.unwrap();
        Self {
            pool,
            service,
            owner,
            user,
            other,
            product,
            plan,
            pricing,
            provider,
        }
    }
    fn token(&self, other: bool, name: &str) -> String {
        self.signed_token(other, name, false)
    }
    fn signed_token(&self, other: bool, name: &str, admin: bool) -> String {
        let now = chrono::Utc::now();
        encode(&Header::default(),&json!({"sub":if other {&self.other}else{&self.user},"owner":self.owner,"name":name,"is_admin":admin,"exp":now.timestamp()+3600,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"iss":AppConfig::get().jwt.issuer}),&EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
    }
    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        let mut response = TestClient::get(format!("http://localhost{path}"))
            .add_header("Authorization", format!("Bearer {token}"), true)
            .send(&self.service)
            .await;
        (
            response.status_code.unwrap_or(StatusCode::OK),
            response.take_json().await.unwrap(),
        )
    }
    async fn cleanup(&self) {
        let mut tx = self.pool.begin().await.unwrap();
        sqlx::query("SET LOCAL casdog.checkout_write='on'")
            .execute(&mut *tx)
            .await
            .unwrap();
        for statement in [
            "DELETE FROM subscription_grants WHERE owner=$1",
            "DELETE FROM order_benefits WHERE order_id IN (SELECT id FROM orders WHERE owner=$1)",
            "DELETE FROM order_stock_reservations WHERE order_id IN (SELECT id FROM orders WHERE owner=$1)",
            "DELETE FROM orders WHERE owner=$1",
            "DELETE FROM subscriptions WHERE owner=$1",
            "DELETE FROM transactions WHERE owner=$1",
            "DELETE FROM payments WHERE owner=$1",
            "DELETE FROM products WHERE owner=$1",
            "DELETE FROM pricings WHERE owner=$1",
            "DELETE FROM plans WHERE owner=$1",
            "DELETE FROM providers WHERE owner=$1",
            "DELETE FROM users WHERE owner=$1",
        ] {
            sqlx::query(statement)
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
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrated disposable PostgreSQL"]
async fn store_catalog_is_tenant_scoped_paginated_and_never_exposes_provider_secrets() {
    let f = Fixture::new().await;
    let token = f.token(false, "alice");
    for (state, deleted) in [("Draft", false), ("Active", true)] {
        sqlx::query("INSERT INTO products(id,owner,name,display_name,price,state,is_deleted) VALUES($1,$2,$1,'Hidden',1,$3,$4)").bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(state).bind(deleted).execute(&f.pool).await.unwrap();
    }
    let foreign_product = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO products(id,owner,name,display_name,price,state) VALUES($1,'another-tenant',$1,'Foreign',1,'Active')").bind(&foreign_product).execute(&f.pool).await.unwrap();
    let (status, value) = f.get("/api/store/catalog?page_size=1", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["total"], 1);
    assert_eq!(value["data"][0]["id"], f.product);
    assert_eq!(value["plans"][0]["id"], f.plan);
    assert_eq!(value["pricings"][0]["id"], f.pricing);
    assert_eq!(value["providers"][0]["id"], f.provider);
    let encoded = value.to_string();
    for secret in [
        "DO_NOT_DISCLOSE",
        "PRIVATE_METADATA",
        "client_secret",
        "metadata",
    ] {
        assert!(!encoded.contains(secret));
    }
    assert_eq!(
        f.get("/api/store/catalog?page=2&page_size=1", &token)
            .await
            .1["data"],
        json!([])
    );
    for path in [
        "/api/store/catalog?owner=another-tenant",
        "/api/store/purchases?user=bob",
    ] {
        assert_eq!(f.get(path, &token).await.0, StatusCode::FORBIDDEN);
    }
    for path in [
        "/api/store/catalog?page=0",
        "/api/store/catalog?page_size=101",
        "/api/store/purchases?page=oops",
    ] {
        assert_eq!(f.get(path, &token).await.0, StatusCode::BAD_REQUEST);
    }
    sqlx::query("DELETE FROM products WHERE id=$1 AND owner='another-tenant'")
        .bind(&foreign_product)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET balance_currency=NULL,currency='CNY' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.get("/api/store/purchases", &token).await.1["wallet"]["currency"],
        "CNY"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrated disposable PostgreSQL"]
async fn store_purchases_show_only_current_buyer_and_keep_paid_benefits_after_account_rename() {
    let f = Fixture::new().await;
    let token = f.token(false, "alice");
    let mut response=TestClient::post(format!("http://localhost/api/buy-product?id={}&providerName={}&pricingName={}&planName={}&period=monthly",f.product,f.provider,f.pricing,f.plan)).add_header("Authorization",format!("Bearer {token}"),true).send(&f.service).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let purchased: Value = response.take_json().await.unwrap();
    assert_eq!(purchased["autoPaid"], true);
    let own = f.get("/api/store/purchases", &token).await.1;
    assert_eq!(own["total"], 1);
    assert_eq!(own["data"][0]["state"], "Paid");
    assert_eq!(own["wallet"]["balance"], 95.0);
    assert_eq!(own["subscriptions"].as_array().unwrap().len(), 1);
    let peer = f.get("/api/store/purchases", &f.token(true, "bob")).await.1;
    assert_eq!(peer["total"], 0);
    assert_eq!(peer["subscriptions"], json!([]));
    assert_eq!(peer["wallet"]["balance"], 100.0);
    sqlx::query("UPDATE users SET name='renamed' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let renamed = f
        .get("/api/store/purchases", &f.token(false, "renamed"))
        .await
        .1;
    assert_eq!(renamed["total"], 1);
    assert_eq!(renamed["data"][0]["id"], purchased["order"]["id"]);
    assert_eq!(renamed["subscriptions"].as_array().unwrap().len(), 1);
    let renamed_token = f.token(false, "renamed");
    let restored = TestClient::post(format!(
        "http://localhost/api/reconcile-order?id={}",
        purchased["order"]["id"].as_str().unwrap()
    ))
    .add_header("Authorization", format!("Bearer {renamed_token}"), true)
    .send(&f.service)
    .await;
    assert_eq!(restored.status_code, Some(StatusCode::OK));
    sqlx::query("UPDATE users SET name='alice' WHERE id=$1")
        .bind(&f.other)
        .execute(&f.pool)
        .await
        .unwrap();
    let replacement = f.token(true, "alice");
    assert_eq!(
        f.get("/api/store/purchases", &replacement).await.1["total"],
        0
    );
    let denied = TestClient::post(format!(
        "http://localhost/api/reconcile-order?id={}",
        purchased["order"]["id"].as_str().unwrap()
    ))
    .add_header("Authorization", format!("Bearer {replacement}"), true)
    .send(&f.service)
    .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrated disposable PostgreSQL"]
async fn compatibility_commerce_lists_accept_current_names_or_ids_and_keep_uuid_ownership_after_rename()
 {
    let f = Fixture::new().await;
    let token = f.token(false, "alice");
    let mut response = TestClient::post(format!(
        "http://localhost/api/buy-product?id={}&providerName={}&pricingName={}&planName={}",
        f.product, f.provider, f.pricing, f.plan
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&f.service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let bought: Value = response.take_json().await.unwrap();
    sqlx::query("UPDATE users SET is_admin=true WHERE id=$1")
        .bind(&f.other)
        .execute(&f.pool)
        .await
        .unwrap();
    let administrator = f.signed_token(true, "bob", true);
    for query in [
        "name=alice".to_string(),
        format!("userId={}", f.user),
        format!("user={}/alice", f.owner),
    ] {
        for route in ["get-user-orders", "get-user-payments"] {
            let (status, body) = f
                .get(
                    &format!("/api/{route}?owner={}&{query}", f.owner),
                    &administrator,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["data"].as_array().unwrap().len(), 1, "{body}");
        }
    }
    sqlx::query("UPDATE users SET name='renamed' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let current = f.token(false, "renamed");
    for route in ["get-user-orders", "get-user-payments"] {
        let (status, body) = f
            .get(
                &format!("/api/{route}?owner={}&name=renamed", f.owner),
                &administrator,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
        let own = f
            .get(&format!("/api/{route}?name=other-user-input"), &current)
            .await;
        assert_eq!(own.0, StatusCode::OK);
        assert_eq!(own.1["data"].as_array().unwrap().len(), 1);
    }
    let own = f.get("/api/get-user-orders", &current).await.1;
    assert_eq!(own["data"][0]["id"], bought["order"]["id"]);
    f.cleanup().await;
}
