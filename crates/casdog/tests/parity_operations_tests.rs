//! Operational parity integration tests; use a migrated disposable database.
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
struct Identity {
    owner: String,
    name: String,
    id: String,
    admin: bool,
}
#[handler]
async fn identify(depot: &mut Depot) {
    let p = depot.obtain::<Identity>().unwrap().clone();
    depot.insert("user_owner", p.owner);
    depot.insert("user_name", p.name);
    depot.insert("user_id", p.id);
    depot.insert("is_admin", p.admin);
}
fn service(pool: &PgPool, p: Identity) -> Service {
    Service::new(Router::with_path("api").push(casdog::handlers::parity_operations::routes()))
        .hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(p),
        )
        .hoop(identify)
}
async fn database() -> PgPool {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        casdog::config::AppConfig::load().unwrap();
    });
    PgPoolOptions::new()
        .max_connections(8)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").expect("set CASDOG_TEST_DATABASE_URL"))
        .await
        .unwrap()
}
fn identity(owner: &str, name: &str, admin: bool) -> Identity {
    Identity {
        owner: owner.into(),
        name: name.into(),
        id: uuid::Uuid::new_v4().to_string(),
        admin,
    }
}
async fn user(pool: &PgPool, p: &Identity) {
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin,balance)VALUES($1,$2,$3,$3,'unused',$4,100)").bind(&p.id).bind(&p.owner).bind(&p.name).bind(p.admin).execute(pool).await.unwrap();
}
async fn cleanup(pool: &PgPool, owners: &[String]) {
    for table in ["coupon_usages", "webhook_events", "coupon_usages"] {
        if table == "coupon_usages" {
            sqlx::query("DELETE FROM coupon_usages WHERE coupon_id IN (SELECT id FROM coupons WHERE owner=ANY($1))").bind(owners).execute(pool).await.unwrap();
        } else {
            sqlx::query("DELETE FROM webhook_events WHERE organization=ANY($1)")
                .bind(owners)
                .execute(pool)
                .await
                .unwrap();
        }
    }
    for table in [
        "coupons",
        "transactions",
        "payments",
        "orders",
        "products",
        "providers",
        "records",
        "webhooks",
        "permissions",
        "subscriptions",
        "plans",
        "users",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE owner=ANY($1)"))
            .bind(owners)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[test]
fn domain_expiration_is_taken_from_authoritative_event() {
    let date=casdog::handlers::parity_operations::rdap_expiration(&json!({"events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"},{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}]})).unwrap();
    assert_eq!(date.to_rfc3339(), "2030-01-01T00:00:00+00:00");
    assert!(casdog::handlers::parity_operations::rdap_expiration(&json!({"events":[]})).is_err());
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn coupons_checkout_settle_once_and_failed_payment_releases_reservation() {
    let pool = database().await;
    let owner = format!("ops-{}", uuid::Uuid::new_v4());
    let other = format!("ops-{}", uuid::Uuid::new_v4());
    let admin = identity(&owner, "admin", true);
    let buyer = identity(&owner, "buyer", false);
    let outsider = identity(&other, "outsider", true);
    for p in [&admin, &buyer, &outsider] {
        user(&pool, p).await;
    }
    let a = service(&pool, admin);
    let b = service(&pool, buyer.clone());
    let foreign = service(&pool, outsider);
    let product = uuid::Uuid::new_v4().to_string();
    let provider = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO products(id,owner,name,display_name,price,quantity,currency)VALUES($1,$2,'book','Book',20,5,'USD')").bind(&product).bind(&owner).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type)VALUES($1,$2,'balance','Balance','Payment','Balance')").bind(&provider).bind(&owner).execute(&pool).await.unwrap();
    let mut res=TestClient::post("http://localhost/api/add-coupon").json(&json!({"owner":owner,"name":"save","code":"SAVE","discountType":"fixed","discount":5,"quantity":1,"maxUsagePerUser":1,"scope":"product","products":["book"],"state":"Active","currency":"USD"})).send(&a).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let created: Value = res.take_json().await.unwrap();
    let coupon = created["object"]["id"].as_str().unwrap().to_owned();
    let mut res=TestClient::post("http://localhost/api/validate-coupon").json(&json!({"owner":owner,"couponCode":"SAVE","products":["book"],"amount":20,"currency":"USD"})).send(&b).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    assert_eq!(
        res.take_json::<Value>().await.unwrap()["data"]["discount"],
        5.0
    );
    let res = TestClient::get(format!("http://localhost/api/get-coupon?id={coupon}"))
        .send(&foreign)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let res = TestClient::get("http://localhost/api/get-coupons")
        .send(&b)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let mut res = TestClient::post(format!(
        "http://localhost/api/buy-product?id={product}&providerName={provider}&couponCode=SAVE"
    ))
    .send(&b)
    .await;
    let status = res.status_code;
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let bought: Value = res.take_json().await.unwrap();
    assert_eq!(bought["autoPaid"], true);
    assert_eq!(bought["order"]["price"], 15.0);
    let balance: f64 = sqlx::query_scalar("SELECT balance FROM users WHERE id=$1")
        .bind(&buyer.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(balance, 85.0);
    let (used,consumed):(i64,bool)=sqlx::query_as("SELECT c.used_count,u.consumed FROM coupons c JOIN coupon_usages u ON u.coupon_id=c.id WHERE c.id=$1").bind(&coupon).fetch_one(&pool).await.unwrap();
    assert_eq!((used, consumed), (1, true));
    let res = TestClient::post(format!(
        "http://localhost/api/buy-product?id={product}&providerName={provider}&couponCode=SAVE"
    ))
    .send(&b)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
    sqlx::query("UPDATE users SET balance=0 WHERE id=$1")
        .bind(&buyer.id)
        .execute(&pool)
        .await
        .unwrap();
    let res=TestClient::post("http://localhost/api/add-coupon").json(&json!({"owner":owner,"name":"retry","code":"RETRY","discountType":"fixed","discount":5,"quantity":1})).send(&a).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let res = TestClient::post(format!(
        "http://localhost/api/buy-product?id={product}&providerName={provider}&couponCode=RETRY"
    ))
    .send(&b)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
    let remaining:i64=sqlx::query_scalar("SELECT COUNT(*) FROM coupon_usages WHERE coupon_id=(SELECT id FROM coupons WHERE owner=$1 AND name='retry')").bind(&owner).fetch_one(&pool).await.unwrap();
    assert_eq!(remaining, 0);
    let mut res = TestClient::get("http://localhost/api/get-coupons")
        .send(&a)
        .await;
    assert_eq!(res.take_json::<Value>().await.unwrap()["total"], 2);
    let res = TestClient::post(format!("http://localhost/api/update-coupon?id={coupon}"))
        .json(&json!({"discount":101,"discountType":"percentage"}))
        .send(&a)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
    let res = TestClient::post("http://localhost/api/delete-coupon")
        .json(&json!({"owner":owner,"name":"retry"}))
        .send(&a)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    // Sub-cent 100% discounts must never produce a negative payment or credit balance.
    sqlx::query("UPDATE products SET price=0.005 WHERE id=$1")
        .bind(&product)
        .execute(&pool)
        .await
        .unwrap();
    let res=TestClient::post("http://localhost/api/add-coupon").json(&json!({"owner":owner,"name":"tiny","code":"TINY","discountType":"percentage","discount":100})).send(&a).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let res = TestClient::post(format!(
        "http://localhost/api/buy-product?id={product}&providerName={provider}&couponCode=TINY"
    ))
    .send(&b)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
    let balance: f64 = sqlx::query_scalar("SELECT balance FROM users WHERE id=$1")
        .bind(&buyer.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(balance, 0.0);
    // Two concurrent immediate balance checkouts for the final item charge only once.
    sqlx::query("UPDATE products SET price=20,quantity=1 WHERE id=$1")
        .bind(&product)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET balance=100 WHERE id=$1")
        .bind(&buyer.id)
        .execute(&pool)
        .await
        .unwrap();
    let url = format!("http://localhost/api/buy-product?id={product}&providerName={provider}");
    let (one, two) = tokio::join!(
        TestClient::post(&url).send(&b),
        TestClient::post(&url).send(&b)
    );
    let statuses = [one.status_code, two.status_code];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == Some(StatusCode::OK))
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == Some(StatusCode::BAD_REQUEST))
            .count(),
        1
    );
    let balance: f64 = sqlx::query_scalar("SELECT balance FROM users WHERE id=$1")
        .bind(&buyer.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(balance, 80.0);
    let stock: i32 = sqlx::query_scalar("SELECT quantity FROM products WHERE id=$1")
        .bind(&product)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stock, 0);
    cleanup(&pool, &[owner, other]).await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn dashboard_subscription_contact_and_atomic_permissions_respect_tenants() {
    let pool = database().await;
    let owner = format!("ops-{}", uuid::Uuid::new_v4());
    let other = format!("ops-{}", uuid::Uuid::new_v4());
    let admin = identity(&owner, "admin", true);
    let member = identity(&owner, "member", false);
    let outsider = identity(&other, "outsider", true);
    for p in [&admin, &member, &outsider] {
        user(&pool, p).await;
    }
    let a = service(&pool, admin);
    let m = service(&pool, member.clone());
    let foreign = service(&pool, outsider);
    sqlx::query("UPDATE users SET mfa_enabled=true,email='member@example.test',phone='123456789' WHERE id=$1").bind(&member.id).execute(&pool).await.unwrap();
    let mut res = TestClient::get("http://localhost/api/get-dashboard-mfa")
        .send(&a)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let data = res.take_json::<Value>().await.unwrap();
    assert_eq!(data["data"], json!({"total":2,"enabled":1,"disabled":1}));
    let res = TestClient::get(format!(
        "http://localhost/api/get-dashboard-mfa?owner={other}"
    ))
    .send(&a)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    sqlx::query("INSERT INTO records(id,owner,name,organization,action,method,request_uri)VALUES($1,$2,'login-record',$2,'login','POST','/api/login')").bind(uuid::Uuid::new_v4().to_string()).bind(&owner).execute(&pool).await.unwrap();
    let mut res = TestClient::get("http://localhost/api/get-dashboard-heatmap")
        .send(&a)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    assert_eq!(
        res.take_json::<Value>().await.unwrap()["data"]["maxCount"],
        1
    );
    let mut res = TestClient::get("http://localhost/api/get-email-and-phone")
        .send(&m)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let data = res.take_json::<Value>().await.unwrap();
    assert_eq!(data["data"]["email"], "me***@example.test");
    assert_eq!(data["data"]["phone"], "***6789");
    let res = TestClient::get("http://localhost/api/get-email-and-phone?username=admin")
        .send(&m)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let subscription = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO subscriptions(id,owner,name,user_id,plan_id)VALUES($1,$2,'sub',$3,'plan')",
    )
    .bind(&subscription)
    .bind(&owner)
    .bind(&member.id)
    .execute(&pool)
    .await
    .unwrap();
    let res = TestClient::post(format!(
        "http://localhost/api/set-subscription-auto-renew?id={subscription}&autoRenew=true"
    ))
    .send(&m)
    .await;
    // An imported flag without a paid purchase is not a wallet mandate.
    assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
    let collision = identity(&owner, &member.id, false);
    user(&pool, &collision).await;
    let collision_service = service(&pool, collision);
    let res = TestClient::post(format!(
        "http://localhost/api/set-subscription-auto-renew?id={subscription}&autoRenew=false"
    ))
    .send(&collision_service)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let renew: bool = sqlx::query_scalar("SELECT auto_renew FROM subscriptions WHERE id=$1")
        .bind(&subscription)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!renew);
    let res = TestClient::post(format!(
        "http://localhost/api/set-subscription-auto-renew?id={subscription}&autoRenew=false"
    ))
    .send(&foreign)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let mine = uuid::Uuid::new_v4().to_string();
    let theirs = uuid::Uuid::new_v4().to_string();
    for (id, tenant) in [(&mine, &owner), (&theirs, &other)] {
        sqlx::query("INSERT INTO permissions(id,owner,name,display_name,resource_type,resources,actions)VALUES($1,$2,'perm','Before','Application','app','Read')").bind(id).bind(tenant).execute(&pool).await.unwrap();
    }
    let res = TestClient::post("http://localhost/api/update-permissions")
        .json(&json!([{"id":mine,"displayName":"After"},{"id":theirs,"displayName":"Hacked"}]))
        .send(&a)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let name: String = sqlx::query_scalar("SELECT display_name FROM permissions WHERE id=$1")
        .bind(&mine)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(name, "Before");
    let res = TestClient::post("http://localhost/api/update-permissions")
        .json(&json!([{"id":mine,"displayName":"After","effect":"Deny"}]))
        .send(&a)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let res = TestClient::get("http://localhost/api/get-setting")
        .send(&a)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    cleanup(&pool, &[owner, other]).await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn webhook_replay_records_real_http_failure_success_and_tenant_scope() {
    let pool = database().await;
    let owner = format!("ops-{}", uuid::Uuid::new_v4());
    let other = format!("ops-{}", uuid::Uuid::new_v4());
    let a = service(&pool, identity(&owner, "admin", true));
    let foreign = service(&pool, identity(&other, "other", true));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for status in ["500 Internal Server Error", "200 OK"] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 4096];
            let body_start = loop {
                let count = stream.read(&mut chunk).await.unwrap();
                assert!(count > 0, "Webhook request ended before its body");
                bytes.extend_from_slice(&chunk[..count]);
                assert!(bytes.len() <= 16_384, "Unexpected webhook request size");
                let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&bytes[..header_end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .expect("Webhook request must declare its body length");
                if bytes.len() >= header_end + 4 + length {
                    break header_end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&bytes[..body_start]);
            assert!(headers.starts_with("POST /hook HTTP/1.1\r\n"));
            let payload: Value = serde_json::from_slice(&bytes[body_start..]).unwrap();
            assert_eq!(payload["event"], "user.created");
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let webhook = uuid::Uuid::new_v4().to_string();
    let event = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO webhooks(id,owner,name,organization,url,method,content_type)VALUES($1,$2,'hook',$2,$3,'POST','application/json')").bind(&webhook).bind(&owner).bind(format!("http://{address}/hook")).execute(&pool).await.unwrap();
    let payload = json!({"event":"user.created","action":"create","entity_type":"user","entity_id":"entity","entity_name":"Alice","owner":owner,"timestamp":chrono::Utc::now().to_rfc3339(),"data":{"password_hash":"do-not-expose","displayName":"Alice"}});
    sqlx::query("INSERT INTO webhook_events(id,owner,name,organization,webhook_id,event,payload)VALUES($1,$2,$1,$2,$3,'user.created',$4)").bind(&event).bind(&owner).bind(&webhook).bind(payload).execute(&pool).await.unwrap();
    let res = TestClient::post(format!(
        "http://localhost/api/replay-webhook-event?id={event}"
    ))
    .send(&foreign)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    for (expected, status, attempt) in [("Failed", 500, 1), ("Success", 200, 2)] {
        let mut res = TestClient::post(format!(
            "http://localhost/api/replay-webhook-event?id={event}"
        ))
        .send(&a)
        .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        let body: Value = res.take_json().await.unwrap();
        assert_eq!(body["data"]["state"], expected);
        assert_eq!(body["data"]["status_code"], status);
        assert_eq!(body["data"]["attempts"], attempt);
        assert!(!body.to_string().contains("do-not-expose"));
    }
    server.await.unwrap();
    let mut res = TestClient::get("http://localhost/api/get-webhook-events")
        .send(&a)
        .await;
    assert_eq!(res.take_json::<Value>().await.unwrap()["total"], 1);
    let mut res = TestClient::get("http://localhost/api/get-webhook-events")
        .send(&foreign)
        .await;
    assert_eq!(res.take_json::<Value>().await.unwrap()["total"], 0);
    let res = TestClient::post("http://localhost/api/delete-webhook-event")
        .json(&json!({"id":event}))
        .send(&a)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    cleanup(&pool, &[owner, other]).await;
}
