//! Cart APIs and one-payment multi-line checkout against real PostgreSQL.
use casdog::{
    config::AppConfig,
    hoops::authz::Principal,
    services::{
        PaymentFlowService,
        cart_service::{CartService, CheckoutCart},
    },
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::collections::HashMap;
struct Fixture {
    pool: PgPool,
    app: Service,
    owner: String,
    buyer: String,
    other: String,
    admin: String,
    book: String,
    pen: String,
    provider: String,
}
impl Fixture {
    async fn new() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            AppConfig::load().unwrap();
        });
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let owner = format!("cart-{}", uuid::Uuid::new_v4());
        let buyer = uuid::Uuid::new_v4().to_string();
        let other = uuid::Uuid::new_v4().to_string();
        let admin = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        for (id, name, is_admin) in [
            (&buyer, "buyer", false),
            (&other, "other", false),
            (&admin, "admin", true),
        ] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin,balance) VALUES($1,$2,$3,$3,'unused',$4,1000)").bind(id).bind(&owner).bind(name).bind(is_admin).execute(&pool).await.unwrap();
        }
        let book = uuid::Uuid::new_v4().to_string();
        let pen = uuid::Uuid::new_v4().to_string();
        let provider = uuid::Uuid::new_v4().to_string();
        for (id, name, price) in [(&book, "book", 20.0), (&pen, "pen", 5.0)] {
            sqlx::query("INSERT INTO products(id,owner,name,display_name,price,quantity,currency) VALUES($1,$2,$3,$3,$4,10,'USD')").bind(id).bind(&owner).bind(name).bind(price).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES($1,$2,'payment','Payment','Payment','Balance')").bind(&provider).bind(&owner).execute(&pool).await.unwrap();
        let diesel = casdog::diesel_pool::create_diesel_pool(
            &std::env::var("CASDOG_TEST_DATABASE_URL").unwrap(),
        )
        .await
        .unwrap();
        let app = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        Self {
            pool,
            app,
            owner,
            buyer,
            other,
            admin,
            book,
            pen,
            provider,
        }
    }
    fn actor(&self, who: &str) -> Principal {
        Principal {
            id: match who {
                "other" => self.other.clone(),
                "admin" => self.admin.clone(),
                _ => self.buyer.clone(),
            },
            owner: self.owner.clone(),
            name: who.into(),
            admin: who == "admin",
            application_identity: false,
        }
    }
    fn token(&self, who: &str) -> String {
        let p = self.actor(who);
        let c = AppConfig::get();
        let now = chrono::Utc::now();
        jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({"sub":p.id,"owner":p.owner,"name":p.name,"is_admin":p.admin,"iat":now.timestamp(),"exp":now.timestamp()+3600,"issued_at_ms":now.timestamp_millis(),"iss":c.jwt.issuer}),&jsonwebtoken::EncodingKey::from_secret(c.jwt.secret.as_bytes())).unwrap()
    }
    async fn request(&self, method: &str, path: &str, body: Option<Value>, who: &str) -> Response {
        let builder = match method {
            "GET" => TestClient::get(format!("http://localhost{path}")),
            "PUT" => TestClient::put(format!("http://localhost{path}")),
            _ => TestClient::post(format!("http://localhost{path}")),
        }
        .add_header("Authorization", format!("Bearer {}", self.token(who)), true);
        if let Some(body) = body {
            builder.json(&body).send(&self.app).await
        } else {
            builder.send(&self.app).await
        }
    }
    async fn json(&self, method: &str, path: &str, body: Option<Value>, who: &str) -> Value {
        let mut response = self.request(method, path, body, who).await;
        let status = response.status_code;
        let body = response.take_string().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
        serde_json::from_str(&body).unwrap()
    }
    async fn get(&self, who: &str) -> Value {
        self.json("GET", "/api/store/cart", None, who).await["data"].clone()
    }
    async fn replace(&self, who: &str, items: Value) -> Value {
        let revision = self.get(who).await["revision"].as_i64().unwrap();
        self.json(
            "PUT",
            "/api/store/cart",
            Some(json!({"revision":revision,"items":items})),
            who,
        )
        .await["data"]
            .clone()
    }
    fn confirmation(&self, cart: &Value) -> Value {
        json!({"revision":cart["revision"],"providerId":self.provider,"expectedTotalCents":cart["total_amount_cents"],"currency":cart["currency"]})
    }
    async fn checkout(&self, who: &str) -> Value {
        let cart = self.get(who).await;
        self.json(
            "POST",
            "/api/store/cart/checkout",
            Some(self.confirmation(&cart)),
            who,
        )
        .await["data"]
            .clone()
    }
    async fn pay(
        &self,
        id: &str,
        who: &str,
    ) -> casdog::error::AppResult<casdog::services::payment_flow_service::PaymentStartResult> {
        PaymentFlowService::start_order_payment(&self.pool, id, None, &self.owner, who, false, None)
            .await
    }
    async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE owner=$1"))
            .bind(&self.owner)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn stock(&self, id: &str) -> (i32, i32) {
        sqlx::query_as("SELECT quantity,sold FROM products WHERE id=$1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn wallet(&self) -> f64 {
        sqlx::query_scalar("SELECT balance FROM users WHERE id=$1")
            .bind(&self.buyer)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn plan(&self, name: &str) -> (String, String, String, String) {
        let product = uuid::Uuid::new_v4().to_string();
        let plan = uuid::Uuid::new_v4().to_string();
        let pricing = uuid::Uuid::new_v4().to_string();
        let role = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO roles(id,owner,name,display_name,is_enabled) VALUES($1,$2,$3,$3,true)",
        )
        .bind(&role)
        .bind(&self.owner)
        .bind(name)
        .execute(&self.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO plans(id,owner,name,display_name,price_per_month,price_per_year,currency,role,is_enabled) VALUES($1,$2,$3,$3,10,100,'USD',$4,true)").bind(&plan).bind(&self.owner).bind(name).bind(&role).execute(&self.pool).await.unwrap();
        sqlx::query("INSERT INTO pricings(id,owner,name,display_name,plans,is_enabled) VALUES($1,$2,$3,$3,$4,true)").bind(&pricing).bind(&self.owner).bind(name).bind(json!([plan]).to_string()).execute(&self.pool).await.unwrap();
        sqlx::query("INSERT INTO products(id,owner,name,display_name,price,quantity,currency,plan_id) VALUES($1,$2,$3,$3,10,10,'USD',$4)").bind(&product).bind(&self.owner).bind(name).bind(&plan).execute(&self.pool).await.unwrap();
        (product, plan, pricing, role)
    }
    async fn recharge(&self) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO products(id,owner,name,display_name,price,quantity,currency,is_recharge,recharge_options,disable_custom_recharge) VALUES($1,$2,'recharge','Recharge',0,-1,'USD',true,'[10,20]',true)").bind(&id).bind(&self.owner).execute(&self.pool).await.unwrap();
        id
    }
    async fn provider(&self, kind: &str) {
        sqlx::query("UPDATE providers SET type=$2,client_id='client',client_secret=CASE WHEN $2='PayPal' THEN 'secret' ELSE 'sk_gateway' END,host='sandbox' WHERE id=$1").bind(&self.provider).bind(kind).execute(&self.pool).await.unwrap();
    }
    async fn cleanup(&self) {
        let ids:Vec<String>=sqlx::query_scalar("SELECT payment_id FROM orders WHERE owner=$1 AND payment_id IS NOT NULL AND lower(state) IN ('created','processing')").bind(&self.owner).fetch_all(&self.pool).await.unwrap();
        for id in ids {
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
            "DELETE FROM coupon_usages WHERE order_id IN(SELECT id FROM orders WHERE owner=$1)",
            "DELETE FROM cart_checkouts WHERE user_id IN(SELECT id FROM users WHERE owner=$1)",
            "DELETE FROM order_lines WHERE order_id IN(SELECT id FROM orders WHERE owner=$1)",
            "DELETE FROM order_benefits WHERE order_id IN(SELECT id FROM orders WHERE owner=$1)",
            "DELETE FROM transactions WHERE owner=$1",
            "DELETE FROM orders WHERE owner=$1",
            "DELETE FROM payments WHERE owner=$1",
            "DELETE FROM carts WHERE owner=$1",
            "DELETE FROM products WHERE owner=$1",
            "DELETE FROM providers WHERE owner=$1",
            "DELETE FROM plans WHERE owner=$1",
            "DELETE FROM pricings WHERE owner=$1",
            "DELETE FROM roles WHERE owner=$1",
            "DELETE FROM coupons WHERE owner=$1",
            "DELETE FROM users WHERE owner=$1",
            "DELETE FROM organizations WHERE name=$1",
        ] {
            sqlx::query(sql)
                .bind(&self.owner)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn cart_cas_self_scope_edit_remove_and_quote_revalidation_are_real_api_operations() {
    let f = Fixture::new().await;
    let initial = f.get("buyer").await;
    assert_eq!(initial["revision"], 0);
    let cart=f.replace("buyer",json!([{"productId":f.book,"quantity":1},{"productId":f.book,"quantity":1},{"productId":f.pen,"quantity":2}])).await;
    assert_eq!(cart["items"].as_array().unwrap().len(), 2);
    assert_eq!(cart["total_amount_cents"], 5000);
    let stale = f
        .request(
            "PUT",
            "/api/store/cart",
            Some(json!({"revision":0,"items":[]})),
            "buyer",
        )
        .await;
    assert_eq!(stale.status_code, Some(StatusCode::CONFLICT));
    assert!(f.get("other").await["items"].as_array().unwrap().is_empty());
    assert!(f.get("admin").await["items"].as_array().unwrap().is_empty());
    assert_eq!(
        f.request(
            "GET",
            &format!("/api/store/cart?owner={}&user=buyer", f.owner),
            None,
            "other"
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let confirmed = f.confirmation(&cart);
    sqlx::query("UPDATE products SET price=21 WHERE id=$1")
        .bind(&f.book)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.request("POST", "/api/store/cart/checkout", Some(confirmed), "buyer")
            .await
            .status_code,
        Some(StatusCode::CONFLICT)
    );
    assert_eq!(f.count("orders").await, 0);
    assert_eq!(f.get("buyer").await["items"].as_array().unwrap().len(), 2);
    let changed = f.get("buyer").await;
    assert_eq!(changed["total_amount_cents"], 5200);
    let response = f
        .json(
            "POST",
            "/api/store/cart/checkout",
            Some(f.confirmation(&changed)),
            "buyer",
        )
        .await;
    assert_eq!(response["data"]["order"]["price"], 52.0);
    assert!(f.get("buyer").await["items"].as_array().unwrap().is_empty());
    f.replace("buyer", json!([{"productId":f.pen,"quantity":1}]))
        .await;
    let cleared = f.replace("buyer", json!([])).await;
    assert!(cleared["items"].as_array().unwrap().is_empty());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn two_pools_create_one_parent_checkout_and_debit_once_for_multiple_skus() {
    let f = Fixture::new().await;
    let cart = f
        .replace(
            "buyer",
            json!([{"productId":f.book,"quantity":2},{"productId":f.pen,"quantity":3}]),
        )
        .await;
    let request: CheckoutCart = serde_json::from_value(f.confirmation(&cart)).unwrap();
    let second = PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let actor = f.actor("buyer");
    let (a, b) = tokio::join!(
        CartService::checkout(&f.pool, &actor, request.clone()),
        CartService::checkout(&second, &actor, request)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a["order"]["id"], b["order"]["id"]);
    let id = a["order"]["id"].as_str().unwrap();
    assert_eq!(f.count("orders").await, 1);
    let (a, b) = tokio::join!(
        PaymentFlowService::start_order_payment(&f.pool, id, None, &f.owner, "buyer", false, None),
        PaymentFlowService::start_order_payment(&second, id, None, &f.owner, "buyer", false, None)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(f.count("payments").await, 1);
    assert_eq!(f.count("transactions").await, 1);
    assert_eq!(f.wallet().await, 945.0);
    assert_eq!(f.stock(&f.book).await, (8, 2));
    assert_eq!(f.stock(&f.pen).await, (7, 3));
    let history = f.json("GET", "/api/store/purchases", None, "buyer").await;
    assert_eq!(history["total"], 1);
    assert_eq!(history["data"][0]["kind"], "cart");
    assert_eq!(history["data"][0]["lines"].as_array().unwrap().len(), 2);
    assert_eq!(
        f.json("GET", "/api/store/purchases", None, "other").await["total"],
        0
    );
    assert!(
        sqlx::query("UPDATE orders SET price=1 WHERE id=$1")
            .bind(id)
            .execute(&f.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE order_lines SET amount_cents=1 WHERE order_id=$1")
            .bind(id)
            .execute(&f.pool)
            .await
            .is_err()
    );
    assert!(f.pay(id, "other").await.is_err());
    f.cleanup().await;
    second.close().await;
}

#[tokio::test]
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn multi_sku_stock_failure_rolls_back_the_whole_payment_and_then_can_retry() {
    let f = Fixture::new().await;
    f.replace(
        "buyer",
        json!([{"productId":f.book,"quantity":2},{"productId":f.pen,"quantity":2}]),
    )
    .await;
    let checkout = f.checkout("buyer").await;
    let id = checkout["order"]["id"].as_str().unwrap();
    sqlx::query("UPDATE products SET quantity=1 WHERE id=$1")
        .bind(&f.pen)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(f.pay(id, "buyer").await.is_err());
    assert_eq!(f.stock(&f.book).await, (10, 0));
    assert_eq!(f.stock(&f.pen).await, (1, 0));
    assert_eq!(f.wallet().await, 1000.0);
    assert_eq!(f.count("payments").await, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM order_line_stock_reservations WHERE order_id=$1"
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        0
    );
    sqlx::query("UPDATE products SET quantity=10 WHERE id=$1")
        .bind(&f.pen)
        .execute(&f.pool)
        .await
        .unwrap();
    f.pay(id, "buyer").await.unwrap();
    assert_eq!(f.wallet().await, 950.0);
    assert_eq!(f.stock(&f.book).await, (8, 2));
    assert_eq!(f.stock(&f.pen).await, (8, 2));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn small_multiline_coupon_allocates_exact_cents_without_negative_last_line() {
    let f = Fixture::new().await;
    let mut items = Vec::new();
    for n in 0..9 {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO products(id,owner,name,display_name,price,quantity,currency) VALUES($1,$2,$3,$3,0.01,1,'USD')").bind(&id).bind(&f.owner).bind(format!("cent-{n}")).execute(&f.pool).await.unwrap();
        items.push(json!({"productId":id,"quantity":1}));
    }
    let response=f.json("POST","/api/add-coupon",Some(json!({"owner":f.owner,"name":"rounding","code":"ROUND","discountType":"fixed","discount":0.08,"quantity":1,"scope":"universal","currency":"USD"})),"admin").await;
    assert_eq!(response["status"], "ok");
    let cart = f.replace("buyer", json!(items)).await;
    let mut request = f.confirmation(&cart);
    request["couponCode"] = json!("ROUND");
    let result = f
        .json("POST", "/api/store/cart/checkout", Some(request), "buyer")
        .await["data"]
        .clone();
    let lines = result["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 9);
    assert_eq!(
        lines
            .iter()
            .map(|l| l["amount_cents"].as_i64().unwrap())
            .sum::<i64>(),
        1
    );
    assert!(
        lines
            .iter()
            .all(|l| l["amount_cents"].as_i64().unwrap() >= 0)
    );
    let id = result["order"]["id"].as_str().unwrap();
    f.pay(id, "buyer").await.unwrap();
    assert_eq!(f.wallet().await, 999.99);
    assert_eq!(f.count("transactions").await, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT used_count FROM coupons WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    f.cleanup().await;
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

#[tokio::test]
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn mixed_cart_one_external_payment_credits_recharge_and_grants_each_plan_once() {
    let f = Fixture::new().await;
    let (product1, plan1, pricing1, role1) = f.plan("premium").await;
    let (product2, plan2, pricing2, role2) = f.plan("pro").await;
    let recharge = f.recharge().await;
    f.provider("Stripe").await;
    let gateway = RecoveryGateway::new().await;
    let driver = gateway.stripe();
    let items = json!([{"productId":f.book,"quantity":2},{"productId":recharge,"quantity":2,"customPrice":10},{"productId":product1,"quantity":2,"planName":plan1,"pricingName":pricing1,"period":"monthly"},{"productId":product2,"quantity":1,"planName":plan2,"pricingName":pricing2,"period":"yearly"}]);
    f.replace("buyer", items).await;
    let result = f.checkout("buyer").await;
    assert_eq!(result["total_amount_cents"], 18000);
    let id = result["order"]["id"].as_str().unwrap();
    let historical = f
        .json("GET", &format!("/api/get-order?id={id}"), None, "buyer")
        .await;
    let infos = historical["data"]["productInfos"].as_array().unwrap();
    assert_eq!(infos.len(), 4);
    assert_eq!(infos[1]["isRecharge"], true);
    assert_eq!(infos[1]["price"], 10.0);
    assert_eq!(infos[2]["planName"], "premium");
    assert_eq!(infos[2]["pricingName"], "premium");
    assert_eq!(infos[2]["quantity"], 2);

    let payment = PaymentFlowService::start_order_payment_using(
        &f.pool, id, None, &f.owner, "buyer", false, None, &driver,
    )
    .await
    .unwrap();
    assert!(!payment.auto_paid);
    assert_eq!(f.wallet().await, 1000.0);
    assert_eq!(f.count("subscriptions").await, 0);
    assert_eq!(f.count("transactions").await, 0);
    assert_eq!(f.stock(&f.book).await, (8, 0));
    assert_eq!(f.stock(&product1).await, (8, 0));
    assert_eq!(f.stock(&product2).await, (9, 0));
    // A checkout already accepted by the gateway retains its paid promise
    // when a merchant later revokes a pricing invitation.
    sqlx::query("UPDATE pricings SET is_invite_only=true,users=$2 WHERE id=ANY($1)")
        .bind(vec![pricing1.clone(), pricing2.clone()])
        .bind(json!(["other"]))
        .execute(&f.pool)
        .await
        .unwrap();
    gateway.status(&payment.payment.id, "complete");
    gateway.state.lock().unwrap().wrong_amount = true;
    assert!(
        PaymentFlowService::reconcile_order_payment_using(
            &f.pool, id, &f.owner, "buyer", false, &driver
        )
        .await
        .is_err()
    );
    assert_eq!(f.count("transactions").await, 0);
    assert_eq!(f.count("subscriptions").await, 0);
    gateway.state.lock().unwrap().wrong_amount = false;
    let second = PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        PaymentFlowService::reconcile_order_payment_using(
            &f.pool, id, &f.owner, "buyer", false, &driver
        ),
        PaymentFlowService::reconcile_order_payment_using(
            &second, id, &f.owner, "buyer", false, &driver
        )
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(gateway.state.lock().unwrap().creates, 1);
    assert_eq!(f.count("orders").await, 1);
    assert_eq!(f.count("payments").await, 1);
    assert_eq!(f.count("transactions").await, 2);
    assert_eq!(f.wallet().await, 1020.0);
    assert_eq!(f.count("subscriptions").await, 2);
    assert_eq!(f.stock(&f.book).await, (8, 2));
    assert_eq!(f.stock(&recharge).await, (-1, 2));
    assert_eq!(f.stock(&product1).await, (8, 2));
    assert_eq!(f.stock(&product2).await, (9, 1));
    let grants:Vec<(String,chrono::DateTime<chrono::Utc>,chrono::DateTime<chrono::Utc>)>=sqlx::query_as("SELECT role_id,starts_at,ends_at FROM subscription_grants WHERE order_id=$1 ORDER BY role_id").bind(id).fetch_all(&f.pool).await.unwrap();
    assert_eq!(grants.len(), 2);
    for (role, start, end) in grants {
        assert_eq!(
            end,
            start
                .checked_add_months(chrono::Months::new(if role == role1 { 2 } else { 12 }))
                .unwrap()
        );
        assert!(role == role1 || role == role2);
    }
    let mut roles =
        casdog::services::SubscriptionService::active_role_names(&f.pool, &f.owner, "buyer")
            .await
            .unwrap();
    roles.sort();
    let mut expected = vec![format!("{}/premium", f.owner), format!("{}/pro", f.owner)];
    expected.sort();
    assert_eq!(roles, expected);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_roles WHERE user_id=$1")
            .bind(&f.buyer)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, f64>("SELECT sum(amount) FROM transactions WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        -160.0
    );
    // A plan bought inside a unified order is a valid proven renewal source.
    sqlx::query("UPDATE pricings SET users='[]'::jsonb WHERE id=$1")
        .bind(&pricing1)
        .execute(&f.pool)
        .await
        .unwrap();
    let subscription: String =
        sqlx::query_scalar("SELECT id FROM subscriptions WHERE owner=$1 AND plan_id=$2")
            .bind(&f.owner)
            .bind(&plan1)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let consent =
        casdog::services::subscription_renewal_service::SubscriptionRenewalService::set_auto_renew(
            &f.pool,
            &subscription,
            &f.owner,
            &f.buyer,
            false,
            true,
        )
        .await
        .unwrap();
    assert_eq!(consent.mode.as_deref(), Some("checkout_required"));
    f.cleanup().await;
    second.close().await;
}

#[tokio::test]
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn stripe_cart_cancel_waits_for_remote_expire_and_releases_every_sku_once() {
    let f = Fixture::new().await;
    f.provider("Stripe").await;
    let gateway = RecoveryGateway::new().await;
    let driver = gateway.stripe();
    f.replace(
        "buyer",
        json!([{"productId":f.book,"quantity":2},{"productId":f.pen,"quantity":3}]),
    )
    .await;
    let result = f.checkout("buyer").await;
    let id = result["order"]["id"].as_str().unwrap();
    PaymentFlowService::start_order_payment_using(
        &f.pool, id, None, &f.owner, "buyer", false, None, &driver,
    )
    .await
    .unwrap();
    assert_eq!(f.stock(&f.book).await, (8, 0));
    assert_eq!(f.stock(&f.pen).await, (7, 0));
    for _ in 0..2 {
        let canceled =
            PaymentFlowService::cancel_order_using(&f.pool, id, &f.owner, "buyer", false, &driver)
                .await
                .unwrap();
        assert_eq!(canceled.state, "Canceled");
    }
    assert_eq!(gateway.state.lock().unwrap().expires, 1);
    assert_eq!(f.stock(&f.book).await, (10, 0));
    assert_eq!(f.stock(&f.pen).await, (10, 0));
    assert_eq!(f.count("transactions").await, 0);
    assert_eq!(f.wallet().await, 1000.0);
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM order_line_stock_reservations WHERE order_id=$1 AND state='released'").bind(id).fetch_one(&f.pool).await.unwrap(),2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn paypal_cart_approval_captures_once_for_the_unified_parent_amount() {
    let f = Fixture::new().await;
    f.provider("PayPal").await;
    let gateway = RecoveryGateway::new().await;
    let driver = gateway.paypal();
    f.replace(
        "buyer",
        json!([{"productId":f.book,"quantity":1},{"productId":f.pen,"quantity":2}]),
    )
    .await;
    let result = f.checkout("buyer").await;
    let id = result["order"]["id"].as_str().unwrap();
    let payment = PaymentFlowService::start_order_payment_using(
        &f.pool, id, None, &f.owner, "buyer", false, None, &driver,
    )
    .await
    .unwrap();
    assert_eq!(payment.payment.amount, 30.0);
    gateway.status(&payment.payment.id, "APPROVED");
    let second = PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        PaymentFlowService::reconcile_order_payment_using(
            &f.pool, id, &f.owner, "buyer", false, &driver
        ),
        PaymentFlowService::reconcile_order_payment_using(
            &second, id, &f.owner, "buyer", false, &driver
        )
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(gateway.state.lock().unwrap().captures, 1);
    assert_eq!(f.count("transactions").await, 1);
    assert_eq!(f.wallet().await, 1000.0);
    assert_eq!(f.stock(&f.book).await, (9, 1));
    assert_eq!(f.stock(&f.pen).await, (8, 2));
    f.cleanup().await;
    second.close().await;
}

#[tokio::test]
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn legacy_user_cart_cas_and_place_order_share_the_canonical_store_without_partial_user_edits()
{
    let f = Fixture::new().await;
    let path = format!("/api/get-user?id={}/buyer", f.owner);
    let response = f.json("GET", &path, None, "buyer").await;
    let mut user = response["data"].clone();
    assert_eq!(user["cartRevision"], 0);
    user["cart"] = json!([{"owner":f.owner,"name":"book","price":0.01,"quantity":2}]);
    f.json(
        "POST",
        &format!("/api/update-user?id={}/buyer", f.owner),
        Some(user.clone()),
        "buyer",
    )
    .await;
    assert_eq!(f.get("buyer").await["total_amount_cents"], 4000);
    assert_eq!(f.get("buyer").await["items"][0]["quantity"], 2);
    let stale = f
        .request(
            "POST",
            &format!("/api/update-user?id={}/buyer", f.owner),
            Some(user),
            "buyer",
        )
        .await;
    assert_eq!(stale.status_code, Some(StatusCode::CONFLICT));
    let mut user = f.json("GET", &path, None, "buyer").await["data"].clone();
    user["displayName"] = json!("Must not change profile with cart");
    user["cart"] = json!([]);
    let revision = f.get("buyer").await["revision"].clone();
    let bad = f
        .request(
            "POST",
            &format!("/api/update-user?id={}/buyer", f.owner),
            Some(user),
            "buyer",
        )
        .await;
    assert_ne!(bad.status_code, Some(StatusCode::OK));
    assert_eq!(f.get("buyer").await["revision"], revision);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT display_name FROM users WHERE id=$1")
            .bind(&f.buyer)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        "buyer"
    );
    let current = f.json("GET", &path, None, "buyer").await["data"].clone();
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/update-user?id={}/buyer", f.owner),
            Some(current),
            "other"
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let placed=f.json("POST",&format!("/api/place-order?owner={}&userName=buyer",f.owner),Some(json!({"productInfos":[{"name":"book","price":0.01,"quantity":1},{"name":"pen","price":999,"quantity":2}]})),"buyer").await;
    assert_eq!(placed["data"]["price"], 30.0);
    assert_eq!(placed["lines"].as_array().unwrap().len(), 2);
    assert_eq!(f.get("buyer").await["items"][0]["quantity"], 2);
    let id = placed["data"]["id"].as_str().unwrap();
    let historical = f
        .json("GET", &format!("/api/get-order?id={id}"), None, "buyer")
        .await;
    let infos = historical["data"]["productInfos"].as_array().unwrap();
    assert_eq!(infos.len(), 2);
    assert_eq!(infos[0]["name"], "book");
    assert_eq!(infos[0]["price"], 20.0);
    assert_eq!(infos[1]["name"], "pen");
    assert_eq!(infos[1]["price"], 5.0);
    assert_eq!(infos[1]["quantity"], 2);
    assert_eq!(historical["data"]["products"], json!(["book", "pen"]));
    assert_eq!(
        f.request("GET", &format!("/api/get-order?id={id}"), None, "other")
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );

    PaymentFlowService::start_order_payment(
        &f.pool,
        id,
        Some(&f.provider),
        &f.owner,
        "buyer",
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(f.count("payments").await, 1);
    assert_eq!(f.wallet().await, 970.0);
    let payment_id: String = sqlx::query_scalar("SELECT payment_id FROM orders WHERE id=$1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    let payment_path = format!("/api/get-payment?id={payment_id}");
    assert_eq!(
        f.json("GET", &payment_path, None, "buyer").await["data"]["id"],
        payment_id
    );
    assert_eq!(
        f.request("GET", &payment_path, None, "other")
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    f.cleanup().await;
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
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn lost_external_cart_checkout_recovers_same_gateway_payment_and_reserved_lines() {
    let f = Fixture::new().await;
    f.provider("Stripe").await;
    let gateway = RecoveryGateway::new().await;
    let lost = LoseCreate {
        inner: gateway.stripe(),
        lost: std::sync::atomic::AtomicBool::new(false),
    };
    f.replace(
        "buyer",
        json!([{"productId":f.book,"quantity":1},{"productId":f.pen,"quantity":2}]),
    )
    .await;
    let result = f.checkout("buyer").await;
    let id = result["order"]["id"].as_str().unwrap();
    assert!(
        PaymentFlowService::start_order_payment_using(
            &f.pool, id, None, &f.owner, "buyer", false, None, &lost
        )
        .await
        .is_err()
    );
    assert_eq!(gateway.state.lock().unwrap().creates, 1);
    assert_eq!(f.count("payments").await, 1);
    assert_eq!(f.stock(&f.book).await, (9, 0));
    assert_eq!(f.stock(&f.pen).await, (8, 0));
    assert_eq!(f.count("transactions").await, 0);
    assert!(f.get("buyer").await["items"].as_array().unwrap().is_empty());
    let driver = gateway.stripe();
    let recovered = PaymentFlowService::reconcile_order_payment_using(
        &f.pool, id, &f.owner, "buyer", false, &driver,
    )
    .await
    .unwrap();
    assert!(!recovered.auto_paid);
    assert_eq!(gateway.state.lock().unwrap().creates, 1);
    let payment = recovered.payment.id;
    {
        let state = gateway.state.lock().unwrap();
        assert_eq!(state.create_keys, vec![payment.clone(), payment.clone()]);
        assert_eq!(state.create_bodies[0], state.create_bodies[1]);
    }
    gateway.status(&payment, "complete");
    PaymentFlowService::reconcile_order_payment_using(
        &f.pool, id, &f.owner, "buyer", false, &driver,
    )
    .await
    .unwrap();
    assert_eq!(f.count("transactions").await, 1);
    assert_eq!(f.count("payments").await, 1);
    assert_eq!(f.stock(&f.book).await, (9, 1));
    assert_eq!(f.stock(&f.pen).await, (8, 2));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrations043-044 and CASDOG_TEST_DATABASE_URL"]
async fn cart_recharge_currency_and_current_pricing_invites_are_checked_before_any_payment() {
    let f = Fixture::new().await;
    let recharge = f.recharge().await;
    let invalid = f
        .request(
            "PUT",
            "/api/store/cart",
            Some(
                json!({"revision":0,"items":[{"productId":recharge,"quantity":1,"customPrice":9}]}),
            ),
            "buyer",
        )
        .await;
    assert_eq!(invalid.status_code, Some(StatusCode::BAD_REQUEST));
    let cart=f.replace("buyer",json!([{"productId":f.book,"quantity":1},{"productId":recharge,"quantity":1,"customPrice":10}])).await;
    assert_eq!(
        f.request(
            "POST",
            "/api/store/cart/checkout",
            Some(f.confirmation(&cart)),
            "buyer"
        )
        .await
        .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    assert_eq!(f.count("orders").await, 0);
    f.provider("Stripe").await;
    let mut coupon = f.confirmation(&cart);
    coupon["couponCode"] = json!("NOT-ALLOWED");
    assert_eq!(
        f.request("POST", "/api/store/cart/checkout", Some(coupon), "buyer")
            .await
            .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    assert_eq!(f.count("orders").await, 0);
    sqlx::query("UPDATE products SET currency='EUR' WHERE id=$1")
        .bind(&f.book)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(f.get("buyer").await["valid"], false);
    assert_eq!(
        f.request(
            "POST",
            "/api/store/cart/checkout",
            Some(f.confirmation(&cart)),
            "buyer"
        )
        .await
        .status_code,
        Some(StatusCode::CONFLICT)
    );
    assert_eq!(f.count("orders").await, 0);
    f.replace("buyer", json!([])).await;
    let (product, plan, pricing, _) = f.plan("invite").await;
    sqlx::query("UPDATE pricings SET is_invite_only=true,users=$2 WHERE id=$1")
        .bind(&pricing)
        .bind(json!(["other"]))
        .execute(&f.pool)
        .await
        .unwrap();
    let revision = f.get("buyer").await["revision"].clone();
    let input = json!({"productId":product,"quantity":1,"planName":plan,"pricingName":pricing});
    assert_eq!(
        f.request(
            "PUT",
            "/api/store/cart",
            Some(json!({"revision":revision,"items":[input.clone()]})),
            "buyer"
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    sqlx::query("UPDATE pricings SET users='[]'::jsonb WHERE id=$1")
        .bind(&pricing)
        .execute(&f.pool)
        .await
        .unwrap();
    f.provider("Balance").await;
    f.replace("buyer", json!([input])).await;
    let placed = f.checkout("buyer").await;
    let id = placed["order"]["id"].as_str().unwrap();
    sqlx::query("UPDATE pricings SET users=$2 WHERE id=$1")
        .bind(&pricing)
        .bind(json!(["other"]))
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(f.pay(id, "buyer").await.is_err());
    assert_eq!(f.count("payments").await, 0);
    assert_eq!(f.wallet().await, 1000.0);
    assert_eq!(f.stock(&product).await, (10, 0));
    let mut machine = f.actor("buyer");
    machine.application_identity = true;
    assert!(CartService::get(&f.pool, &machine).await.is_err());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migration043 and CASDOG_TEST_DATABASE_URL"]
async fn invalid_cart_rows_can_be_removed_individually_without_reaccepting_the_remaining_invalid_rows()
 {
    let f = Fixture::new().await;
    let valid = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO products(id,owner,name,display_name,price,quantity,currency) VALUES($1,$2,'valid','Valid',2,10,'USD')").bind(&valid).bind(&f.owner).execute(&f.pool).await.unwrap();
    f.replace("buyer",json!([{"productId":f.book,"quantity":1},{"productId":f.pen,"quantity":1},{"productId":valid,"quantity":1}])).await;
    sqlx::query("UPDATE products SET is_deleted=true WHERE id=$1")
        .bind(&f.book)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE products SET quantity=0 WHERE id=$1")
        .bind(&f.pen)
        .execute(&f.pool)
        .await
        .unwrap();
    let before = f.get("buyer").await;
    assert_eq!(
        before["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["valid"] == false)
            .count(),
        2
    );
    let reduced = f
        .replace(
            "buyer",
            json!([{"productId":f.pen,"quantity":1},{"productId":valid,"quantity":1}]),
        )
        .await;
    assert_eq!(reduced["items"].as_array().unwrap().len(), 2);
    assert_eq!(reduced["valid"], false);
    assert!(
        reduced["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["product_id"] == valid && v["valid"] == true)
    );
    assert_eq!(
        f.request(
            "POST",
            "/api/store/cart/checkout",
            Some(f.confirmation(&reduced)),
            "buyer"
        )
        .await
        .status_code,
        Some(StatusCode::CONFLICT)
    );
    assert_eq!(f.count("orders").await, 0);
    let revision = reduced["revision"].clone();
    let increase=f.request("PUT","/api/store/cart",Some(json!({"revision":revision,"items":[{"productId":f.pen,"quantity":2},{"productId":valid,"quantity":1}]})),"buyer").await;
    assert_eq!(increase.status_code, Some(StatusCode::CONFLICT));
    assert_eq!(f.get("buyer").await["revision"], revision);
    let path = format!("/api/get-user?id={}/buyer", f.owner);
    let mut user = f.json("GET", &path, None, "buyer").await["data"].clone();
    let rows = user["cart"].as_array_mut().unwrap();
    assert_eq!(rows.len(), 2);
    rows.retain(|v| v["productId"] != f.pen);
    assert_eq!(rows.len(), 1);
    f.json(
        "POST",
        &format!("/api/update-user?id={}/buyer", f.owner),
        Some(user),
        "buyer",
    )
    .await;
    let ready = f.get("buyer").await;
    assert_eq!(ready["valid"], true);
    assert_eq!(ready["items"].as_array().unwrap().len(), 1);
    let placed = f.checkout("buyer").await;
    f.pay(placed["order"]["id"].as_str().unwrap(), "buyer")
        .await
        .unwrap();
    assert_eq!(f.wallet().await, 998.0);
    assert_eq!(f.stock(&valid).await, (9, 1));
    // Created snapshots are promises only after checkout was accepted. A first
    // Balance debit must re-check the current plan and role availability.
    let (product, plan, pricing, role) = f.plan("pending-plan").await;
    f.replace(
        "buyer",
        json!([{"productId":product,"quantity":1,"planName":plan,"pricingName":pricing}]),
    )
    .await;
    let pending = f.checkout("buyer").await;
    let pending_id = pending["order"]["id"].as_str().unwrap();
    for (table, id, field) in [
        ("plans", &plan, "is_enabled"),
        ("plans", &plan, "is_deleted"),
        ("roles", &role, "is_enabled"),
        ("roles", &role, "is_deleted"),
    ] {
        let unavailable = field == "is_deleted";
        sqlx::query(&format!("UPDATE {table} SET {field}=$2 WHERE id=$1"))
            .bind(id)
            .bind(unavailable)
            .execute(&f.pool)
            .await
            .unwrap();
        assert!(f.pay(pending_id, "buyer").await.is_err(), "{table}.{field}");
        assert_eq!(f.wallet().await, 998.0, "{table}.{field}");
        assert_eq!(f.stock(&product).await, (10, 0), "{table}.{field}");
        assert_eq!(f.count("payments").await, 1, "{table}.{field}");
        assert_eq!(f.count("transactions").await, 1, "{table}.{field}");
        assert_eq!(f.count("subscriptions").await, 0, "{table}.{field}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM order_line_stock_reservations WHERE order_id=$1"
            )
            .bind(pending_id)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            0
        );
        sqlx::query(&format!("UPDATE {table} SET {field}=$2 WHERE id=$1"))
            .bind(id)
            .bind(!unavailable)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    f.pay(pending_id, "buyer").await.unwrap();
    assert_eq!(f.wallet().await, 988.0);
    assert_eq!(f.stock(&product).await, (9, 1));
    assert_eq!(f.count("payments").await, 2);
    assert_eq!(f.count("transactions").await, 2);
    assert_eq!(f.count("subscriptions").await, 1);
    f.cleanup().await;
}
