//! Local-wire Custom HTTP protocols through normal Provider CRUD, approval and delivery.
use casdog::{
    config::AppConfig,
    models::Provider,
    services::{ProviderService, provider_dispatch_service::ProviderDispatchService},
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

struct Fixture {
    pool: PgPool,
    service: Arc<Service>,
    owner: String,
    admin: String,
    tenant: String,
    foreign: String,
    users: Vec<String>,
}
impl Fixture {
    async fn new() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            AppConfig::load().unwrap();
        });
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let owner = format!("hdel-{}", uuid::Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin','built-in','Built in') ON CONFLICT(name) DO NOTHING").bind(uuid::Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
        let mut tokens = Vec::new();
        let mut users = Vec::new();
        for (tenant, name) in [
            ("built-in", owner.as_str()),
            (owner.as_str(), "admin"),
            ("other-config-tenant", owner.as_str()),
        ] {
            let id = uuid::Uuid::new_v4().to_string();
            users.push(id.clone());
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,$3,'unused',true)").bind(&id).bind(tenant).bind(name).execute(&pool).await.unwrap();
            let config = AppConfig::get();
            let now = chrono::Utc::now();
            tokens.push(jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({"sub":id,"owner":tenant,"name":name,"is_admin":true,"iat":now.timestamp(),"exp":now.timestamp()+3600,"issued_at_ms":now.timestamp_millis(),"iss":config.jwt.issuer}),&jsonwebtoken::EncodingKey::from_secret(config.jwt.secret.as_bytes())).unwrap());
        }
        let diesel = casdog::diesel_pool::create_diesel_pool(
            &std::env::var("CASDOG_TEST_DATABASE_URL").unwrap(),
        )
        .await
        .unwrap();
        let service = Arc::new(
            Service::new(casdog::routes::create_router()).hoop(
                salvo::affix_state::AffixList::new()
                    .inject(pool.clone())
                    .inject(diesel),
            ),
        );
        Self {
            pool,
            service,
            owner,
            admin: tokens[0].clone(),
            tenant: tokens[1].clone(),
            foreign: tokens[2].clone(),
            users,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        token: &str,
    ) -> Response {
        request(&self.service, method, path, body, token).await
    }
    async fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let mut response = self.request(method, path, body, &self.admin).await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
        body
    }
    async fn create(&self, name: &str, category: &str, kind: &str, extra: Value) -> Value {
        let mut body = json!({"owner":self.owner,"name":name,"display_name":name,"category":category,"type":kind});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        self.ok("POST", "/api/providers", Some(body)).await
    }
    async fn saved(&self, id: &str) -> Provider {
        ProviderService::get_by_id_internal(&self.pool, id)
            .await
            .unwrap()
    }
    async fn grant(&self, id: &str) {
        let result = self
            .ok(
                "POST",
                &format!("/api/providers/{id}/network-approval"),
                Some(json!({"allow_private":true})),
            )
            .await;
        assert_eq!(result["allow_private"], true);
    }
    async fn cleanup(self) {
        sqlx::query("DELETE FROM verifications WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM providers WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        for id in self.users {
            sqlx::query("DELETE FROM users WHERE id=$1")
                .bind(id)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM organizations WHERE name=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        self.pool.close().await;
    }
}
async fn request(
    service: &Service,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: &str,
) -> Response {
    let builder = match method {
        "GET" => TestClient::get(format!("http://localhost{path}")),
        "PUT" => TestClient::put(format!("http://localhost{path}")),
        "DELETE" => TestClient::delete(format!("http://localhost{path}")),
        _ => TestClient::post(format!("http://localhost{path}")),
    };
    let builder = builder.add_header("Authorization", format!("Bearer {token}"), true);
    if let Some(body) = body {
        builder.json(&body).send(service).await
    } else {
        builder.send(service).await
    }
}

#[derive(Clone, Debug)]
struct WireRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
impl WireRequest {
    fn query(&self) -> Vec<(String, String)> {
        reqwest::Url::parse(&format!("http://fixture{}", self.path))
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }
    fn fields(&self) -> Value {
        if self.method == "GET" {
            return pairs_value(self.query());
        }
        if self
            .headers
            .get("content-type")
            .is_some_and(|s| s.starts_with("application/json"))
        {
            serde_json::from_slice(&self.body).unwrap()
        } else {
            let url = reqwest::Url::parse(&format!(
                "http://fixture/?{}",
                String::from_utf8_lossy(&self.body)
            ))
            .unwrap();
            pairs_value(
                url.query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect(),
            )
        }
    }
}
fn pairs_value(pairs: Vec<(String, String)>) -> Value {
    let mut value = serde_json::Map::new();
    for (key, item) in pairs {
        match value.get_mut(&key) {
            None => {
                value.insert(key, json!(item));
            }
            Some(Value::Array(items)) => items.push(json!(item)),
            Some(old) => {
                let first = old.take();
                *old = json!([first, item]);
            }
        }
    }
    Value::Object(value)
}
struct Wire {
    url: String,
    requests: Arc<Mutex<Vec<WireRequest>>>,
    mode: Arc<std::sync::atomic::AtomicU8>,
    gate: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Wire {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = requests.clone();
        let mode = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let flag = mode.clone();
        let gate = Arc::new(tokio::sync::Notify::new());
        let barrier = gate.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let received = received.clone();
                let flag = flag.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let boundary = loop {
                        let mut chunk = [0; 4096];
                        let n = socket.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                        if let Some(i) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                            break i + 4;
                        }
                        assert!(bytes.len() < 128 * 1024);
                    };
                    let head = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
                    let mut lines = head.lines();
                    let mut first = lines.next().unwrap().split_whitespace();
                    let method = first.next().unwrap().to_string();
                    let path = first.next().unwrap().to_string();
                    let headers: BTreeMap<String, String> = lines
                        .filter_map(|line| {
                            line.split_once(':')
                                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().into()))
                        })
                        .collect();
                    let length = headers
                        .get("content-length")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    while bytes.len() - boundary < length {
                        let mut chunk = [0; 4096];
                        let n = socket.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                    }
                    received.lock().unwrap().push(WireRequest {
                        method,
                        path,
                        headers,
                        body: bytes[boundary..boundary + length].to_vec(),
                    });
                    let mode = flag.load(std::sync::atomic::Ordering::SeqCst);
                    if mode == 6 {
                        barrier.notified().await;
                    }
                    let (status, extra, body) = match mode {
                        1 => (
                            "307 Temporary Redirect",
                            "Location: /credential-sink\r\n",
                            Vec::new(),
                        ),
                        2 => ("200 OK", "", vec![b'x'; 65537]),
                        3 => (
                            "500 Internal Server Error",
                            "",
                            b"gateway-secret must not be echoed".to_vec(),
                        ),
                        4 => {
                            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                            ("200 OK", "", Vec::new())
                        }
                        5 => ("204 No Content", "", Vec::new()),
                        _ => ("200 OK", "", b"{}".to_vec()),
                    };
                    let _=socket.write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n",body.len()).as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                });
            }
        });
        Self {
            url,
            requests,
            mode,
            gate,
            task,
        }
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn last(&self) -> WireRequest {
        self.requests.lock().unwrap().last().unwrap().clone()
    }
}
fn id(value: &Value) -> &str {
    value["id"].as_str().unwrap()
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn email_four_methods_json_form_mapping_headers_and_batch_use_real_dispatch() {
    let f = Fixture::new().await;
    let wire = Wire::new().await;
    for method in ["GET", "POST", "PUT", "DELETE"] {
        for content_type in ["application/json", "application/x-www-form-urlencoded"] {
            let name = format!("mail-{}-{}", method, wire.count());
            let p=f.create(&name,"Email","Custom HTTP Email",json!({"endpoint":format!("{}/mail?fixed=one",wire.url),"method":method,"issuer_url":content_type,"client_id2":"sender@example.test","client_secret2":"Sender Name","client_secret":"mail-secret","http_headers":{"X-Custom":"header-secret"},"user_mapping":{"subject":"heading","content":"message","toAddress":"destination","toAddresses":"destinations"}})).await;
            f.grant(id(&p)).await;
            let before = wire.count();
            f.ok("POST","/api/send-email",Some(json!({"provider":format!("{}/{}",f.owner,name),"receivers":["a+tag@example.test","b@example.test"],"title":"Mail + 文 &","content":"Body = &文"}))).await;
            assert_eq!(wire.count(), before + 1);
            let request = wire.last();
            assert_eq!(request.method, method);
            assert_eq!(request.headers["x-custom"], "header-secret");
            assert_eq!(request.headers["authorization"], "Bearer mail-secret");
            let fields = request.fields();
            assert_eq!(fields["heading"], "Mail + 文 &");
            assert_eq!(fields["message"], "Body = &文");
            assert_eq!(fields["fromAddress"], "sender@example.test");
            assert_eq!(fields["fromName"], "Sender Name");
            assert_eq!(
                fields["destinations"],
                json!(["a+tag@example.test", "b@example.test"])
            );
            assert!(fields.get("subject").is_none());
            if method == "GET" {
                assert!(request.body.is_empty());
                assert_eq!(fields["fixed"], "one");
            } else {
                assert!(request.headers["content-type"].starts_with(content_type));
            }
        }
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn sms_four_methods_json_form_template_and_get_placeholders_are_encoded_on_wire() {
    let f = Fixture::new().await;
    let wire = Wire::new().await;
    for method in ["GET", "POST", "PUT", "DELETE"] {
        for content_type in ["application/json", "application/x-www-form-urlencoded"] {
            let name = format!("sms-{}-{}", method, wire.count());
            let p=f.create(&name,"SMS","Custom HTTP SMS",json!({"endpoint":format!("{}/sms?fixed=one",wire.url),"method":method,"issuer_url":content_type,"title":"messageText","template_code":"OTP:%s","user_mapping":{"phoneNumber":"destination"},"http_headers":{"X-SMS":"sms-header"}})).await;
            f.grant(id(&p)).await;
            f.ok("POST","/api/send-sms",Some(json!({"provider":format!("{}/{}",f.owner,name),"to":"+15550123456","content":"12+ &文"}))).await;
            let request = wire.last();
            assert_eq!(request.method, method);
            let fields = request.fields();
            assert_eq!(fields["destination"], "+15550123456");
            assert_eq!(fields["messageText"], "OTP:12+ &文");
            assert_eq!(request.headers["x-sms"], "sms-header");
        }
    }
    let p=f.create("placeholder","SMS","Custom HTTP SMS",json!({"endpoint":format!("{}?fixed=one&phone={{mobile}}&code={{code}}",wire.url),"method":"GET","title":"message","template_code":"OTP:%s"})).await;
    f.grant(id(&p)).await;
    f.ok("POST","/api/send-sms",Some(json!({"provider":format!("{}/placeholder",f.owner),"to":"+15550123456","content":"a+&文/"}))).await;
    let request = wire.last();
    let fields = request.fields();
    assert_eq!(
        fields,
        json!({"fixed":"one","phone":"+15550123456","code":"a+&文/"})
    );
    assert!(request.body.is_empty());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn notification_methods_parameter_recipient_header_precedence_and_receiver_url_fallback() {
    let f = Fixture::new().await;
    let wire = Wire::new().await;
    for method in ["GET", "POST"] {
        let p=f.create(method,"Notification","Custom HTTP",json!({"endpoint":format!("{}/notify?fixed=one",wire.url),"method":method,"title":"messageText","receiver":"default-recipient","metadata":[["X-Shared","legacy-value"],["X-Legacy","retained"]],"http_headers":{"x-shared":"map-value"}})).await;
        assert_eq!(p["endpoint"], "***");
        f.grant(id(&p)).await;
        f.ok("POST","/api/send-notification",Some(json!({"provider":format!("{}/{}",f.owner,method),"content":"hello +文&","title":"not-a-parameter"}))).await;
        let request = wire.last();
        assert_eq!(request.method, method);
        assert_eq!(request.headers["x-shared"], "map-value");
        assert_eq!(request.headers["x-legacy"], "retained");
        let fields = request.fields();
        assert_eq!(fields["messageText"], "hello +文&");
        assert_eq!(fields["recipient"], "default-recipient");
        assert!(fields.get("title").is_none());
    }
    let p=f.create("receiver-url","Notification","Custom HTTP",json!({"receiver":format!("{}/notify?privateToken=not-public",wire.url),"method":"POST","title":"message"})).await;
    let pid = id(&p);
    assert_eq!(p["receiver"], "***");
    f.ok("PUT", &format!("/api/providers/{pid}"), Some(p.clone()))
        .await;
    f.grant(pid).await;
    f.ok(
        "POST",
        "/api/send-notification",
        Some(
            json!({"provider":format!("{}/receiver-url",f.owner),"content":"Receiver URL content"}),
        ),
    )
    .await;
    assert_eq!(
        wire.last().fields(),
        json!({"message":"Receiver URL content"})
    );
    let before = wire.count();
    assert_eq!(
        f.request(
            "PUT",
            &format!("/api/providers/{pid}"),
            Some(json!({"endpoint":format!("{}/other",wire.url)})),
            &f.admin
        )
        .await
        .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    assert_eq!(wire.count(), before);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn private_approval_revocation_stale_record_and_invalid_configuration_fail_before_delivery() {
    let f = Fixture::new().await;
    let wire = Wire::new().await;
    let p = f
        .create(
            "private",
            "Email",
            "Custom HTTP Email",
            json!({"endpoint":wire.url,"method":"POST","issuer_url":"application/json"}),
        )
        .await;
    let pid = id(&p);
    let send = json!({"provider":format!("{}/private",f.owner),"to":"receiver@example.test","content":"secret"});
    assert_eq!(
        f.request("POST", "/api/send-email", Some(send.clone()), &f.admin)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(wire.count(), 0);
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/providers/{pid}/network-approval"),
            Some(json!({"allow_private":true})),
            &f.tenant
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    f.grant(pid).await;
    f.ok("POST", "/api/send-email", Some(send.clone())).await;
    assert_eq!(wire.count(), 1);
    let old = f.saved(pid).await;
    f.ok(
        "PUT",
        &format!("/api/providers/{pid}"),
        Some(json!({"method":"GET"})),
    )
    .await;
    assert!(matches!(
        ProviderDispatchService::new(f.pool.clone())
            .send_email_with_provider(&old, &["receiver@example.test".into()], "Old", "old", None)
            .await,
        Err(casdog::error::AppError::Authorization(_))
    ));
    assert_eq!(wire.count(), 1);
    assert_eq!(
        f.request("POST", "/api/send-email", Some(send.clone()), &f.admin)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    f.grant(pid).await;
    f.ok("POST", "/api/send-email", Some(send.clone())).await;
    assert_eq!(wire.last().method, "GET");
    f.ok(
        "DELETE",
        &format!("/api/providers/{pid}/network-approval"),
        None,
    )
    .await;
    assert_eq!(
        f.request("POST", "/api/send-email", Some(send.clone()), &f.admin)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        f.request("POST", "/api/send-email", Some(send), &f.foreign)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let before = wire.count();
    for patch in [
        json!({"method":"PATCH"}),
        json!({"user_mapping":{"subject":"content"}}),
        json!({"http_headers":{"Content-Length":"0"}}),
        json!({"issuer_url":"application/json","http_headers":{"Content-Type":"application/x-www-form-urlencoded"}}),
    ] {
        assert_eq!(
            f.request(
                "PUT",
                &format!("/api/providers/{pid}"),
                Some(patch),
                &f.admin
            )
            .await
            .status_code,
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(wire.count(), before);
    }
    let saved = f.saved(pid).await;
    assert_eq!(saved.method.as_deref(), Some("GET"));
    // Every real HTTP request rechecks approval. Revoking while recipient one
    // is in flight must prevent recipient two, without holding a DB lock over IO.
    let batch = f
        .create(
            "batch",
            "Email",
            "Custom HTTP Email",
            json!({"endpoint":wire.url}),
        )
        .await;
    f.grant(id(&batch)).await;
    let before_batch = wire.count();
    wire.mode.store(6, std::sync::atomic::Ordering::SeqCst);
    let record = f.saved(id(&batch)).await;
    let pool = f.pool.clone();
    let task = tokio::spawn(async move {
        ProviderDispatchService::new(pool)
            .send_email_with_provider(
                &record,
                &["one@example.test".into(), "two@example.test".into()],
                "Batch",
                "Content",
                None,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while wire.count() == before_batch {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    f.ok(
        "DELETE",
        &format!("/api/providers/{}/network-approval", id(&batch)),
        None,
    )
    .await;
    wire.gate.notify_one();
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(casdog::error::AppError::Authorization(_))
    ));
    assert_eq!(wire.count(), before_batch + 1);
    wire.mode.store(0, std::sync::atomic::Ordering::SeqCst);
    for category in ["SMS", "sms"] {
        let name = format!("unknown-{category}");
        let unknown = f
            .create(
                &name,
                category,
                "TotallyCustom",
                json!({"endpoint":wire.url,"client_secret":"not-a-bypass"}),
            )
            .await;
        let body = json!({"provider":format!("{}/{}",f.owner,name),"to":"+15550123456","content":"Blocked"});
        let count = wire.count();
        assert_eq!(
            f.request("POST", "/api/send-sms", Some(body.clone()), &f.admin)
                .await
                .status_code,
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(wire.count(), count);
        f.grant(id(&unknown)).await;
        f.ok("POST", "/api/send-sms", Some(body)).await;
        assert_eq!(wire.last().fields()["body"], "Blocked");
    }
    let lower=f.create("lower-notify","notification","cUsToM hTtP",json!({"receiver":format!("{}/lower?secret=protected",wire.url),"method":"GET","title":"message"})).await;
    assert_eq!(lower["receiver"], "***");
    f.ok(
        "PUT",
        &format!("/api/providers/{}", id(&lower)),
        Some(lower.clone()),
    )
    .await;
    f.grant(id(&lower)).await;
    f.ok(
        "POST",
        "/api/send-notification",
        Some(json!({"provider":format!("{}/lower-notify",f.owner),"content":"Lowercase"})),
    )
    .await;
    assert_eq!(wire.last().fields()["message"], "Lowercase");
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn legacy_json_compatibility_and_network_response_failures_are_bounded_and_secret_safe() {
    let f = Fixture::new().await;
    let wire = Wire::new().await;
    for (name, category) in [
        ("legacy-email", "Email"),
        ("legacy-sms", "SMS"),
        ("legacy-notification", "Notification"),
    ] {
        let p=f.create(name,category,"Custom HTTP",json!({"endpoint":wire.url,"client_secret":"gateway-secret","http_headers":{"X-New":"actual-header"}})).await;
        f.grant(id(&p)).await;
        let route = match category {
            "Email" => "send-email",
            "SMS" => "send-sms",
            _ => "send-notification",
        };
        f.ok("POST",&format!("/api/{route}"),Some(json!({"provider":format!("{}/{}",f.owner,name),"to":"receiver","content":"legacy-body","title":"legacy-title"}))).await;
        let request = wire.last();
        let body = request.fields();
        assert_eq!(request.method, "POST");
        assert_eq!(request.headers["x-new"], "actual-header");
        assert_eq!(request.headers["authorization"], "Bearer gateway-secret");
        match category {
            "Email" => {
                assert_eq!(body["body"], "legacy-body");
                assert_eq!(body["subject"], "legacy-title");
                assert!(body["timestamp"].is_string());
            }
            "SMS" => assert_eq!(body["body"], "legacy-body"),
            _ => {
                assert_eq!(body["content"], "legacy-body");
                assert!(body["timestamp"].is_number());
            }
        }
    }
    let p=f.create("failure","Email","Custom HTTP Email",json!({"endpoint":format!("{}/gateway?credential=URL-secret",wire.url),"method":"POST","issuer_url":"application/json","client_secret":"gateway-secret"})).await;
    f.grant(id(&p)).await;
    for mode in [1, 2, 3, 4, 5] {
        wire.mode.store(mode, std::sync::atomic::Ordering::SeqCst);
        let before = wire.count();
        let error = ProviderDispatchService::new(f.pool.clone())
            .send_email_with_provider(
                &f.saved(id(&p)).await,
                &["to@example.test".into()],
                "Subject",
                "Message",
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("gateway-secret"));
        assert!(!error.contains("URL-secret"));
        assert!(!error.contains("http://"));
        assert_eq!(wire.count(), before + 1, "Redirect must not be followed");
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn sms_verification_templates_code_once_after_normal_crud_and_network_approval() {
    let f = Fixture::new().await;
    let wire = Wire::new().await;
    let p=f.create("mfa-sms","SMS","Custom HTTP SMS",json!({"endpoint":wire.url,"method":"POST","issuer_url":"application/json","title":"messageText","template_code":"OTP=%s","user_mapping":{"phoneNumber":"recipient"}})).await;
    f.grant(id(&p)).await;
    let dest = format!(
        "+1555{}",
        uuid::Uuid::new_v4().simple().to_string()[..8]
            .chars()
            .map(|c| char::from(b'0' + c as u8 % 10))
            .collect::<String>()
    );
    let response = casdog::services::VerificationService::send_verification_code(
        &f.pool,
        &f.owner,
        Some(&f.users[1]),
        &dest,
        "phone",
        None,
        Some(&format!("{}/mfa-sms", f.owner)),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let code: String = sqlx::query_scalar("SELECT code FROM verifications WHERE id=$1")
        .bind(&response.id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        wire.last().fields(),
        json!({"recipient":dest,"messageText":format!("OTP={code}")})
    );
    assert_eq!(wire.count(), 1);
    f.cleanup().await;
}
