//! Real Provider HTTP CRUD, masked configuration transactions and delivery.
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
            .max_connections(6)
            .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let owner = format!("pcfg-{}", uuid::Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
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
        let service = Arc::new(
            Service::new(casdog::routes::create_router())
                .hoop(salvo::affix_state::AffixList::new().inject(pool.clone())),
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
    async fn cleanup(self) {
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
        _ => TestClient::post(format!("http://localhost{path}")),
    };
    let builder = builder.add_header("Authorization", format!("Bearer {token}"), true);
    if let Some(body) = body {
        builder.json(&body).send(service).await
    } else {
        builder.send(service).await
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn native_configuration_roundtrip_and_legacy_projection_preserve_effective_fields_and_tenant()
{
    let f = Fixture::new().await;
    let result=f.create("custom","OAuth","Custom",json!({"client_id":"client","client_secret":"primary-real","client_id2":"secondary-id","client_secret2":"secondary-real",
        "custom_auth_url":"https://id.example.test/auth","custom_token_url":"https://id.example.test/token","custom_user_info_url":"https://id.example.test/userinfo","custom_logo":"https://cdn.example.test/logo.svg",
        "user_mapping":{"id":"identity.key","username":"identity.login"},"http_headers":{"X-Private":"header-real"},"scopes":"openid profile","method":"POST","receiver":"receiver","title":"Title",
        "disable_ssl":true,"issuer_url":"https://id.example.test","sign_name":"Sender","template_code":"sms-template","app_id":"sms-app","metadata":{"opaque":"opaque-real"}})).await;
    let id = result["id"].as_str().unwrap();
    for field in [
        "client_id2",
        "custom_auth_url",
        "custom_token_url",
        "custom_user_info_url",
        "custom_logo",
        "receiver",
        "title",
        "method",
        "issuer_url",
        "sign_name",
        "template_code",
        "app_id",
    ] {
        assert!(result[field].as_str().is_some(), "{field}:{result}");
    }
    assert_eq!(result["disable_ssl"], true);
    assert_eq!(result["user_mapping"]["id"], "identity.key");
    assert_eq!(result["client_secret"], "***");
    assert_eq!(result["client_secret2"], "***");
    assert_eq!(result["http_headers"]["X-Private"], "***");
    assert_eq!(result["metadata"], "***");
    for secret in [
        "primary-real",
        "secondary-real",
        "header-real",
        "opaque-real",
    ] {
        assert!(!result.to_string().contains(secret));
    }
    let get = f.ok("GET", &format!("/api/providers/{id}"), None).await;
    assert_eq!(get, result);
    let saved = f
        .ok("PUT", &format!("/api/providers/{id}"), Some(get.clone()))
        .await;
    assert_eq!(saved["client_secret"], "***");
    let internal = f.saved(id).await;
    assert_eq!(internal.client_secret.as_deref(), Some("primary-real"));
    assert_eq!(internal.client_secret2.as_deref(), Some("secondary-real"));
    assert_eq!(
        internal.metadata.as_deref(),
        Some("{\"opaque\":\"opaque-real\"}")
    );
    for path in [
        format!("/api/providers/{id}"),
        format!("/api/get-provider?id={}/custom", f.owner),
    ] {
        assert_eq!(
            f.request("GET", &path, None, &f.foreign).await.status_code,
            Some(StatusCode::FORBIDDEN)
        );
    }
    let mut body = get.clone();
    body["owner"] = json!("other-config-tenant");
    assert_eq!(
        f.request("POST", "/api/providers", Some(body), &f.tenant)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let legacy = f
        .ok(
            "GET",
            &format!("/api/get-provider?id={}/custom", f.owner),
            None,
        )
        .await;
    assert_eq!(legacy["data"]["clientSecret"], "***");
    assert_eq!(legacy["data"]["userMapping"]["id"], "identity.key");
    assert_eq!(legacy["data"]["metadata"], "***");
    let updated=f.ok("POST",&format!("/api/update-provider?id={}/custom",f.owner),Some(json!({"owner":f.owner,"name":"custom","clientSecret":"***","clientSecret2":"***","userMapping":"{\"id\":\"identity.id\"}"}))).await;
    assert_eq!(updated["object"]["userMapping"]["id"], "identity.id");
    assert_eq!(
        f.saved(id).await.client_secret.as_deref(),
        Some("primary-real")
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn payment_metadata_masks_merge_aliases_rotation_and_locked_concurrent_preservation() {
    let f = Fixture::new().await;
    let p=f.create("stripe","Payment","Stripe",json!({"client_secret":"sk-original","metadata":{"webhookSecret":"wh-original","opaque":"hidden"}})).await;
    let id = p["id"].as_str().unwrap().to_string();
    let path = format!("/api/providers/{id}");
    let metadata: Value = serde_json::from_str(p["metadata"].as_str().unwrap()).unwrap();
    assert_eq!(metadata, json!({"webhook_secret":"***"}));
    f.ok(
        "PUT",
        &path,
        Some(json!({"metadata":{"signingSecret":"***","extraSetting":"new-hidden"}})),
    )
    .await;
    let actual: Value =
        serde_json::from_str(f.saved(&id).await.metadata.as_deref().unwrap()).unwrap();
    assert_eq!(actual["webhook_secret"], "wh-original");
    assert_eq!(actual["opaque"], "hidden");
    f.ok(
        "PUT",
        &path,
        Some(json!({"metadata":{"webhook_secret":"wh-rotated"},"client_secret":"sk-rotated"})),
    )
    .await;
    // The in-flight masked update must wait for the writer and merge against
    // its new secret, rather than the stale GET's credential snapshot.
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM providers WHERE id=$1 FOR UPDATE")
        .bind(&id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let service = f.service.clone();
    let token = f.admin.clone();
    let update_path = path.clone();
    let snapshot = p.clone();
    let task = tokio::spawn(async move {
        request(&service, "PUT", &update_path, Some(snapshot), &token).await
    });
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    assert!(!task.is_finished());
    sqlx::query("UPDATE providers SET client_secret='sk-current',metadata=$2 WHERE id=$1")
        .bind(&id)
        .bind(json!({"webhook_secret":"wh-current","opaque":"latest"}).to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut response = task.await.unwrap();
    let status = response.status_code;
    let value: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{value}");
    let actual = f.saved(&id).await;
    assert_eq!(actual.client_secret.as_deref(), Some("sk-current"));
    assert_eq!(
        serde_json::from_str::<Value>(actual.metadata.as_deref().unwrap()).unwrap()["webhook_secret"],
        "wh-current"
    );
    let paypal=f.create("paypal","Payment","PayPal",json!({"client_id":"paypal-client","client_secret":"paypal-secret","metadata":{"webhookId":"paypal-hook"}})).await;
    assert_eq!(
        serde_json::from_str::<Value>(paypal["metadata"].as_str().unwrap()).unwrap(),
        json!({"webhook_id":"***"})
    );
    f.ok(
        "PUT",
        &format!("/api/providers/{}", paypal["id"].as_str().unwrap()),
        Some(paypal.clone()),
    )
    .await;
    f.ok(
        "PUT",
        &path,
        Some(json!({"metadata":"","client_secret":""})),
    )
    .await;
    let cleared = f.saved(&id).await;
    assert_eq!(cleared.client_secret.as_deref(), Some(""));
    assert_eq!(cleared.metadata.as_deref(), Some(""));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn missing_markers_invalid_mapping_headers_and_legacy_updates_rollback_completely() {
    let f = Fixture::new().await;
    for field in [
        "client_secret",
        "client_secret2",
        "metadata",
        "http_headers",
    ] {
        let mut body = json!({"owner":f.owner,"name":"invalid","display_name":"bad","category":"Payment","type":"Dummy"});
        body[field] = json!("***");
        assert_eq!(
            f.request("POST", "/api/providers", Some(body.clone()), &f.admin)
                .await
                .status_code,
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            f.request("POST", "/api/add-provider", Some(body), &f.admin)
                .await
                .status_code,
            Some(StatusCode::BAD_REQUEST)
        );
    }
    let p = f
        .create(
            "valid",
            "Payment",
            "Stripe",
            json!({"client_secret":"secret","metadata":{"webhook_secret":"hook"}}),
        )
        .await;
    let id = p["id"].as_str().unwrap();
    let before: Value = sqlx::query_scalar("SELECT to_jsonb(p) FROM providers p WHERE id=$1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    for patch in [
        json!({"user_mapping":{"unsupported":"id"},"display_name":"bad"}),
        json!({"http_headers":{"Bad\nName":"secret"},"display_name":"bad"}),
        json!({"metadata":{"webhook_secret":123},"display_name":"bad"}),
        json!({"metadata":{"webhook_secret":"***","webhookSecret":"conflict"},"display_name":"bad"}),
    ] {
        assert_eq!(
            f.request(
                "PUT",
                &format!("/api/providers/{id}"),
                Some(patch.clone()),
                &f.admin
            )
            .await
            .status_code,
            Some(StatusCode::BAD_REQUEST)
        );
        let after: Value = sqlx::query_scalar("SELECT to_jsonb(p) FROM providers p WHERE id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(after, before);
        assert_eq!(
            f.request(
                "POST",
                &format!("/api/update-provider?id={}/valid", f.owner),
                Some(patch),
                &f.admin
            )
            .await
            .status_code,
            Some(StatusCode::BAD_REQUEST)
        );
        let after: Value = sqlx::query_scalar("SELECT to_jsonb(p) FROM providers p WHERE id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(after, before);
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM providers WHERE owner=$1")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    // Stored secrets cannot become public merely by changing category/type.
    let telegram = f
        .create(
            "telegram",
            "Notification",
            "Telegram",
            json!({"client_id":"telegram-token-real","client_secret2":"secondary-private"}),
        )
        .await;
    let telegram_id = telegram["id"].as_str().unwrap();
    assert_eq!(telegram["client_id"], "***");
    f.ok(
        "PUT",
        &format!("/api/providers/{telegram_id}"),
        Some(telegram.clone()),
    )
    .await;
    assert_eq!(
        f.saved(telegram_id).await.client_id.as_deref(),
        Some("telegram-token-real")
    );
    let dangerous = json!({"category":"Email","type":"SMTP","host":"127.0.0.1","client_secret":"smtp-new","client_id2":"sender@example.test"});
    assert_eq!(
        f.request(
            "PUT",
            &format!("/api/providers/{telegram_id}"),
            Some(dangerous.clone()),
            &f.admin
        )
        .await
        .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/update-provider?id={}/telegram", f.owner),
            Some(dangerous),
            &f.admin
        )
        .await
        .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    assert_eq!(f.saved(telegram_id).await.category, "Notification");
    let public_email=f.ok("PUT",&format!("/api/providers/{telegram_id}"),Some(json!({"category":"Email","type":"SMTP","host":"127.0.0.1","client_id":"smtp-login","client_secret":"smtp-new","client_id2":"sender@example.test","client_secret2":"Public Sender"}))).await;
    assert_eq!(public_email["client_id"], "smtp-login");
    assert_eq!(public_email["client_secret2"], "Public Sender");
    assert!(!public_email.to_string().contains("telegram-token-real"));
    let wechat=f.create("wechat","OAuth","WeChat",json!({"client_id":"wechat-public","client_secret":"wechat-secret","content":"wechat-private"})).await;
    let wechat_id = wechat["id"].as_str().unwrap();
    assert_eq!(wechat["content"], "***");
    assert_eq!(
        f.request(
            "PUT",
            &format!("/api/providers/{wechat_id}"),
            Some(json!({"type":"Google"})),
            &f.admin
        )
        .await
        .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    f.ok(
        "PUT",
        &format!("/api/providers/{wechat_id}"),
        Some(json!({"type":"Google","content":""})),
    )
    .await;
    let opaque=f.create("opaque","OAuth","Google",json!({"client_id":"public-client","client_secret":"secret","metadata":{"base_dn":"hidden-secret"}})).await;
    let opaque_id = opaque["id"].as_str().unwrap();
    assert_eq!(opaque["metadata"], "***");
    assert_eq!(
        f.request(
            "PUT",
            &format!("/api/providers/{opaque_id}"),
            Some(json!({"category":"LDAP","type":"LDAP"})),
            &f.admin
        )
        .await
        .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    let public = f
        .ok(
            "PUT",
            &format!("/api/providers/{opaque_id}"),
            Some(json!({"category":"LDAP","type":"LDAP","metadata":{"base_dn":"public-DN"}})),
        )
        .await;
    assert_eq!(
        serde_json::from_str::<Value>(public["metadata"].as_str().unwrap()).unwrap(),
        json!({"base_dn":"public-DN"})
    );
    let fallback = f
        .create(
            "sendgrid-fallback",
            "Email",
            "SendGrid",
            json!({"client_id":"sendgrid-fallback-key","client_id2":"sender@example.test"}),
        )
        .await;
    let fallback_id = fallback["id"].as_str().unwrap();
    assert_eq!(fallback["client_id"], "***");
    f.ok(
        "PUT",
        &format!("/api/providers/{fallback_id}"),
        Some(fallback.clone()),
    )
    .await;
    assert_eq!(
        f.saved(fallback_id).await.client_id.as_deref(),
        Some("sendgrid-fallback-key")
    );
    let masked = f
        .ok(
            "GET",
            &format!("/api/get-provider?id={}/sendgrid-fallback", f.owner),
            None,
        )
        .await;
    assert_eq!(masked["data"]["clientId"], "***");
    assert_eq!(
        f.request(
            "PUT",
            &format!("/api/providers/{fallback_id}"),
            Some(json!({"client_secret":"new-primary"})),
            &f.admin
        )
        .await
        .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    let slack = f
        .create(
            "slack-fallback",
            "Notification",
            "Slack",
            json!({"client_id":"https://hooks.example.test/private-capability"}),
        )
        .await;
    assert_eq!(slack["client_id"], "***");
    f.ok(
        "PUT",
        &format!("/api/providers/{}", slack["id"].as_str().unwrap()),
        Some(slack.clone()),
    )
    .await;
    let oauth = f
        .create(
            "google-public",
            "OAuth",
            "Google",
            json!({"client_id":"ordinary-oauth-id","client_secret":"secret"}),
        )
        .await;
    assert_eq!(oauth["client_id"], "ordinary-oauth-id");
    let twilio=f.create("twilio-public","SMS","Twilio",json!({"client_id":"public-account-sid","client_secret":"auth-secret","app_id":"+15550123456"})).await;
    assert_eq!(twilio["client_id"], "public-account-sid");
    f.cleanup().await;
}

struct HttpFixture {
    url: String,
    requests: Arc<Mutex<Vec<(BTreeMap<String, String>, Value)>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl HttpFixture {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let received = requests.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let received = received.clone();
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
                        assert!(bytes.len() < 64 * 1024);
                    };
                    let head = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
                    let headers: BTreeMap<String, String> = head
                        .lines()
                        .skip(1)
                        .filter_map(|line| {
                            line.split_once(':')
                                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().into()))
                        })
                        .collect();
                    let length = headers
                        .get("content-length")
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    while bytes.len() - boundary < length {
                        let mut chunk = [0; 4096];
                        let n = socket.read(&mut chunk).await.unwrap();
                        assert!(n > 0);
                        bytes.extend_from_slice(&chunk[..n]);
                    }
                    let body: Value =
                        serde_json::from_slice(&bytes[boundary..boundary + length]).unwrap();
                    received.lock().unwrap().push((headers, body));
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
                });
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn native_notification_headers_mask_reorder_and_rotation_are_used_by_real_dispatch() {
    let f = Fixture::new().await;
    let http = HttpFixture::new().await;
    let provider=f.create("notify","Notification","Custom HTTP",json!({"endpoint":http.url,"receiver":"configured-target","metadata":[["X-One","one-real"],["X-Two","two-real"]]})).await;
    let id = provider["id"].as_str().unwrap();
    let path = format!("/api/providers/{id}");
    assert_eq!(
        serde_json::from_str::<Value>(provider["metadata"].as_str().unwrap()).unwrap(),
        json!([["X-One", "***"], ["X-Two", "***"]])
    );
    f.ok(
        "PUT",
        &path,
        Some(json!({"metadata":[["x-two","***"],["x-one","***"]]})),
    )
    .await;
    let dispatcher = ProviderDispatchService::new(f.pool.clone());
    dispatcher
        .send_notification(
            Some(&format!("{}/notify", f.owner)),
            None,
            &[],
            "Title",
            "Body",
        )
        .await
        .unwrap();
    {
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0["x-one"], "one-real");
        assert_eq!(requests[0].0["x-two"], "two-real");
        assert_eq!(requests[0].1["receiver"], "configured-target");
    }
    f.ok(
        "PUT",
        &path,
        Some(json!({"metadata":[["X-One","rotated-real"]]})),
    )
    .await;
    dispatcher
        .send_notification(
            Some(&format!("{}/notify", f.owner)),
            None,
            &[],
            "Title",
            "Again",
        )
        .await
        .unwrap();
    {
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests[1].0["x-one"], "rotated-real");
        assert!(!requests[1].0.contains_key("x-two"));
    }
    f.ok(
        "PUT",
        &path,
        Some(json!({"client_secret2":"[[\"X-Secondary\",\"secondary-real\"]]"})),
    )
    .await;
    let get = f.ok("GET", &path, None).await;
    assert_eq!(get["client_secret2"], "***");
    f.ok("PUT", &path, Some(get)).await;
    dispatcher
        .send_notification(
            Some(&format!("{}/notify", f.owner)),
            None,
            &[],
            "Title",
            "Secondary",
        )
        .await
        .unwrap();
    {
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests[2].0["x-secondary"], "secondary-real");
        assert!(!requests[2].0.contains_key("x-one"));
    }
    f.ok("PUT", &path, Some(json!({"client_secret2":""}))).await;
    dispatcher
        .send_notification(
            Some(&format!("{}/notify", f.owner)),
            None,
            &[],
            "Title",
            "Clear",
        )
        .await
        .unwrap();
    {
        let requests = http.requests.lock().unwrap();
        assert!(!requests[3].0.contains_key("x-secondary"));
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn native_sms_sender_receiver_and_credential_survive_masked_edits_and_real_http_dispatch() {
    let f = Fixture::new().await;
    let http = HttpFixture::new().await;
    let provider=f.create("sms","SMS","Custom HTTP",json!({"endpoint":http.url,"client_secret":"sms-real","app_id":"ActualBrand","sign_name":"FallbackBrand","receiver":"+15550123456"})).await;
    let id = provider["id"].as_str().unwrap();
    assert_eq!(provider["app_id"], "ActualBrand");
    assert_eq!(provider["sign_name"], "FallbackBrand");
    f.ok(
        "PUT",
        &format!("/api/providers/{id}"),
        Some(provider.clone()),
    )
    .await;
    ProviderDispatchService::new(f.pool.clone())
        .send_sms_with_provider(&f.saved(id).await, &[], "SMS body")
        .await
        .unwrap();
    {
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0["authorization"], "Bearer sms-real");
        assert_eq!(
            requests[0].1,
            json!({"to":"+15550123456","from":"ActualBrand","body":"SMS body"})
        );
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn smtp_native_sender_name_address_disable_ssl_and_auth_are_consumed_on_wire() {
    use base64::Engine as _;
    let f = Fixture::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new((Vec::<String>::new(), String::new())));
    let capture = received.clone();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (read, mut write) = socket.into_split();
        let mut reader = BufReader::new(read);
        write.write_all(b"220 fixture ESMTP\r\n").await.unwrap();
        let mut login = 0;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let command = line.trim_end();
            if login > 0 {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(command)
                    .unwrap();
                capture
                    .lock()
                    .unwrap()
                    .0
                    .push(String::from_utf8(decoded).unwrap());
                if login == 1 {
                    login = 2;
                    write.write_all(b"334 UGFzc3dvcmQ6\r\n").await.unwrap();
                } else {
                    login = 0;
                    write
                        .write_all(b"235 Authentication successful\r\n")
                        .await
                        .unwrap();
                }
                continue;
            }
            if command.starts_with("EHLO") {
                write
                    .write_all(b"250-fixture\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1000000\r\n")
                    .await
                    .unwrap();
            } else if command.starts_with("AUTH PLAIN ") {
                let data = base64::engine::general_purpose::STANDARD
                    .decode(command.trim_start_matches("AUTH PLAIN "))
                    .unwrap();
                capture
                    .lock()
                    .unwrap()
                    .0
                    .push(String::from_utf8(data).unwrap());
                write
                    .write_all(b"235 Authentication successful\r\n")
                    .await
                    .unwrap();
            } else if command == "AUTH LOGIN" {
                login = 1;
                write.write_all(b"334 VXNlcm5hbWU6\r\n").await.unwrap();
            } else if command == "AUTH PLAIN" {
                login = 3;
                write.write_all(b"334 \r\n").await.unwrap();
            } else if command == "DATA" {
                write.write_all(b"354 End data\r\n").await.unwrap();
                loop {
                    let mut data = String::new();
                    reader.read_line(&mut data).await.unwrap();
                    if data == ".\r\n" {
                        break;
                    }
                    capture.lock().unwrap().1.push_str(&data);
                }
                write.write_all(b"250 Queued\r\n").await.unwrap();
            } else if command == "QUIT" {
                write.write_all(b"221 Bye\r\n").await.unwrap();
                break;
            } else {
                assert!(
                    command.starts_with("MAIL FROM:")
                        || command.starts_with("RCPT TO:")
                        || command == "RSET",
                    "{command}"
                );
                write.write_all(b"250 OK\r\n").await.unwrap();
            }
        }
    });
    let provider=f.create("smtp","Email","SMTP",json!({"host":"127.0.0.1","port":port,"disable_ssl":true,"client_id":"login-user","client_secret":"smtp-real","client_id2":"source@example.test","client_secret2":"Display Sender","receiver":"recipient@example.test"})).await;
    let id = provider["id"].as_str().unwrap();
    assert_eq!(provider["client_secret2"], "Display Sender");
    assert_eq!(provider["disable_ssl"], true);
    f.ok(
        "PUT",
        &format!("/api/providers/{id}"),
        Some(provider.clone()),
    )
    .await;
    ProviderDispatchService::new(f.pool.clone())
        .send_email_with_provider(&f.saved(id).await, &[], "Email Subject", "Hello", None)
        .await
        .unwrap();
    {
        let capture = received.lock().unwrap();
        assert!(capture.0.join("|").contains("login-user"));
        assert!(capture.0.join("|").contains("smtp-real"));
        assert!(
            capture.1.lines().any(|line| line.starts_with("From:")
                && line.contains("Display Sender")
                && line.contains("source@example.test")),
            "{}",
            capture.1
        );
        assert!(capture.1.contains("To: recipient@example.test"));
    }
    for invalid in [
        json!({"client_secret2":"bad\r\nBcc: stolen@example.test"}),
        json!({"client_id2":"bad\naddress"}),
        json!({"port":70000}),
    ] {
        assert_eq!(
            f.request(
                "PUT",
                &format!("/api/providers/{id}"),
                Some(invalid),
                &f.admin
            )
            .await
            .status_code,
            Some(StatusCode::BAD_REQUEST)
        );
        let saved = f.saved(id).await;
        assert_eq!(saved.client_secret2.as_deref(), Some("Display Sender"));
        assert_eq!(saved.port, Some(i32::from(port)));
    }
    task.abort();
    // Default SMTP on a submission-style port must negotiate STARTTLS rather
    // than speaking implicit TLS or sending AUTH/DATA on the clear connection.
    // The compatibility flag still upgrades when advertised; with no STARTTLS,
    // only the explicit compatibility case tested above may send plaintext.
    for (disable_ssl, advertise_starttls) in [(false, true), (true, true), (false, false)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_port = listener.local_addr().unwrap().port();
        assert_ne!(tls_port, 465);
        let transcript = Arc::new(Mutex::new(Vec::<u8>::new()));
        let captured = transcript.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (read, mut write) = socket.into_split();
            let mut reader = BufReader::new(read);
            write.write_all(b"220 fixture ESMTP\r\n").await.unwrap();
            let mut ehlo = String::new();
            reader.read_line(&mut ehlo).await.unwrap();
            assert!(
                ehlo.starts_with("EHLO "),
                "Expected clear EHLO before STARTTLS, got {ehlo:?}"
            );
            captured.lock().unwrap().extend_from_slice(ehlo.as_bytes());
            write
                .write_all(if advertise_starttls {
                    b"250-fixture\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n"
                } else {
                    b"250-fixture\r\n250 AUTH PLAIN LOGIN\r\n"
                })
                .await
                .unwrap();
            if advertise_starttls {
                let mut command = String::new();
                reader.read_line(&mut command).await.unwrap();
                captured
                    .lock()
                    .unwrap()
                    .extend_from_slice(command.as_bytes());
                assert_eq!(command, "STARTTLS\r\n");
                write.write_all(b"220 Begin TLS\r\n").await.unwrap();
                let mut hello = [0; 4096];
                let count = reader.read(&mut hello).await.unwrap();
                assert!(count > 0);
                assert_eq!(hello[0], 0x16, "Client must send a TLS handshake record");
                captured.lock().unwrap().extend_from_slice(&hello[..count]);
                // Fail the actual TLS handshake. No insecure verifier or fake
                // success can advance the client to credentials or DATA.
                write.write_all(b"not-a-valid-TLS-record").await.unwrap();
                write.shutdown().await.unwrap();
            } else {
                let mut command = Vec::new();
                reader.read_to_end(&mut command).await.unwrap();
                captured.lock().unwrap().extend_from_slice(&command);
            }
        });
        let name = format!("tls-{disable_ssl}-{advertise_starttls}");
        let config=f.create(&name,"Email","SMTP",json!({"host":"127.0.0.1","port":tls_port,"disable_ssl":disable_ssl,"client_id":"tls-user","client_secret":"must-stay-encrypted","client_id2":"sender@example.test","receiver":"recipient@example.test"})).await;
        let record = f.saved(config["id"].as_str().unwrap()).await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ProviderDispatchService::new(f.pool.clone()).send_email_with_provider(
                &record,
                &[],
                "TLS subject",
                "must-not-leak-message",
                None,
            ),
        )
        .await
        .expect("TLS failure must finish promptly");
        assert!(result.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        let transcript = transcript.lock().unwrap();
        for forbidden in [
            b"AUTH ".as_slice(),
            b"DATA\r\n".as_slice(),
            b"must-stay-encrypted".as_slice(),
            b"must-not-leak-message".as_slice(),
        ] {
            assert!(
                !transcript
                    .windows(forbidden.len())
                    .any(|part| part == forbidden),
                "Credentials or message leaked before TLS"
            );
        }
    }
    let http = HttpFixture::new().await;
    let sendgrid=f.create("sendgrid","Email","SendGrid",json!({"client_id":"api-user","client_secret":"sendgrid-real","client_id2":"sendgrid-source@example.test","client_secret2":"SendGrid Display"})).await;
    let record = f.saved(sendgrid["id"].as_str().unwrap()).await;
    let sender =
        casdog::services::provider_configuration_service::email_sender(&record, None).unwrap();
    use casdog::services::providers::{EmailProviderTrait, email_extra::SendGridEmailProvider};
    SendGridEmailProvider::from_provider_record(
        record.client_secret.as_deref().unwrap(),
        &sender.email.to_string(),
    )
    .with_sender(&sender)
    .with_api_url(&http.url)
    .unwrap()
    .send_email("recipient@example.test", "SendGrid subject", "Message")
    .await
    .unwrap();
    {
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests[0].0["authorization"], "Bearer sendgrid-real");
        assert_eq!(
            requests[0].1["from"],
            json!({"email":"sendgrid-source@example.test","name":"SendGrid Display"})
        );
    }
    f.cleanup().await;
}
