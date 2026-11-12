//! Real authenticated APIs and shared database state for private OAuth grants.
use casdog::{
    config::AppConfig, diesel_pool::create_diesel_pool, error::AppError, hoops::authz::Principal,
    models::Provider, services::provider_network_service,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{Arc, Once};

struct Fixture {
    pool: PgPool,
    service: Arc<Service>,
    owner: String,
    global: String,
    tenant: String,
    member: String,
    users: Vec<String>,
}
impl Fixture {
    async fn new() -> Self {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            AppConfig::load().unwrap();
        });
        let url = std::env::var("CASDOG_TEST_DATABASE_URL")
            .expect("Migrated disposable PostgreSQL required");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let owner = format!("network-{}", uuid::Uuid::new_v4());
        for name in ["built-in", &owner] {
            sqlx::query("INSERT INTO organizations(id,owner,name,display_name) SELECT $1,'admin',$2,$2 WHERE NOT EXISTS(SELECT 1 FROM organizations WHERE name=$2)")
                .bind(uuid::Uuid::new_v4().to_string()).bind(name).execute(&pool).await.unwrap();
        }
        let mut users = Vec::new();
        let mut tokens = Vec::new();
        for (organization, admin) in [
            ("built-in", true),
            (owner.as_str(), true),
            (owner.as_str(), false),
        ] {
            let id = uuid::Uuid::new_v4().to_string();
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$1,$1,'unused',$3)")
                .bind(&id).bind(organization).bind(admin).execute(&pool).await.unwrap();
            tokens.push(token(&id, organization, admin));
            users.push(id);
        }
        let service = Arc::new(
            Service::new(casdog::routes::create_router()).hoop(
                salvo::affix_state::AffixList::new()
                    .inject(pool.clone())
                    .inject(create_diesel_pool(&url).await.unwrap()),
            ),
        );
        Self {
            pool,
            service,
            owner,
            global: tokens[0].clone(),
            tenant: tokens[1].clone(),
            member: tokens[2].clone(),
            users,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Response {
        let url = format!("http://localhost{path}");
        let mut request = match method {
            "GET" => TestClient::get(url),
            "POST" => TestClient::post(url),
            "PUT" => TestClient::put(url),
            "DELETE" => TestClient::delete(url),
            _ => unreachable!(),
        };
        if let Some(token) = token {
            request = request.add_header("Authorization", format!("Bearer {token}"), true);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        request.send(&*self.service).await
    }
    async fn json(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> Value {
        let mut response = self.request(method, path, Some(token), body).await;
        let status = response.status_code;
        let value: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{value}");
        value
    }
    async fn provider(&self) -> String {
        let result = self
            .json(
                "POST",
                "/api/providers",
                &self.global,
                Some(json!({
                    "owner":self.owner,"name":format!("custom-{}",uuid::Uuid::new_v4()),
                    "display_name":"Custom intranet identity","category":"OAuth","type":"Custom",
                    "client_id":"test-client","client_secret":"test-secret",
                    "custom_auth_url":"http://127.0.0.1:9/authorize",
                    "custom_token_url":"http://127.0.0.1:9/token",
                    "custom_user_info_url":"http://127.0.0.1:9/userinfo","scopes":"openid profile",
                    "metadata":"{\"allow_private\":true,\"networkApproval\":true}"
                })),
            )
            .await;
        result["id"].as_str().unwrap().into()
    }
    fn actor(&self) -> Principal {
        Principal {
            id: self.users[0].clone(),
            owner: "built-in".into(),
            name: self.users[0].clone(),
            admin: true,
            application_identity: false,
        }
    }
    async fn cleanup(self) {
        sqlx::query("DELETE FROM providers WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        for id in &self.users {
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
    }
}
fn token(id: &str, owner: &str, admin: bool) -> String {
    let now = chrono::Utc::now();
    encode(&Header::default(), &json!({"sub":id,"owner":owner,"name":id,"is_admin":admin,
        "exp":now.timestamp()+3600,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"iss":AppConfig::get().jwt.issuer}),
        &EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
}

#[tokio::test]
async fn checked_ipv6_transport_supports_literals_without_relaxing_private_network_policy() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let url = reqwest::Url::parse(&format!(
        "http://[::1]:{}/probe",
        listener.local_addr().unwrap().port()
    ))
    .unwrap();
    assert!(matches!(
        casdog::services::system_gap_service::client(&url, false).await,
        Err(AppError::Authorization(_))
    ));
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut bytes = [0; 1024];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let n = socket.read(&mut bytes).await.unwrap();
            assert!(n > 0 && request.len() + n <= 8192);
            request.extend_from_slice(&bytes[..n]);
        }
        assert!(request.starts_with(b"GET /probe HTTP/1.1\r\n"));
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nipv6 fixture",
            )
            .await
            .unwrap();
    });
    let client = casdog::services::system_gap_service::client(&url, true)
        .await
        .unwrap();
    let response = client.get(url).send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "ipv6 fixture");
    server.await.unwrap();
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn private_oauth_approval_is_explicit_global_only_stamped_and_revocable() {
    let f = Fixture::new().await;
    let id = f.provider().await;
    let path = format!("/api/providers/{id}/network-approval");
    for method in ["GET", "POST", "DELETE"] {
        let body = (method == "POST").then(|| json!({"allow_private":true}));
        assert_eq!(
            f.request(method, &path, None, body.clone())
                .await
                .status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
        for actor in [&f.tenant, &f.member] {
            assert_eq!(
                f.request(method, &path, Some(actor), body.clone())
                    .await
                    .status_code,
                Some(StatusCode::FORBIDDEN)
            );
        }
    }
    let status = f.json("GET", &path, &f.global, None).await;
    assert_eq!(
        status["allow_private"], false,
        "Creating even global-owned configuration must not auto-grant private access"
    );
    assert_eq!(status["stale"], false);
    for invalid in [
        json!({}),
        json!({"allow_private":false}),
        json!({"allow_private":true,"approved_by":"forged"}),
    ] {
        assert_eq!(
            f.request("POST", &path, Some(&f.global), Some(invalid))
                .await
                .status_code,
            Some(StatusCode::BAD_REQUEST)
        );
    }
    let mut granted = f
        .request(
            "POST",
            &path,
            Some(&f.global),
            Some(json!({"allow_private":true})),
        )
        .await;
    assert_eq!(granted.status_code, Some(StatusCode::OK));
    assert_eq!(granted.headers().get("cache-control").unwrap(), "no-store");
    let grant: Value = granted.take_json().await.unwrap();
    assert_eq!(grant["allow_private"], true);
    assert_eq!(grant["approved_by"], f.users[0]);
    let first: String = sqlx::query_scalar(
        "SELECT generation FROM oauth_provider_network_approvals WHERE provider_id=$1",
    )
    .bind(&id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    f.json(
        "POST",
        &path,
        &f.global,
        Some(json!({"allow_private":true})),
    )
    .await;
    let second: String = sqlx::query_scalar(
        "SELECT generation FROM oauth_provider_network_approvals WHERE provider_id=$1",
    )
    .bind(&id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_ne!(
        first, second,
        "Every approval must get a distinct grant generation even with identical configuration"
    );
    uuid::Uuid::parse_str(&second).unwrap();
    f.json(
        "PUT",
        &format!("/api/providers/{id}"),
        &f.tenant,
        Some(json!({"scopes":"openid email"})),
    )
    .await;
    let stale = f.json("GET", &path, &f.global, None).await;
    assert_eq!(stale["allow_private"], false);
    assert_eq!(stale["stale"], true);
    let record: Provider = sqlx::query_as("SELECT * FROM providers WHERE id=$1")
        .bind(&id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(
        !provider_network_service::allowed_conn(&mut *f.pool.acquire().await.unwrap(), &record)
            .await
            .unwrap()
    );
    f.json(
        "POST",
        &path,
        &f.global,
        Some(json!({"allow_private":true})),
    )
    .await;
    assert!(
        provider_network_service::allowed_conn(&mut *f.pool.acquire().await.unwrap(), &record)
            .await
            .unwrap()
    );
    let revoked = f.json("DELETE", &path, &f.global, None).await;
    assert_eq!(revoked["allow_private"], false);
    assert!(
        !provider_network_service::allowed_conn(&mut *f.pool.acquire().await.unwrap(), &record)
            .await
            .unwrap()
    );
    let okta = f.json("POST","/api/providers",&f.global,Some(json!({
        "owner":f.owner,"name":format!("okta-{}",uuid::Uuid::new_v4()),"display_name":"Custom Okta issuer",
        "category":"OAuth","type":"Okta","client_id":"client","client_secret":"secret",
        "domain":"https://identity.example.test/oauth2/default"
    }))).await;
    let okta_path = format!(
        "/api/providers/{}/network-approval",
        okta["id"].as_str().unwrap()
    );
    assert_eq!(
        f.json(
            "POST",
            &okta_path,
            &f.global,
            Some(json!({"allow_private":true}))
        )
        .await["allow_private"],
        true,
        "Upstream Okta issuer configuration does not require three Generic OAuth endpoint fields"
    );
    assert_eq!(
        f.request(
            "DELETE",
            &format!("/api/providers/{id}"),
            Some(&f.global),
            None
        )
        .await
        .status_code,
        Some(StatusCode::NO_CONTENT)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oauth_provider_network_approvals WHERE provider_id=$1"
        )
        .bind(&id)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn private_oauth_approval_rechecks_current_real_global_administrator() {
    let f = Fixture::new().await;
    let id = f.provider().await;
    let path = format!("/api/providers/{id}/network-approval");
    // A tenant named "admin" is still a tenant. Namespace spelling is never
    // evidence that its administrator can approve arbitrary private requests.
    let existed: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name='admin')")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    if !existed {
        f.json(
            "POST",
            "/api/organizations",
            &f.global,
            Some(json!({"owner":"admin","name":"admin","display_name":"Ordinary named tenant"})),
        )
        .await;
    }
    let named_admin = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,'admin',$1,$1,'unused',true)")
        .bind(&named_admin).execute(&f.pool).await.unwrap();
    let named_token = token(&named_admin, "admin", true);
    let owned = f.json("POST","/api/providers",&named_token,Some(json!({
        "owner":"admin","name":format!("named-tenant-{}",uuid::Uuid::new_v4()),"display_name":"Ordinary tenant IdP","category":"OAuth","type":"Custom",
        "client_id":"client","client_secret":"secret","custom_auth_url":"http://127.0.0.1:9/authorize",
        "custom_token_url":"http://127.0.0.1:9/token","custom_user_info_url":"http://127.0.0.1:9/userinfo"
    }))).await;
    let owned_id = owned["id"].as_str().unwrap();
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/providers/{owned_id}/network-approval"),
            Some(&named_token),
            Some(json!({"allow_private":true}))
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oauth_provider_network_approvals WHERE provider_id=$1"
        )
        .bind(owned_id)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        0
    );
    sqlx::query("DELETE FROM providers WHERE id=$1")
        .bind(owned_id)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(&named_admin)
        .execute(&f.pool)
        .await
        .unwrap();
    if !existed {
        sqlx::query("DELETE FROM organizations WHERE name='admin'")
            .execute(&f.pool)
            .await
            .unwrap();
    }
    let mut application = f.actor();
    application.application_identity = true;
    assert!(matches!(
        provider_network_service::approve(&f.pool, &application, &id).await,
        Err(AppError::Authorization(_))
    ));
    sqlx::query("UPDATE users SET is_admin=false WHERE id=$1")
        .bind(&f.users[0])
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.request(
            "POST",
            &path,
            Some(&f.global),
            Some(json!({"allow_private":true}))
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert!(matches!(
        provider_network_service::approve(&f.pool, &f.actor(), &id).await,
        Err(AppError::Authorization(_))
    ));
    sqlx::query("UPDATE users SET is_admin=true,is_forbidden=true WHERE id=$1")
        .bind(&f.users[0])
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        provider_network_service::approve(&f.pool, &f.actor(), &id).await,
        Err(AppError::Authorization(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oauth_provider_network_approvals WHERE provider_id=$1"
        )
        .bind(&id)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        0
    );
    f.cleanup().await;
}
