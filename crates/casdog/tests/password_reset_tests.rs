//! Real PostgreSQL recovery tests. Mail is captured by an ephemeral loopback server.
//! Run with CASDOG_TEST_DATABASE_URL and `--ignored`; no external mail is sent.
use casdog::services::{
    PasswordService,
    password_reset_service::{CompletePasswordReset, PasswordResetService, RequestPasswordReset},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
    task::JoinHandle,
};
use uuid::Uuid;

struct Fixture {
    pool: PgPool,
    owner: String,
    user: String,
    email: String,
    source: String,
    mail: mpsc::Receiver<Value>,
    server: JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Self {
        let url =
            std::env::var("CASDOG_TEST_DATABASE_URL").expect("Set disposable test database URL");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();
        let owner = format!("reset-{}", Uuid::new_v4());
        let user = Uuid::new_v4().to_string();
        let email = format!("{user}@example.test");
        let source = Uuid::new_v4().to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mail", listener.local_addr().unwrap());
        let (sender, mail) = mpsc::channel(32);
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let (header_end, content_length) = loop {
                    let count = socket.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        break (end + 4, length);
                    }
                };
                while bytes.len() < header_end + content_length {
                    let count = socket.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                }
                let payload =
                    serde_json::from_slice(&bytes[header_end..header_end + content_length])
                        .unwrap();
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
                sender.send(payload).await.unwrap();
            }
        });
        sqlx::query("INSERT INTO organizations (id,owner,name,display_name,password_options) VALUES ($1,$2,$2,'Reset test',$3)")
            .bind(Uuid::new_v4().to_string()).bind(&owner).bind(json!(["AtLeast8", "Aa", "AtLeastOneDigit"])).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users (id,owner,name,display_name,password_hash,email,password_type,password_salt,need_update_password,signin_wrong_times) VALUES ($1,$2,'alice','Alice','old-hash',$3,'bcrypt','old-salt',true,3)")
            .bind(&user).bind(&owner).bind(&email).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO providers (id,owner,name,display_name,category,type,endpoint) VALUES ($1,$2,'mail','Mail','Email','Custom HTTP',$3)")
            .bind(Uuid::new_v4().to_string()).bind(&owner).bind(endpoint).execute(&pool).await.unwrap();
        Self {
            pool,
            owner,
            user,
            email,
            source,
            mail,
            server,
        }
    }

    fn request_payload(&self, app: Option<String>) -> RequestPasswordReset {
        RequestPasswordReset {
            organization: self.owner.clone(),
            email: self.email.clone(),
            application: app,
        }
    }

    fn complete_payload(&self, id: &str, code: &str, app: Option<String>) -> CompletePasswordReset {
        CompletePasswordReset {
            organization: self.owner.clone(),
            email: self.email.clone(),
            application: app,
            request_id: id.into(),
            code: code.into(),
            new_password: "Recovered42!".into(),
        }
    }

    async fn request(&mut self, app: Option<String>) -> (String, String) {
        let receipt =
            PasswordResetService::request(&self.pool, self.request_payload(app), &self.source)
                .await
                .unwrap();
        let mail = tokio::time::timeout(std::time::Duration::from_secs(10), self.mail.recv())
            .await
            .expect("Local mail was not dispatched")
            .unwrap();
        let body = mail["body"].as_str().unwrap();
        let token = body.lines().nth(1).unwrap().to_string();
        assert_eq!(token.len(), 43);
        assert_eq!(mail["to"], self.email);
        let response = serde_json::to_string(&receipt).unwrap();
        assert!(!response.contains(&token));
        (receipt.request_id, token)
    }

    async fn application(&self, name: &str) -> String {
        let id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO applications (id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password,providers) VALUES ($1,$2,$3,$3,$2,$1,'test','[]',true,$4)")
            .bind(&id).bind(&self.owner).bind(name).bind(json!([{"name":format!("{}/mail",self.owner),"rule":"Forget"}])).execute(&self.pool).await.unwrap();
        id
    }

    async fn cleanup(self) {
        self.server.abort();
        for table in [
            "password_reset_requests",
            "sessions",
            "tokens",
            "applications",
            "providers",
            "users",
            "organizations",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner = $1"))
                .bind(&self.owner)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        self.pool.close().await;
    }
}

#[test]
fn password_reset_contract_accepts_camel_case_aliases() {
    let request: RequestPasswordReset =
        serde_json::from_value(json!({"owner":"org","email":"alice@example.test"})).unwrap();
    assert_eq!(request.organization, "org");
    let complete: CompletePasswordReset = serde_json::from_value(json!({"organization":"org","email":"alice@example.test","requestId":"id","code":"secret","newPassword":"New42pass"})).unwrap();
    assert_eq!(complete.request_id, "id");
    assert_eq!(complete.new_password, "New42pass");
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-016"]
async fn reset_dispatch_policy_hash_and_atomic_session_revocation() {
    let mut f = Fixture::new().await;
    casdog::config::AppConfig::load().unwrap();
    let diesel = casdog::diesel_pool::create_diesel_pool(
        &std::env::var("CASDOG_TEST_DATABASE_URL").unwrap(),
    )
    .await
    .unwrap();
    let users = casdog::services::UserService::new(diesel.clone());
    let old_token = casdog::services::AuthService::new(users.clone())
        .generate_token(&users.get_by_id(&f.user).await.unwrap())
        .unwrap();
    let service = salvo::Service::new(casdog::routes::create_router()).hoop(
        salvo::affix_state::AffixList::new()
            .inject(f.pool.clone())
            .inject(diesel),
    );
    use salvo::test::{ResponseExt, TestClient};
    let before = TestClient::get("http://localhost/api/get-account")
        .add_header("Authorization", format!("Bearer {old_token}"), true)
        .send(&service)
        .await;
    assert_eq!(before.status_code, Some(salvo::http::StatusCode::OK));
    let (id, code) = f.request(None).await;
    let hash: String =
        sqlx::query_scalar("SELECT token_hash FROM password_reset_requests WHERE id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_ne!(hash, code);
    assert_eq!(hash.len(), 64);
    let mut weak = f.complete_payload(&id, &code, None);
    weak.new_password = "weak".into();
    assert!(PasswordResetService::complete(&f.pool, weak).await.is_err());
    sqlx::query("INSERT INTO sessions (id,owner,name,application,user_id,session_id) VALUES ($1,$2,'old-session','app',$3,'session')")
        .bind(Uuid::new_v4().to_string()).bind(&f.owner).bind(&f.user).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO tokens (id,owner,name,application,organization,user_id,access_token,refresh_token) VALUES ($1,$2,'old-token','app',$2,$3,'old-access','old-refresh')")
        .bind(Uuid::new_v4().to_string()).bind(&f.owner).bind(&f.user).execute(&f.pool).await.unwrap();
    let reset = TestClient::post("http://localhost/api/reset-password").json(&json!({"organization":f.owner,"email":f.email,"requestId":id,"code":code,"newPassword":"Recovered42!"})).send(&service).await;
    assert_eq!(reset.status_code, Some(salvo::http::StatusCode::OK));
    let stale = TestClient::get("http://localhost/api/get-account")
        .add_header("Authorization", format!("Bearer {old_token}"), true)
        .send(&service)
        .await;
    assert_eq!(
        stale.status_code,
        Some(salvo::http::StatusCode::UNAUTHORIZED)
    );
    let mut login = TestClient::post("http://localhost/api/login")
        .json(&json!({"owner":f.owner,"name":"alice","password":"Recovered42!"}))
        .send(&service)
        .await;
    assert_eq!(login.status_code, Some(salvo::http::StatusCode::OK));
    let signed_in: Value = login.take_json().await.unwrap();
    let account = TestClient::get("http://localhost/api/get-account")
        .add_header(
            "Authorization",
            format!("Bearer {}", signed_in["token"].as_str().unwrap()),
            true,
        )
        .send(&service)
        .await;
    assert_eq!(account.status_code, Some(salvo::http::StatusCode::OK));
    let (hash, kind, salt, changed, update, wrong): (String, String, Option<String>, Option<String>, bool, i32) = sqlx::query_as("SELECT password_hash,password_type,password_salt,last_change_password_time,need_update_password,signin_wrong_times FROM users WHERE id=$1")
        .bind(&f.user).fetch_one(&f.pool).await.unwrap();
    assert!(
        PasswordService::verify_password("Recovered42!", &hash, &kind, salt.as_deref()).unwrap()
    );
    assert_eq!(kind, "argon2");
    assert!(salt.is_none());
    assert!(changed.is_some());
    assert!(!update);
    assert_eq!(wrong, 0);
    for table in ["tokens", "sessions"] {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE user_id=$1"))
                .bind(&f.user)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
    }
    assert!(
        PasswordResetService::complete(&f.pool, f.complete_payload(&id, &code, None))
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-016"]
async fn reset_rejects_wrong_tenant_email_application_and_expired_codes() {
    let mut f = Fixture::new().await;
    let app = f.application("app-a").await;
    let other = f.application("app-b").await;
    let (id, code) = f.request(Some(app.clone())).await;
    let mut cross_tenant = f.complete_payload(&id, &code, Some(app.clone()));
    cross_tenant.organization = "another-tenant".into();
    assert!(
        PasswordResetService::complete(&f.pool, cross_tenant)
            .await
            .is_err()
    );
    let mut cross_email = f.complete_payload(&id, &code, Some(app.clone()));
    cross_email.email = "another@example.test".into();
    assert!(
        PasswordResetService::complete(&f.pool, cross_email)
            .await
            .is_err()
    );
    assert!(
        PasswordResetService::complete(&f.pool, f.complete_payload(&id, &code, Some(other)))
            .await
            .is_err()
    );
    assert!(
        PasswordResetService::complete(&f.pool, f.complete_payload(&id, &code, None))
            .await
            .is_err()
    );
    sqlx::query(
        "UPDATE password_reset_requests SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",
    )
    .bind(&id)
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(
        PasswordResetService::complete(&f.pool, f.complete_payload(&id, &code, Some(app.clone())))
            .await
            .is_err()
    );
    sqlx::query(
        "UPDATE password_reset_requests SET expires_at=NOW()+INTERVAL '1 minute' WHERE id=$1",
    )
    .bind(&id)
    .execute(&f.pool)
    .await
    .unwrap();
    PasswordResetService::complete(&f.pool, f.complete_payload(&id, &code, Some(app)))
        .await
        .unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-016"]
async fn reset_limits_guessing_and_resends_and_hides_unknown_users() {
    let mut f = Fixture::new().await;
    let (id, code) = f.request(None).await;
    let repeated = PasswordResetService::request(&f.pool, f.request_payload(None), &f.source)
        .await
        .unwrap();
    assert_eq!(repeated.request_id, id);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), f.mail.recv())
            .await
            .is_err()
    );
    for _ in 0..5 {
        assert!(
            PasswordResetService::complete(&f.pool, f.complete_payload(&id, "wrong", None))
                .await
                .is_err()
        );
    }
    assert!(
        PasswordResetService::complete(&f.pool, f.complete_payload(&id, &code, None))
            .await
            .is_err()
    );
    let mut unknown = f.request_payload(None);
    unknown.email = "unknown@example.test".into();
    let receipt = PasswordResetService::request(&f.pool, unknown, &f.source)
        .await
        .unwrap();
    assert_eq!(receipt.msg, repeated.msg);
    assert_eq!(receipt.status, repeated.status);
    assert_eq!(receipt.expires_in, repeated.expires_in);
    let principal: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM password_reset_requests WHERE id=$1")
            .bind(receipt.request_id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(principal.is_none());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), f.mail.recv())
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-016"]
async fn reset_concurrent_consume_has_exactly_one_winner() {
    let mut f = Fixture::new().await;
    let (id, code) = f.request(None).await;
    let first = f.complete_payload(&id, &code, None);
    let second = f.complete_payload(&id, &code, None);
    let (a, b) = tokio::join!(
        PasswordResetService::complete(&f.pool, first),
        PasswordResetService::complete(&f.pool, second)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    f.cleanup().await;
}
