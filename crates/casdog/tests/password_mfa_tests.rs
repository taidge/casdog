//! Real PostgreSQL password-first MFA regressions (migration 020).
#[path = "support/provider_network.rs"]
mod fixture_network;
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    handlers::password_mfa,
    services::{PasswordService, social_state_service::proof_hash},
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
    task::JoinHandle,
};
struct Fixture {
    pool: PgPool,
    other_pool: PgPool,
    service: Service,
    other: Service,
    owner: String,
    user: String,
    app: String,
    mail: mpsc::Receiver<Value>,
    server: JoinHandle<()>,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let other_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let router = || {
            Router::new()
                .push(Router::with_path("api/login").post(password_mfa::login))
                .push(
                    Router::with_path("api/auth/password/session")
                        .post(password_mfa::consume_password_session)
                        .push(
                            Router::with_path("send-code")
                                .post(password_mfa::send_password_mfa_code),
                        )
                        .push(
                            Router::with_path("cancel").post(password_mfa::cancel_password_session),
                        ),
                )
        };
        let service = Service::new(router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel.clone()),
        );
        let other = Service::new(router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(other_pool.clone())
                .inject(diesel),
        );
        let owner = format!("pw-mfa-{}", uuid::Uuid::new_v4());
        let user = uuid::Uuid::new_v4().to_string();
        let app = uuid::Uuid::new_v4().to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mail", listener.local_addr().unwrap());
        let (sender, mail) = mpsc::channel::<Value>(10);
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let (start, length) = loop {
                    let n = socket.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let h = String::from_utf8_lossy(&bytes[..end]);
                        let len = h
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        break (end + 4, len);
                    }
                };
                while bytes.len() < start + length {
                    let n = socket.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                }
                let payload = serde_json::from_slice(&bytes[start..start + length]).unwrap();
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
                sender.send(payload).await.unwrap();
            }
        });
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Password MFA')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        let hash = PasswordService::hash_password("ValidPassword42!", "bcrypt", None).unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type,email,mfa_email_enabled) VALUES($1,$2,'alice','Alice',$3,'bcrypt','alice@example.test',true)")
        .bind(&user).bind(&owner).bind(hash).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,endpoint) VALUES($1,$2,'mail','Mail','Email','Custom HTTP',$3)")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&owner).bind(endpoint).execute(&pool).await.unwrap();
        fixture_network::approve_owner(&pool, &owner).await;
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password,providers,grant_types) VALUES($1,$2,'app','App',$2,$1,'secret','https://example.test/callback',true,$3,$4)")
        .bind(&app).bind(&owner).bind(json!([{"name":format!("{owner}/mail"),"rule":"mfa"}])).bind(json!(["authorization_code"])).execute(&pool).await.unwrap();
        Self {
            pool,
            other_pool,
            service,
            other,
            owner,
            user,
            app,
            mail,
            server,
        }
    }
    fn login_body(&self) -> Value {
        json!({"owner":self.owner,"name":"alice","password":"ValidPassword42!","application":format!("{}/app",self.owner)})
    }
    async fn start_body(&self, body: Value) -> Response {
        TestClient::post("http://localhost/api/login")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&body)
            .send(&self.service)
            .await
    }
    async fn begin(&self) -> String {
        let mut response = self.start_body(self.login_body()).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let proof = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("casdog_password_mfa=")
            .unwrap()
            .to_string();
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(body["mfa_required"], true);
        assert_eq!(body["token"], "");
        assert!(!body.to_string().contains(&proof));
        proof
    }
    async fn call(service: &Service, proof: &str, suffix: &str, body: Value) -> Response {
        TestClient::post(format!(
            "http://localhost/api/auth/password/session{suffix}"
        ))
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .add_header("Cookie", format!("casdog_password_mfa={proof}"), true)
        .json(&body)
        .send(service)
        .await
    }
    async fn send(&mut self, proof: &str) -> String {
        let mut response = Self::call(
            &self.service,
            proof,
            "/send-code",
            json!({"mfaType":"email","receiver":"attacker@example.test","provider":"evil/mail"}),
        )
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let receipt: Value = response.take_json().await.unwrap();
        let mail = tokio::time::timeout(std::time::Duration::from_secs(5), self.mail.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mail["to"], "alice@example.test");
        let code = mail["body"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .find(|s| {
                s.len() == 7 && s.ends_with('.') && s[..6].bytes().all(|b| b.is_ascii_digit())
            })
            .unwrap()
            .trim_end_matches('.')
            .to_owned();
        assert!(!receipt.to_string().contains(&code));
        code
    }
    async fn fixture_code(&self, proof: &str, method: &str, code: &str, receiver: &str) {
        sqlx::query("UPDATE password_mfa_challenges SET code_hash=$1,code_method=$2,receiver=$3,sent_at=clock_timestamp() WHERE secret_hash=$4")
        .bind(proof_hash(&format!("{proof}:{code}"))).bind(method).bind(receiver).bind(proof_hash(proof)).execute(&self.pool).await.unwrap();
    }
    async fn cleanup(self) {
        self.server.abort();
        for table in [
            "password_mfa_challenges",
            "tokens",
            "verifications",
            "permissions",
            "applications",
            "users",
            "providers",
            "organizations",
        ] {
            let column = if table == "password_mfa_challenges" {
                "organization"
            } else {
                "owner"
            };
            sqlx::query(&format!("DELETE FROM {table} WHERE {column}=$1"))
                .bind(&self.owner)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        drop(self.service);
        drop(self.other);
        self.pool.close().await;
        self.other_pool.close().await;
    }
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn password_proof_is_required_before_delivery_and_email_is_browser_bound_single_use() {
    let mut f = Fixture::new().await;
    let anonymous = TestClient::post("http://localhost/api/auth/password/session/send-code")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .json(&json!({"mfaType":"email","receiver":"alice@example.test"}))
        .send(&f.service)
        .await;
    assert_eq!(anonymous.status_code, Some(StatusCode::UNAUTHORIZED));
    let mut wrong = f.login_body();
    wrong["password"] = json!("wrong");
    assert_eq!(
        f.start_body(wrong).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM password_mfa_challenges WHERE organization=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    let proof = f.begin().await;
    let code = f.send(&proof).await;
    let (hash, context): (String, Value) = sqlx::query_as(
        "SELECT code_hash,context FROM password_mfa_challenges WHERE secret_hash=$1",
    )
    .bind(proof_hash(&proof))
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_ne!(hash, code);
    assert!(!context.to_string().contains("ValidPassword42!"));
    assert!(!context.to_string().contains(&proof));
    assert_ne!(
        Fixture::call(&f.other, &proof, "/send-code", json!({"mfaType":"email"}))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let (mut a, mut b) = tokio::join!(
        Fixture::call(
            &f.service,
            &proof,
            "",
            json!({"mfaType":"email","passcode":code})
        ),
        Fixture::call(
            &f.other,
            &proof,
            "",
            json!({"mfaType":"email","passcode":code})
        )
    );
    let statuses = [a.status_code.unwrap(), b.status_code.unwrap()];
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::UNAUTHORIZED)
            .count(),
        1
    );
    let body: Value = if a.status_code == Some(StatusCode::OK) {
        a.take_json().await.unwrap()
    } else {
        b.take_json().await.unwrap()
    };
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert_eq!(
        Fixture::call(
            &f.other,
            &proof,
            "",
            json!({"mfaType":"email","passcode":code})
        )
        .await
        .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn password_mfa_rejects_generic_and_other_browser_codes_and_caps_attempts() {
    let mut f = Fixture::new().await;
    let proof = f.begin().await;
    let other = f.begin().await;
    let code = f.send(&proof).await;
    sqlx::query("INSERT INTO verifications(id,owner,name,type,user_id,provider,receiver,code) VALUES($1,$2,'generic','email',$3,'mail','alice@example.test','123456')").bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(&f.user).execute(&f.pool).await.unwrap();
    assert_eq!(
        Fixture::call(
            &f.other,
            &other,
            "",
            json!({"mfaType":"email","passcode":code})
        )
        .await
        .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    for _ in 0..4 {
        assert_eq!(
            Fixture::call(
                &f.other,
                &proof,
                "",
                json!({"mfaType":"email","passcode":"123456"})
            )
            .await
            .status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    // The fifth account-wide failure blocks both proofs even across instances.
    assert_ne!(
        Fixture::call(
            &f.service,
            &proof,
            "",
            json!({"mfaType":"email","passcode":code})
        )
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn password_mfa_sms_checks_current_contact_expiry_origin_and_cancel() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE users SET mfa_phone_enabled=true,phone='+15555550123' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let proof = f.begin().await;
    f.fixture_code(&proof, "sms", "234567", "+15555550123")
        .await;
    let missing = TestClient::post("http://localhost/api/auth/password/session")
        .add_header("Cookie", format!("casdog_password_mfa={proof}"), true)
        .json(&json!({"mfaType":"sms","passcode":"234567"}))
        .send(&f.service)
        .await;
    assert_eq!(missing.status_code, Some(StatusCode::UNAUTHORIZED));
    sqlx::query("UPDATE users SET phone='+15555550999' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::call(
            &f.other,
            &proof,
            "",
            json!({"mfaType":"sms","passcode":"234567"})
        )
        .await
        .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE users SET phone='+15555550123' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::call(
            &f.other,
            &proof,
            "",
            json!({"mfaType":"sms","passcode":"234567"})
        )
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    let expired = f.begin().await;
    sqlx::query("UPDATE password_mfa_challenges SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE secret_hash=$1").bind(proof_hash(&expired)).execute(&f.pool).await.unwrap();
    assert_eq!(
        Fixture::call(&f.service, &expired, "", json!({}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let canceled = f.begin().await;
    assert_eq!(
        Fixture::call(&f.service, &canceled, "/cancel", json!({}))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        Fixture::call(&f.other, &canceled, "", json!({}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn password_mfa_revalidates_password_logout_organization_and_application() {
    for change in 0..5 {
        let f = Fixture::new().await;
        let proof = f.begin().await;
        f.fixture_code(&proof, "email", "234567", "alice@example.test")
            .await;
        match change {
            0 => {
                sqlx::query("UPDATE users SET password_hash='changed' WHERE id=$1")
                    .bind(&f.user)
                    .execute(&f.pool)
                    .await
                    .unwrap();
            }
            1 => {
                sqlx::query("INSERT INTO user_session_epochs(user_id) VALUES($1)")
                    .bind(&f.user)
                    .execute(&f.pool)
                    .await
                    .unwrap();
            }
            2 => {
                sqlx::query("UPDATE organizations SET disable_signin=true WHERE name=$1")
                    .bind(&f.owner)
                    .execute(&f.pool)
                    .await
                    .unwrap();
            }
            3 => {
                sqlx::query("UPDATE applications SET organization='foreign' WHERE id=$1")
                    .bind(&f.app)
                    .execute(&f.pool)
                    .await
                    .unwrap();
            }
            _ => {
                sqlx::query("INSERT INTO permissions(id,owner,name,display_name,resource_type,resources,actions,effect) VALUES($1,$2,'restricted','Restricted','Application',$3,'Read','Allow')").bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(&f.app).execute(&f.pool).await.unwrap();
            }
        }
        assert_ne!(
            Fixture::call(
                &f.other,
                &proof,
                "",
                json!({"mfaType":"email","passcode":"234567"})
            )
            .await
            .status_code,
            Some(StatusCode::OK)
        );
        assert_ne!(
            Fixture::call(&f.other, &proof, "/send-code", json!({"mfaType":"email"}))
                .await
                .status_code,
            Some(StatusCode::OK)
        );
        f.cleanup().await;
    }
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn password_mfa_oauth_code_is_atomic_and_revalidates_redirect_grant_and_public_pkce() {
    let f = Fixture::new().await;
    let mut body = f.login_body();
    body["clientId"] = json!(f.app);
    body["responseType"] = json!("code");
    body["redirectUri"] = json!("https://example.test/callback");
    body["state"] = json!("state");
    let mut begun = f.start_body(body).await;
    assert_eq!(begun.status_code, Some(StatusCode::OK));
    let proof = begun
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("casdog_password_mfa=")
        .unwrap()
        .to_owned();
    let challenge: Value = begun.take_json().await.unwrap();
    assert_eq!(challenge["token"], "");
    f.fixture_code(&proof, "email", "234567", "alice@example.test")
        .await;
    sqlx::query("UPDATE applications SET grant_types='[]' WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_ne!(
        Fixture::call(
            &f.service,
            &proof,
            "",
            json!({"mfaType":"email","passcode":"234567"})
        )
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    sqlx::query("UPDATE applications SET grant_types='[\"authorization_code\"]',client_secret='' WHERE id=$1").bind(&f.app).execute(&f.pool).await.unwrap();
    assert_ne!(
        Fixture::call(
            &f.service,
            &proof,
            "",
            json!({"mfaType":"email","passcode":"234567"})
        )
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    sqlx::query("UPDATE applications SET client_secret='secret',redirect_uris='https://elsewhere.test' WHERE id=$1").bind(&f.app).execute(&f.pool).await.unwrap();
    assert_ne!(
        Fixture::call(
            &f.service,
            &proof,
            "",
            json!({"mfaType":"email","passcode":"234567"})
        )
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    sqlx::query(
        "UPDATE applications SET redirect_uris='https://example.test/callback' WHERE id=$1",
    )
    .bind(&f.app)
    .execute(&f.pool)
    .await
    .unwrap();
    let mut done = Fixture::call(
        &f.other,
        &proof,
        "",
        json!({"mfaType":"email","passcode":"234567"}),
    )
    .await;
    assert_eq!(done.status_code, Some(StatusCode::OK));
    let result: Value = done.take_json().await.unwrap();
    assert_eq!(result["state"], "state");
    assert!(!result["code"].as_str().unwrap().is_empty());
    assert_eq!(
        Fixture::call(
            &f.service,
            &proof,
            "",
            json!({"mfaType":"email","passcode":"234567"})
        )
        .await
        .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn password_mfa_totp_and_recovery_require_a_separate_atomic_browser_completion() {
    use casdog::services::mfa_service::MfaService;
    use totp_rs::{Algorithm, Secret, TOTP};
    let f = Fixture::new().await;
    let (secret, _) = MfaService::initiate_totp_setup("alice", "test").unwrap();
    MfaService::save_mfa(&f.pool, &f.user, "totp", Some(&secret))
        .await
        .unwrap();
    MfaService::enable_mfa(&f.pool, &f.user, "totp")
        .await
        .unwrap();
    let code = || {
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret.clone()).to_bytes().unwrap(),
            None,
            "alice".into(),
        )
        .unwrap()
        .generate_current()
        .unwrap()
    };
    let mut request = f.login_body();
    request["mfaType"] = json!("app");
    request["passcode"] = json!(code());
    let mut response = f.start_body(request).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let proof = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("casdog_password_mfa=")
        .unwrap()
        .to_owned();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["token"], "");
    assert_eq!(body["mfa_required"], true);
    assert_eq!(
        Fixture::call(
            &f.other,
            &proof,
            "",
            json!({"mfaType":"app","passcode":code()})
        )
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    sqlx::query("UPDATE user_mfa SET recovery_codes='[\"one-use-recovery\"]' WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let proof = f.begin().await;
    let (a, b) = tokio::join!(
        Fixture::call(
            &f.service,
            &proof,
            "",
            json!({"mfaType":"recovery","passcode":"one-use-recovery"})
        ),
        Fixture::call(
            &f.other,
            &proof,
            "",
            json!({"mfaType":"recovery","passcode":"one-use-recovery"})
        )
    );
    assert_eq!(
        [a.status_code, b.status_code]
            .iter()
            .filter(|s| **s == Some(StatusCode::OK))
            .count(),
        1
    );
    assert_eq!(
        [a.status_code, b.status_code]
            .iter()
            .filter(|s| **s == Some(StatusCode::UNAUTHORIZED))
            .count(),
        1
    );
    let remaining: String =
        sqlx::query_scalar("SELECT recovery_codes FROM user_mfa WHERE user_id=$1")
            .bind(&f.user)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(remaining, "[]");
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn password_challenge_creation_and_delivery_are_rate_and_application_scoped() {
    let f = Fixture::new().await;
    let proof = f.begin().await;
    sqlx::query("UPDATE applications SET providers='[]' WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::call(&f.other, &proof, "/send-code", json!({"mfaType":"email"}))
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    for _ in 0..4 {
        f.begin().await;
    }
    assert_ne!(
        f.start_body(f.login_body()).await.status_code,
        Some(StatusCode::OK)
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM password_mfa_challenges WHERE user_id=$1")
            .bind(&f.user)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 5);
    f.cleanup().await;
}
