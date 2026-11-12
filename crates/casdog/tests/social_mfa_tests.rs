//! Durable social sign-in second-factor regressions; requires migrations 001-019.
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    handlers::social_session::{
        cancel_social_session, consume_social_session, send_social_mfa_code,
    },
    services::{
        mfa_service::MfaService,
        social_state_service::{self as state, NewCompletion},
    },
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::PgPool;

struct Fixture {
    pool: PgPool,
    other_pool: PgPool,
    service: Service,
    other: Service,
    owner: String,
    user: String,
    app: String,
    provider: String,
    secret: String,
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
            Router::with_path("api/auth/session")
                .post(consume_social_session)
                .push(Router::with_path("send-code").post(send_social_mfa_code))
                .push(Router::with_path("cancel").post(cancel_social_session))
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
        let owner = format!("social-mfa-{}", uuid::Uuid::new_v4());
        let user = uuid::Uuid::new_v4().to_string();
        let app = uuid::Uuid::new_v4().to_string();
        let provider = uuid::Uuid::new_v4().to_string();
        let (secret, _) = MfaService::initiate_totp_setup("alice", "test").unwrap();
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'MFA test')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES($1,$2,'mock','Mock','OAuth','Mock')").bind(&provider).bind(&owner).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,providers) VALUES($1,$2,'app','App',$2,$1,'secret','',$3)")
   .bind(&app).bind(&owner).bind(json!([{"name":format!("{owner}/mock"),"canSignIn":true}])).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,provider_ids,mfa_enabled,totp_secret,email) VALUES($1,$2,'alice','Alice','',$3,true,$4,'alice@example.test')")
   .bind(&user).bind(&owner).bind(json!({format!("oauth:{provider}"):"subject"})).bind(&secret).execute(&pool).await.unwrap();
        MfaService::save_mfa(&pool, &user, "totp", Some(&secret))
            .await
            .unwrap();
        MfaService::enable_mfa(&pool, &user, "totp").await.unwrap();
        Self {
            pool,
            other_pool,
            service,
            other,
            owner,
            user,
            app,
            provider,
            secret,
        }
    }
    async fn completion(&self) -> String {
        let provider: casdog::models::Provider =
            sqlx::query_as("SELECT * FROM providers WHERE id=$1")
                .bind(&self.provider)
                .fetch_one(&self.pool)
                .await
                .unwrap();
        state::create_completion(
            &self.pool,
            &NewCompletion {
                user_id: self.user.clone(),
                provider_id: self.provider.clone(),
                provider_name: "mock".into(),
                application_id: self.app.clone(),
                organization: self.owner.clone(),
                context: json!({"link_key":format!("oauth:{}",self.provider),"subject":"subject","provider_stamp":casdog::services::providers::oauth_provider::configuration_stamp(&provider),"network_binding":"unapproved"}),
            },
        )
        .await
        .unwrap()
    }
    async fn post(&self, proof: &str, body: Value) -> Response {
        Self::on(&self.service, proof, body).await
    }
    async fn on(service: &Service, proof: &str, body: Value) -> Response {
        TestClient::post("http://localhost/api/auth/session")
            .add_header("Cookie", format!("casdog_oauth_completion={proof}"), true)
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&body)
            .send(service)
            .await
    }
    fn code(&self) -> String {
        use totp_rs::{Algorithm, Secret, TOTP};
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(self.secret.clone()).to_bytes().unwrap(),
            None,
            "alice".into(),
        )
        .unwrap()
        .generate_current()
        .unwrap()
    }
    async fn cleanup(self) {
        sqlx::query("DELETE FROM social_oauth_completions WHERE organization=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        for table in [
            "verifications",
            "permissions",
            "applications",
            "users",
            "providers",
            "organizations",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1"))
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
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL"]
async fn completion_without_provider_configuration_stamp_is_not_an_upgrade_bypass() {
    let f = Fixture::new().await;
    let proof = f.completion().await;
    sqlx::query(
        "UPDATE social_oauth_completions SET context=context-'provider_stamp' WHERE secret_hash=$1",
    )
    .bind(state::proof_hash(&proof))
    .execute(&f.pool)
    .await
    .unwrap();
    let response = f
        .post(&proof, json!({"mfaType":"app","passcode":f.code()}))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn social_totp_challenge_issues_no_jwt_until_proof_and_is_single_use() {
    let f = Fixture::new().await;
    let key = f.completion().await;
    let mut challenge = f.post(&key, json!({})).await;
    assert_eq!(challenge.status_code, Some(StatusCode::OK));
    let body: Value = challenge.take_json().await.unwrap();
    assert_eq!(body["token"], "");
    assert_eq!(body["mfa_required"], true);
    assert!(
        body["mfa_types"]
            .as_array()
            .unwrap()
            .contains(&json!("app"))
    );
    let wrong = f
        .post(&key, json!({"mfaType":"app","passcode":"wrong"}))
        .await;
    assert_eq!(wrong.status_code, Some(StatusCode::UNAUTHORIZED));
    assert_eq!(
        state::load_completion(&f.other_pool, &key)
            .await
            .unwrap()
            .attempts,
        1
    );
    let mut completed =
        Fixture::on(&f.other, &key, json!({"mfaType":"app","passcode":f.code()})).await;
    assert_eq!(completed.status_code, Some(StatusCode::OK));
    let body: Value = completed.take_json().await.unwrap();
    let token = body["token"].as_str().unwrap();
    assert!(!token.is_empty());
    assert_eq!(
        casdog::hoops::auth::validate_session_claims(&f.pool, token)
            .await
            .unwrap()
            .sub,
        f.user
    );
    assert_eq!(
        f.post(&key, json!({"mfaType":"app","passcode":f.code()}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn social_recovery_consumption_is_atomic_across_instances() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE user_mfa SET recovery_codes='[\"one-time-recovery\"]' WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let key = f.completion().await;
    let (a, b) = tokio::join!(
        Fixture::on(
            &f.service,
            &key,
            json!({"mfaType":"recovery","passcode":"one-time-recovery"})
        ),
        Fixture::on(
            &f.other,
            &key,
            json!({"mfaType":"recovery","passcode":"one-time-recovery"})
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
    let codes: String = sqlx::query_scalar("SELECT recovery_codes FROM user_mfa WHERE user_id=$1")
        .bind(&f.user)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(codes, "[]");
    let again = f.completion().await;
    assert_eq!(
        f.post(
            &again,
            json!({"mfaType":"recovery","passcode":"one-time-recovery"})
        )
        .await
        .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn social_pending_factor_rechecks_expiry_account_tenant_identity_and_credential_epochs() {
    let f = Fixture::new().await;
    let expired = f.completion().await;
    sqlx::query("UPDATE social_oauth_completions SET expires_at=NOW()-INTERVAL '1 second' WHERE secret_hash=$1").bind(state::proof_hash(&expired)).execute(&f.pool).await.unwrap();
    assert_eq!(
        f.post(&expired, json!({})).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let disabled = f.completion().await;
    sqlx::query("UPDATE users SET is_forbidden=true WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.post(&disabled, json!({})).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE users SET is_forbidden=false WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let unlinked = f.completion().await;
    sqlx::query("UPDATE users SET provider_ids='{}' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.post(&unlinked, json!({})).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE users SET provider_ids=$1 WHERE id=$2")
        .bind(json!({format!("oauth:{}",f.provider):"subject"}))
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let reset = f.completion().await;
    sqlx::query("UPDATE users SET last_change_password_time=$1 WHERE id=$2")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.post(&reset, json!({})).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE users SET last_change_password_time=NULL WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let logout = f.completion().await;
    sqlx::query("INSERT INTO user_session_epochs(user_id) VALUES($1)")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.post(&logout, json!({})).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("DELETE FROM user_session_epochs WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let tenant = f.completion().await;
    sqlx::query("UPDATE social_oauth_completions SET organization='foreign' WHERE secret_hash=$1")
        .bind(state::proof_hash(&tenant))
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.post(&tenant, json!({})).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("DELETE FROM social_oauth_completions WHERE secret_hash=$1")
        .bind(state::proof_hash(&tenant))
        .execute(&f.pool)
        .await
        .unwrap();
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn social_mfa_attempt_limit_survives_instance_switch() {
    let f = Fixture::new().await;
    let key = f.completion().await;
    for n in 0..5 {
        let service = if n % 2 == 0 { &f.service } else { &f.other };
        assert_eq!(
            Fixture::on(service, &key, json!({"mfaType":"app","passcode":"wrong"}))
                .await
                .status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    assert!(state::load_completion(&f.pool, &key).await.is_err());
    assert_eq!(
        f.post(&key, json!({"mfaType":"app","passcode":f.code()}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn social_email_factor_rejects_other_completion_and_generic_codes() {
    let f = Fixture::new().await;
    sqlx::query(
        "UPDATE users SET mfa_enabled=false,totp_secret=NULL,mfa_email_enabled=true WHERE id=$1",
    )
    .bind(&f.user)
    .execute(&f.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE user_mfa SET is_enabled=false WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let key = f.completion().await;
    let other = f.completion().await;
    for (kind, name, code) in [
        ("email", state::proof_hash(&key), "111111"),
        ("social:email", state::proof_hash(&other), "222222"),
        ("social:email", state::proof_hash(&key), "333333"),
    ] {
        sqlx::query("INSERT INTO verifications(id,owner,name,type,user_id,provider,receiver,code) VALUES($1,$2,$3,$4,$5,$2 || '/mail','alice@example.test',$6)").bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(name).bind(kind).bind(&f.user).bind(code).execute(&f.pool).await.unwrap();
    }
    for code in ["111111", "222222"] {
        assert_eq!(
            f.post(&key, json!({"mfaType":"email","passcode":code}))
                .await
                .status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    assert_eq!(
        f.post(&key, json!({"mfaType":"email","passcode":"333333"}))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn social_mfa_sender_uses_enrolled_contact_and_scoped_provider() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc,
    };
    let f = Fixture::new().await;
    sqlx::query("UPDATE users SET mfa_email_enabled=true WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/mail", listener.local_addr().unwrap());
    let (sender, mut mail) = mpsc::channel::<Value>(4);
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            let (start, length) = loop {
                let count = socket.read(&mut buffer).await.unwrap();
                if count == 0 {
                    return;
                }
                bytes.extend_from_slice(&buffer[..count]);
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
            while bytes.len() < start + length {
                let count = socket.read(&mut buffer).await.unwrap();
                if count == 0 {
                    return;
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            let value = serde_json::from_slice(&bytes[start..start + length]).unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
            sender.send(value).await.unwrap();
        }
    });
    sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,endpoint) VALUES($1,$2,'mail','Mail','Email','Custom HTTP',$3)")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(endpoint).execute(&f.pool).await.unwrap();
    let key = f.completion().await;
    // A tenant default provider is insufficient: the application must explicitly select it.
    let send = || {
        TestClient::post("http://localhost/api/auth/session/send-code").add_header("Cookie",format!("casdog_oauth_completion={key}"),true).add_header("Origin","http://127.0.0.1:8000",true).json(&json!({"mfaType":"email","receiver":"attacker@example.test","provider":"foreign/mail"}))
    };
    assert_eq!(
        send().send(&f.service).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    sqlx::query("UPDATE applications SET providers=$1 WHERE id=$2").bind(json!([{"name":format!("{}/mock",f.owner),"canSignIn":true},{"name":format!("{}/mail",f.owner),"rule":"mfa"}])).bind(&f.app).execute(&f.pool).await.unwrap();
    let mut sent = send().send(&f.other).await;
    assert_eq!(sent.status_code, Some(StatusCode::OK));
    let receipt: Value = sent.take_json().await.unwrap();
    let delivery = tokio::time::timeout(std::time::Duration::from_secs(5), mail.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivery["to"], "alice@example.test");
    let code = delivery["body"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .find(|part| {
            part.len() == 7 && part.ends_with('.') && part[..6].bytes().all(|b| b.is_ascii_digit())
        })
        .unwrap()
        .trim_end_matches('.');
    assert!(!receipt.to_string().contains(code));
    assert_ne!(
        send().send(&f.service).await.status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        f.post(&key, json!({"mfaType":"email","passcode":code}))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert_ne!(
        send().send(&f.other).await.status_code,
        Some(StatusCode::OK)
    );
    server.abort();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn social_sms_factor_origin_cancel_and_method_changes() {
    let f = Fixture::new().await;
    let key = f.completion().await;
    let without_origin = TestClient::post("http://localhost/api/auth/session")
        .add_header("Cookie", format!("casdog_oauth_completion={key}"), true)
        .json(&json!({}))
        .send(&f.service)
        .await;
    assert_eq!(without_origin.status_code, Some(StatusCode::UNAUTHORIZED));
    let cross_origin = TestClient::post("http://localhost/api/auth/session")
        .add_header("Cookie", format!("casdog_oauth_completion={key}"), true)
        .add_header("Origin", "https://attacker.invalid", true)
        .json(&json!({}))
        .send(&f.service)
        .await;
    assert_eq!(cross_origin.status_code, Some(StatusCode::UNAUTHORIZED));
    sqlx::query("UPDATE users SET mfa_enabled=false,totp_secret=NULL,mfa_phone_enabled=true,phone='+15555550123' WHERE id=$1").bind(&f.user).execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE user_mfa SET is_enabled=false WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.post(&key, json!({"mfaType":"app","passcode":f.code()}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let mut response = f.post(&key, json!({})).await;
    let challenge: Value = response.take_json().await.unwrap();
    assert_eq!(challenge["mfa_types"], json!(["sms"]));
    assert_eq!(challenge["token"], "");
    sqlx::query("INSERT INTO verifications(id,owner,name,type,user_id,provider,receiver,code) VALUES($1,$2,$3,'social:phone',$4,$2 || '/sms','+15555550123','654321')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(state::proof_hash(&key)).bind(&f.user).execute(&f.pool).await.unwrap();
    assert_eq!(
        Fixture::on(&f.other, &key, json!({"mfaType":"sms","passcode":"654321"}))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let cancel = f.completion().await;
    let response = TestClient::post("http://localhost/api/auth/session/cancel")
        .add_header("Cookie", format!("casdog_oauth_completion={cancel}"), true)
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .json(&json!({}))
        .send(&f.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert!(
        state::load_completion(&f.other_pool, &cancel)
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn social_pending_factor_rechecks_organization_provider_and_application_permission() {
    let f = Fixture::new().await;
    let key = f.completion().await;
    assert_eq!(
        f.post(&key, json!({})).await.status_code,
        Some(StatusCode::OK)
    );
    sqlx::query("UPDATE organizations SET disable_signin=true WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.post(&key, json!({"mfaType":"app","passcode":f.code()}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE organizations SET disable_signin=false WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE applications SET providers='[]' WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.post(&key, json!({"mfaType":"app","passcode":f.code()}))
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    sqlx::query("UPDATE applications SET providers=$1 WHERE id=$2")
        .bind(json!([{"name":format!("{}/mock",f.owner),"canSignIn":true}]))
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO permissions(id,owner,name,display_name,resource_type,resources,actions,effect) VALUES($1,$2,'allow-members','Allow members','Application',$3,'Read','Allow')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(&f.app).execute(&f.pool).await.unwrap();
    assert_eq!(
        Fixture::on(&f.other, &key, json!({"mfaType":"app","passcode":f.code()}))
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert!(state::load_completion(&f.pool, &key).await.is_ok());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn social_enabled_but_unusable_mfa_never_degrades_to_no_factor() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE users SET totp_secret=NULL WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE user_mfa SET is_enabled=false WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let key = f.completion().await;
    let mut response = f.post(&key, json!({})).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let challenge: Value = response.take_json().await.unwrap();
    assert_eq!(challenge["token"], "");
    assert_eq!(challenge["mfa_required"], true);
    assert_eq!(challenge["mfa_types"], json!([]));
    assert_eq!(
        f.post(&key, json!({"mfaType":"app","passcode":f.code()}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE users SET mfa_enabled=false WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE user_mfa SET is_enabled=true,secret='not-a-valid-base32-secret',recovery_codes='[]' WHERE user_id=$1").bind(&f.user).execute(&f.pool).await.unwrap();
    let mut response = f.post(&key, json!({})).await;
    let challenge: Value = response.take_json().await.unwrap();
    assert_eq!(challenge["token"], "");
    assert_eq!(challenge["mfa_required"], true);
    assert_ne!(
        f.post(&key, json!({"mfaType":"app","passcode":f.code()}))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert!(state::load_completion(&f.pool, &key).await.is_ok());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn enrollment_and_social_completion_use_the_same_account_factor_lock_order() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE user_mfa SET is_enabled=false WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let proof = f.completion().await;
    let setup_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&f.other_pool)
        .await
        .unwrap();
    let mut social_transaction = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(&f.user)
        .fetch_one(&mut *social_transaction)
        .await
        .unwrap();
    // Simulate the social transaction paused between its two row locks. The
    // second pool runs the real enrollment function on its sole connection.
    let setup_pool = f.other_pool.clone();
    let setup_user = f.user.clone();
    let code = f.code();
    let consumed_code = code.clone();
    let setup = tokio::spawn(async move {
        MfaService::confirm_setup(&setup_pool, &setup_user, "totp", &code).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            sqlx::query("SELECT pg_stat_clear_snapshot()")
                .execute(&mut *social_transaction).await.unwrap();
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')")
                .bind(setup_pid).fetch_one(&mut *social_transaction).await.unwrap();
            if waiting {break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("Enrollment should wait for the account held by social completion");
    // The old inverse order holds user_mfa here and deadlocks (or times out).
    // The corrected enrollment waits on users without holding its factor.
    sqlx::query("SET LOCAL lock_timeout='1s'")
        .execute(&mut *social_transaction)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM user_mfa WHERE user_id=$1 FOR UPDATE")
        .bind(&f.user)
        .fetch_one(&mut *social_transaction)
        .await
        .expect("Enrollment must not lock the factor before acquiring the account");
    social_transaction.commit().await.unwrap();
    let confirmed = tokio::time::timeout(std::time::Duration::from_secs(5), setup)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(confirmed.is_some());
    assert_eq!(
        f.post(&proof, json!({"mfaType":"app","passcode":consumed_code}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    // Enrollment already consumed this authenticator step. Recovery is an
    // independent proof and avoids waiting for another 30-second window.
    let codes: String = sqlx::query_scalar(
        "SELECT recovery_codes FROM user_mfa WHERE user_id=$1 AND mfa_type='totp'",
    )
    .bind(&f.user)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    let codes: Vec<String> = serde_json::from_str(&codes).unwrap();
    assert_eq!(
        f.post(&proof, json!({"mfaType":"recovery","passcode":codes[0]}))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    f.cleanup().await;
}
