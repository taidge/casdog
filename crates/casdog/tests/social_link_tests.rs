//! Explicit account binding uses browser proof, current session and provider identity;
//! all HTTP provider calls use a loopback mock. Run with CASDOG_TEST_DATABASE_URL --ignored.
use casdog::{
    config::AppConfig,
    diesel_pool::{DieselPool, create_diesel_pool},
    handlers::social_link,
    models::Provider,
    services::{AuthService, UserService, social_state_service::OAuthFlow},
};
use chrono::{Duration, Utc};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

struct Fixture {
    pool: PgPool,
    diesel: DieselPool,
    service: Service,
    org: String,
    app: String,
    provider: Provider,
    a: String,
    b: String,
    server: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPool::connect(&url).await.unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    loop {
                        let mut buf = [0; 4096];
                        let n = socket.read(&mut buf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&buf[..n]);
                        if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&bytes[..end]);
                            let len = head
                                .lines()
                                .find_map(|s| {
                                    let (k, v) = s.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            if bytes.len() >= end + 4 + len {
                                break;
                            }
                        }
                    }
                    let body=if bytes.starts_with(b"POST /token "){json!({"access_token":"provider-token"})}else{json!({"sub":"external-1","name":"External user","email":"untrusted@example.test"})}.to_string();
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                });
            }
        });
        let org = format!("link-{}", Uuid::new_v4());
        let app = Uuid::new_v4().to_string();
        let provider_id = Uuid::new_v4().to_string();
        let name = format!("provider-{}", Uuid::new_v4());
        let a = Uuid::new_v4().to_string();
        let b = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Links')",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&org)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,client_id,client_secret,custom_auth_url,custom_token_url,custom_user_info_url) VALUES($1,$2,$3,'Mock','OAuth','Mock','client','secret',$4,$5,$6)").bind(&provider_id).bind(&org).bind(&name).bind(format!("{origin}/authorize")).bind(format!("{origin}/token")).bind(format!("{origin}/userinfo")).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password,enable_idp_signup,providers) VALUES($1,$2,'links-app','Links',$2,$1,'secret','[]',true,false,$3)").bind(&app).bind(&org).bind(json!([{"name":format!("{org}/{name}"),"canSignIn":true,"canSignUp":false,"canUnlink":true}])).execute(&pool).await.unwrap();
        for (id, name) in [(&a, "alice"), (&b, "bob")] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type) VALUES($1,$2,$3,$3,'Password42!','plain')").bind(id).bind(&org).bind(name).execute(&pool).await.unwrap();
        }
        let provider = sqlx::query_as("SELECT * FROM providers WHERE id=$1")
            .bind(&provider_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel.clone()),
        );
        Self {
            pool,
            diesel,
            service,
            org,
            app,
            provider,
            a,
            b,
            server,
        }
    }
    async fn token(&self, id: &str) -> String {
        let users = UserService::new(self.diesel.clone());
        AuthService::new(users.clone())
            .generate_token(&users.get_by_id(id).await.unwrap())
            .unwrap()
    }
    async fn flow(&self, id: &str) -> OAuthFlow {
        let token = self.token(id).await;
        let claims = casdog::hoops::auth::validate_session_claims(&self.pool, &token)
            .await
            .unwrap();
        OAuthFlow {
            provider_id: self.provider.id.clone(),
            provider_name: self.provider.name.clone(),
            application_id: self.app.clone(),
            organization: self.org.clone(),
            redirect_uri: format!(
                "http://127.0.0.1:8000/api/auth/{}/callback",
                self.provider.name
            ),
            purpose: "link".into(),
            context: json!({"user_id":id,"owner":self.org,"token_hash":casdog::hoops::auth::session_fingerprint(&token),"issued_at_ms":claims.issued_at_ms,"exp":claims.exp}),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }
    async fn cleanup(self) {
        self.server.abort();
        for table in ["social_oauth_completions", "social_oauth_flows"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE organization=$1"))
                .bind(&self.org)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        for table in ["applications", "providers", "users", "organizations"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1"))
                .bind(&self.org)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        drop(self.service);
        self.pool.close().await;
    }
}
fn cookie(response: &Response, name: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find(|v| v.starts_with(name))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}
async fn state(mut response: Response) -> (String, String) {
    let status = response.status_code;
    let browser = cookie(&response, "casdog_oauth_browser=");
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    let url = reqwest::Url::parse(body["url"].as_str().unwrap()).unwrap();
    (
        url.query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .to_string(),
        browser,
    )
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL"]
async fn authenticated_link_callback_then_social_signin_returns_the_original_account() {
    let f = Fixture::new().await;
    let auth = format!("Bearer {}", f.token(&f.a).await);
    let begin = TestClient::post(format!(
        "http://localhost/api/auth/{}/link",
        f.provider.name
    ))
    .add_header("Authorization", &auth, true)
    .add_header("Origin", "http://127.0.0.1:8000", true)
    .json(&json!({"application":f.app}))
    .send(&f.service)
    .await;
    let (proof, browser) = state(begin).await;
    let callback = format!(
        "http://localhost/api/auth/{}/callback?state={proof}&code=valid",
        f.provider.name
    );
    let linked = TestClient::get(&callback)
        .add_header("Cookie", &browser, true)
        .send(&f.service)
        .await;
    assert_eq!(linked.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(linked.headers().get("location").unwrap(), "/?social=linked");
    let replay = TestClient::get(&callback)
        .add_header("Cookie", &browser, true)
        .send(&f.service)
        .await;
    assert_eq!(replay.status_code, Some(StatusCode::UNAUTHORIZED));
    let mut list = TestClient::get(format!(
        "http://localhost/api/auth/links?application={}",
        f.app
    ))
    .add_header("Authorization", &auth, true)
    .send(&f.service)
    .await;
    let value: Value = list.take_json().await.unwrap();
    assert_eq!(value["data"][0]["provider_id"], f.provider.id);
    assert!(!value.to_string().contains("secret"));
    let (proof, browser) = state(
        TestClient::get(format!(
            "http://localhost/api/auth/{}?application={}",
            f.provider.name, f.app
        ))
        .send(&f.service)
        .await,
    )
    .await;
    let response = TestClient::get(format!(
        "http://localhost/api/auth/{}/callback?state={proof}&code=valid",
        f.provider.name
    ))
    .add_header("Cookie", browser, true)
    .send(&f.service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let completion = cookie(&response, "casdog_oauth_completion=");
    let mut session = TestClient::post("http://localhost/api/auth/session")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .add_header("Cookie", completion, true)
        .send(&f.service)
        .await;
    let signed_in: Value = session.take_json().await.unwrap();
    assert_eq!(signed_in["user"]["id"], f.a);
    assert!(signed_in["token"].as_str().is_some_and(|s| !s.is_empty()));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL"]
async fn linking_rejects_identity_theft_cross_tenant_stale_session_and_conflicting_rebind() {
    let f = Fixture::new().await;
    let flow = f.flow(&f.a).await;
    social_link::finalize_link(&f.pool, &flow, &f.provider, "same-subject")
        .await
        .unwrap();
    assert!(
        social_link::finalize_link(&f.pool, &f.flow(&f.b).await, &f.provider, "same-subject")
            .await
            .is_err()
    );
    assert!(
        social_link::finalize_link(&f.pool, &flow, &f.provider, "different-subject")
            .await
            .is_err()
    );
    let mut foreign = f.flow(&f.b).await;
    foreign.organization = "other-tenant".into();
    assert!(
        social_link::finalize_link(&f.pool, &foreign, &f.provider, "new-subject")
            .await
            .is_err()
    );
    let mut expired = f.flow(&f.b).await;
    expired.expires_at = Utc::now() - Duration::seconds(1);
    assert!(
        social_link::finalize_link(&f.pool, &expired, &f.provider, "new-subject")
            .await
            .is_err()
    );
    let reset = f.flow(&f.b).await;
    sqlx::query("UPDATE users SET last_change_password_time=$1 WHERE id=$2")
        .bind((Utc::now() + Duration::seconds(1)).to_rfc3339())
        .bind(&f.b)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        social_link::finalize_link(&f.pool, &reset, &f.provider, "new-subject")
            .await
            .is_err()
    );
    sqlx::query("UPDATE users SET last_change_password_time=NULL WHERE id=$1")
        .bind(&f.b)
        .execute(&f.pool)
        .await
        .unwrap();
    let revoked = f.flow(&f.b).await;
    sqlx::query("INSERT INTO revoked_session_tokens(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '1 hour')").bind(revoked.context["token_hash"].as_str().unwrap()).bind(&f.b).execute(&f.pool).await.unwrap();
    assert!(
        social_link::finalize_link(&f.pool, &revoked, &f.provider, "new-subject")
            .await
            .is_err()
    );
    let auth = format!("Bearer {}", f.token(&f.a).await);
    let endpoint = format!("http://localhost/api/auth/{}/link", f.provider.name);
    let wrong_origin = TestClient::post(&endpoint)
        .add_header("Authorization", &auth, true)
        .add_header("Origin", "https://attacker.test", true)
        .json(&json!({"application":f.app}))
        .send(&f.service)
        .await;
    assert_eq!(wrong_origin.status_code, Some(StatusCode::UNAUTHORIZED));
    let wrong_user = TestClient::post(endpoint)
        .add_header("Authorization", &auth, true)
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .json(&json!({"application":f.app,"userId":f.b}))
        .send(&f.service)
        .await;
    assert_eq!(wrong_user.status_code, Some(StatusCode::FORBIDDEN));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL"]
async fn competing_bindings_have_one_winner_and_imported_duplicates_fail_closed() {
    let f = Fixture::new().await;
    let a = f.flow(&f.a).await;
    let b = f.flow(&f.b).await;
    let (one, two) = tokio::join!(
        social_link::finalize_link(&f.pool, &a, &f.provider, "racing-subject"),
        social_link::finalize_link(&f.pool, &b, &f.provider, "racing-subject")
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE owner=$1 AND provider_ids->>$2='racing-subject'",
    )
    .bind(&f.org)
    .bind(format!("oauth:{}", f.provider.id))
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    sqlx::query(
        "UPDATE users SET provider_ids=jsonb_build_object($1::text,'duplicate') WHERE owner=$2",
    )
    .bind(format!("oauth:{}", f.provider.id))
    .bind(&f.org)
    .execute(&f.pool)
    .await
    .unwrap();
    let mut tx = f.pool.begin().await.unwrap();
    assert!(
        social_link::find_identity(&mut tx, &f.org, &f.provider.id, "duplicate")
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL"]
async fn unlink_requires_policy_recent_session_and_another_usable_signin_method() {
    let f = Fixture::new().await;
    social_link::finalize_link(&f.pool, &f.flow(&f.a).await, &f.provider, "last-account")
        .await
        .unwrap();
    let auth = format!("Bearer {}", f.token(&f.a).await);
    let endpoint = format!("http://localhost/api/auth/{}/unlink", f.provider.name);
    for proof in [None, Some("incorrect")] {
        let res = TestClient::post(&endpoint)
            .add_header("Authorization", &auth, true)
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&json!({"application":f.app,"password":proof}))
            .send(&f.service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
    }
    let res = TestClient::post(&endpoint)
        .add_header("Authorization", &auth, true)
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .json(&json!({"application":f.app,"password":"Password42!"}))
        .send(&f.service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let linked: bool =
        sqlx::query_scalar("SELECT COALESCE(provider_ids ? $1,false) FROM users WHERE id=$2")
            .bind(format!("oauth:{}", f.provider.id))
            .bind(&f.a)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(!linked);
    social_link::finalize_link(&f.pool, &f.flow(&f.a).await, &f.provider, "last-account")
        .await
        .unwrap();
    sqlx::query("UPDATE applications SET providers=$1 WHERE id=$2").bind(json!([{"name":format!("{}/{}",f.org,f.provider.name),"canSignIn":true,"canUnlink":false}])).bind(&f.app).execute(&f.pool).await.unwrap();
    let res = TestClient::post(endpoint)
        .add_header("Authorization", &auth, true)
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .json(&json!({"application":f.app,"password":"Password42!"}))
        .send(&f.service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL"]
async fn linking_rechecks_logout_epoch_and_requires_recent_session() {
    let f = Fixture::new().await;
    let pending = f.flow(&f.b).await;
    sqlx::query("INSERT INTO user_session_epochs(user_id,invalid_before) VALUES($1,NOW()+INTERVAL '1 second')")
        .bind(&f.b).execute(&f.pool).await.unwrap();
    assert!(
        social_link::finalize_link(&f.pool, &pending, &f.provider, "after-logout")
            .await
            .is_err()
    );
    let users = UserService::new(f.diesel.clone());
    let auth = AuthService::new(users.clone());
    let mut old = auth.claims_for_user(&users.get_by_id(&f.a).await.unwrap());
    old.iat -= 301;
    old.issued_at_ms = old.issued_at_ms.map(|t| t - 301_000);
    let token = auth.generate_token_from_claims(&old).unwrap();
    // The token itself remains valid, but is too old for a binding mutation.
    assert!(
        casdog::hoops::auth::validate_session_claims(&f.pool, &token)
            .await
            .is_ok()
    );
    let response = TestClient::post(format!(
        "http://localhost/api/auth/{}/link",
        f.provider.name
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .add_header("Origin", "http://127.0.0.1:8000", true)
    .json(&json!({"application":f.app}))
    .send(&f.service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL"]
async fn binding_lock_wait_cannot_extend_oauth_or_session_lifetime() {
    let f = Fixture::new().await;
    for expire_session in [false, true] {
        let mut pending = f.flow(&f.a).await;
        let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        if expire_session {
            pending.context["exp"] = json!(now.timestamp() + 2);
        } else {
            pending.expires_at = now + Duration::seconds(1);
        }
        let mut blocker = f.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(&f.a)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let pool = f.pool.clone();
        let provider = f.provider.clone();
        let waiter = tokio::spawn(async move {
            social_link::finalize_link(&pool, &pending, &provider, "waited-too-long").await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !waiter.is_finished(),
            "binding must wait for the held user lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(if expire_session {
            2100
        } else {
            1100
        }))
        .await;
        blocker.commit().await.unwrap();
        assert!(waiter.await.unwrap().is_err());
    }
    let links: Option<Value> = sqlx::query_scalar("SELECT provider_ids FROM users WHERE id=$1")
        .bind(&f.a)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(
        links
            .as_ref()
            .and_then(|v| v.get(format!("oauth:{}", f.provider.id)))
            .is_none()
    );
    f.cleanup().await;
}
