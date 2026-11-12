//! Native provider configuration -> real HTTP OAuth -> shared browser/MFA proof.
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    services::providers::{
        generic_oauth::GenericOAuthProvider,
        oauth_provider::{self as oauth, OAuthProviderTrait},
    },
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fields() -> Value {
    json!({"id":"data.identity.id","username":"data.login","displayName":"data.name","email":"data.email","emailVerified":"data.emailOk","phone":"data.phone","phoneVerified":"data.phoneOk","avatarUrl":"data.picture"})
}
fn claims() -> Value {
    json!({"data":{"identity":{"id":1234567890123456789u64},"login":"wire-user","name":"Mapped User","email":"same@example.test","emailOk":true,"phone":"+12025550123","phoneOk":true,"picture":"https://example.test/avatar.png"}})
}
#[test]
fn upstream_mapping_uses_object_paths_all_eight_fields_and_exact_integer_subjects() {
    let map = oauth::mapping(Some(&fields().to_string())).unwrap();
    let info = oauth::map_user_info(&claims(), &map, "Custom").unwrap();
    assert_eq!(info.id, "1234567890123456789");
    assert_eq!(info.username, "wire-user");
    assert_eq!(info.display_name, "Mapped User");
    assert_eq!(info.email.as_deref(), Some("same@example.test"));
    assert!(info.email_verified);
    assert_eq!(info.phone.as_deref(), Some("+12025550123"));
    assert!(info.phone_verified);
    assert_eq!(
        info.avatar_url.as_deref(),
        Some("https://example.test/avatar.png")
    );
    let default = oauth::map_user_info(
        &json!({"sub":"s","preferred_username":"u","name":"n","email_verified":false}),
        &Default::default(),
        "OIDC",
    )
    .unwrap();
    assert_eq!(default.id, "s");
    assert_eq!(default.username, "u");
    assert!(!default.email_verified);
    for bad in [
        json!({"id":"data.missing"}),
        json!({"id":"data.identity.id.0"}),
        json!({"id":"data..id"}),
        json!({"unknown":"data.id"}),
        json!({"id":["data.id"]}),
    ] {
        let mapping = oauth::mapping(Some(&bad.to_string()));
        assert!(
            mapping.is_err()
                || oauth::map_user_info(&claims(), &mapping.unwrap(), "Custom").is_err()
        );
    }
    for value in [
        Value::Null,
        json!(true),
        json!([]),
        json!({}),
        json!(""),
        json!("unknown"),
        json!(1.25),
    ] {
        let mut raw = claims();
        raw["data"]["identity"]["id"] = value;
        raw["sub"] = json!("must-not-substitute-this-subject");
        assert!(oauth::map_user_info(&raw, &map, "Custom").is_err());
    }
    let mut raw = claims();
    raw["data"]["phone"] = json!("invalid");
    assert!(oauth::map_user_info(&raw, &map, "Custom").is_err());
}
#[test]
fn okta_record_uses_upstream_domain_issuer_path_and_binds_it_to_configuration() {
    let now = chrono::Utc::now();
    let mut record:casdog::models::Provider=serde_json::from_value(json!({"id":"p","owner":"tenant","name":"okta","created_at":now,"updated_at":now,"display_name":"Okta","category":"OAuth","type":"Okta","disable_ssl":false,"enable_sign_authn_request":false,"client_id":"client","client_secret":"secret","domain":"https://org.okta.test/oauth2/default/","issuer_url":"https://secondary.okta.test/oauth2/ignored","custom_auth_url":"https://legacy.okta.test/old/authorize","scopes":"openid custom-scope"})).unwrap();
    let stamp = oauth::configuration_stamp(&record);
    let provider = oauth::create_oauth_provider_record(&record).unwrap();
    let url =
        reqwest::Url::parse(&provider.get_auth_url("https://app.test/callback", "state", None))
            .unwrap();
    assert_eq!(
        url.as_str().split('?').next().unwrap(),
        "https://org.okta.test/oauth2/default/v1/authorize"
    );
    assert_eq!(
        url.query_pairs().find(|(k, _)| k == "scope").unwrap().1,
        "openid custom-scope"
    );
    record.domain = Some("https://org.okta.test/oauth2/another".into());
    assert_ne!(oauth::configuration_stamp(&record), stamp);
    for base in [
        "http://org.okta.test/oauth2/default",
        "https://user@org.okta.test/oauth2/default",
        "https://org.okta.test/oauth2/default?query=x",
        "https://org.okta.test/oauth2/default#fragment",
    ] {
        record.domain = Some(base.into());
        assert!(oauth::create_oauth_provider_record(&record).is_err());
    }
    record.domain = None;
    assert_eq!(
        oauth::okta_base(&record).unwrap(),
        "https://secondary.okta.test/oauth2/ignored"
    );
    record.issuer_url = None;
    assert_eq!(
        oauth::okta_base(&record).unwrap(),
        "https://legacy.okta.test/oauth2"
    );
}

#[test]
fn builtin_custom_scopes_apply_and_empty_configuration_retains_defaults() {
    for kind in ["Steam", "Telegram", "Lark", "Feishu"] {
        assert!(
            oauth::create_oauth_provider(
                kind,
                "c",
                "s",
                None,
                None,
                None,
                Some("unsupported-scope")
            )
            .is_none()
        );
        assert!(oauth::create_oauth_provider(kind, "c", "s", None, None, None, None).is_some());
    }
    for provider in [
        "GitHub",
        "Google",
        "Facebook",
        "Microsoft",
        "Apple",
        "GitLab",
        "Discord",
        "Slack",
        "Twitter",
        "LinkedIn",
        "Bitbucket",
        "Okta",
        "WeChat",
        "DingTalk",
    ] {
        let configured = oauth::create_oauth_provider(
            provider,
            "c",
            "s",
            None,
            None,
            None,
            Some("custom-a custom-b"),
        )
        .unwrap();
        let url = reqwest::Url::parse(&configured.get_auth_url(
            "https://casdog.test/callback",
            "state",
            None,
        ))
        .unwrap();
        assert_eq!(
            url.query_pairs().find(|(k, _)| k == "scope").unwrap().1,
            "custom-a custom-b",
            "{provider}"
        );
        let empty =
            oauth::create_oauth_provider(provider, "c", "s", None, None, None, Some(" ")).unwrap();
        let defaults =
            oauth::create_oauth_provider(provider, "c", "s", None, None, None, None).unwrap();
        assert_eq!(
            empty.get_auth_url("https://casdog.test/callback", "state", None),
            defaults.get_auth_url("https://casdog.test/callback", "state", None)
        );
    }
}
struct Wire {
    origin: String,
    mode: Arc<AtomicU8>,
    hits: Arc<AtomicUsize>,
    traps: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Wire {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let hits = Arc::new(AtomicUsize::new(0));
        let traps = Arc::new(AtomicUsize::new(0));
        let (m, h, t) = (mode.clone(), hits.clone(), traps.clone());
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (m, h, t) = (m.clone(), h.clone(), t.clone());
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    let end = loop {
                        let mut buf = [0; 4096];
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        data.extend_from_slice(&buf[..n]);
                        assert!(data.len() < 32768);
                        if let Some(end) = data.windows(4).position(|v| v == b"\r\n\r\n") {
                            let length = String::from_utf8_lossy(&data[..end])
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            if data.len() >= end + 4 + length {
                                break end;
                            }
                        }
                    };
                    h.fetch_add(1, Ordering::SeqCst);
                    let mode = m.load(Ordering::SeqCst);
                    let header = String::from_utf8_lossy(&data[..end]);
                    let token = header.starts_with("POST /token ");
                    let trap = header.contains(" /trap ");
                    if trap {
                        t.fetch_add(1, Ordering::SeqCst);
                    }
                    if token {
                        let form: std::collections::HashMap<_, _> = reqwest::Url::parse(&format!(
                            "http://local/?{}",
                            String::from_utf8_lossy(&data[end + 4..])
                        ))
                        .unwrap()
                        .query_pairs()
                        .into_owned()
                        .collect();
                        assert_eq!(form["client_secret"], "wire-secret");
                        assert_eq!(form["grant_type"], "authorization_code");
                    } else if !trap {
                        assert!(
                            header
                                .to_ascii_lowercase()
                                .contains("authorization: bearer wire-token")
                        );
                    }
                    let mut status = "200 OK";
                    let mut extra = String::new();
                    let mut body = if token {
                        json!({"access_token":"wire-token","token_type":"Bearer"})
                    } else {
                        claims()
                    }
                    .to_string();
                    if (token && mode == 1) || (!token && mode == 5) {
                        status = "302 Found";
                        extra = "Location: /trap\r\n".into();
                    }
                    if token && mode == 2 {
                        status = "400 Bad Request";
                    }
                    if token && mode == 3 {
                        body = json!({"access_token":"x".repeat(1024*1024)}).to_string();
                    }
                    if !token && mode == 4 {
                        body = json!({"data":{"name":"missing identity"}}).to_string();
                    }
                    if token && mode == 6 {
                        body = "not JSON wire-secret".into();
                    }
                    if token && mode == 7 {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                    let _=stream.write_all(format!("HTTP/1.1 {status}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await;
                });
            }
        });
        Self {
            origin,
            mode,
            hits,
            traps,
            task,
        }
    }
    fn provider(&self, private: bool) -> GenericOAuthProvider {
        GenericOAuthProvider::new(
            "Custom".into(),
            "wire-client".into(),
            "wire-secret".into(),
            format!("{}/authorize?fixed=kept&scope=old", self.origin),
            format!("{}/token", self.origin),
            format!("{}/userinfo", self.origin),
            "custom-scope".into(),
        )
        .with_configuration(
            oauth::mapping(Some(&fields().to_string())).unwrap(),
            private,
        )
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[tokio::test]
async fn generic_transport_refuses_private_without_grant_redirects_errors_oversize_and_secret_leaks()
 {
    let wire = Wire::start().await;
    let okta = casdog::services::providers::okta::OktaProvider::from_issuer_base(
        "client".into(),
        "secret".into(),
        format!(
            "{}/oauth2/default",
            wire.origin.replace("http://", "https://")
        ),
    )
    .unwrap();
    assert!(
        okta.exchange_code("code", "https://app.test/callback")
            .await
            .is_err()
    );
    assert_eq!(wire.hits.load(Ordering::SeqCst), 0);
    assert!(
        wire.provider(false)
            .exchange_code("code", "https://app.test/callback")
            .await
            .is_err()
    );
    assert_eq!(wire.hits.load(Ordering::SeqCst), 0);
    let provider = wire.provider(true);
    let auth = reqwest::Url::parse(&provider.get_auth_url(
        "https://app.test/callback",
        "bound-state",
        None,
    ))
    .unwrap();
    assert_eq!(
        auth.query_pairs().find(|(k, _)| k == "fixed").unwrap().1,
        "kept"
    );
    assert_eq!(auth.query_pairs().filter(|(k, _)| k == "scope").count(), 1);
    assert_eq!(
        provider
            .exchange_code("code", "https://app.test/callback")
            .await
            .unwrap(),
        "wire-token"
    );
    assert_eq!(
        provider.get_user_info("wire-token").await.unwrap().username,
        "wire-user"
    );
    for mode in [1, 2, 3, 6] {
        wire.mode.store(mode, Ordering::SeqCst);
        let error = provider
            .exchange_code("code", "https://app.test/callback")
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("wire-secret"));
        assert!(!error.contains(&wire.origin));
    }
    for mode in [4, 5] {
        wire.mode.store(mode, Ordering::SeqCst);
        assert!(provider.get_user_info("wire-token").await.is_err());
    }
    assert_eq!(wire.traps.load(Ordering::SeqCst), 0);
    wire.mode.store(7, Ordering::SeqCst);
    let started = std::time::Instant::now();
    assert!(
        provider
            .exchange_code("code", "https://app.test/callback")
            .await
            .is_err()
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}
fn token(id: &str, owner: &str, name: &str, admin: bool) -> String {
    let now = chrono::Utc::now();
    jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({"sub":id,"owner":owner,"name":name,"is_admin":admin,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"exp":now.timestamp()+3600,"iss":AppConfig::get().jwt.issuer}),&jsonwebtoken::EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
}
fn origin() -> String {
    let cfg = AppConfig::get();
    reqwest::Url::parse(
        &cfg.server
            .public_url
            .unwrap_or_else(|| format!("http://{}:{}", cfg.server.host, cfg.server.port)),
    )
    .unwrap()
    .origin()
    .ascii_serialization()
}
fn cookie(response: &Response, prefix: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|s| s.to_str().ok())
        .find(|v| v.starts_with(prefix))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}
struct Fixture {
    pool: PgPool,
    service: Service,
    wire: Wire,
    owner: String,
    app: String,
    provider: String,
    name: String,
    admin: String,
    admin_name: String,
    user: String,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(create_diesel_pool(&url).await.unwrap()),
        );
        let wire = Wire::start().await;
        let owner = format!("oauth-{}", uuid::Uuid::new_v4());
        let admin = uuid::Uuid::new_v4().to_string();
        let admin_name = format!("oauth-admin-{}", uuid::Uuid::new_v4());
        let user = uuid::Uuid::new_v4().to_string();
        let app = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin','built-in','Built in') ON CONFLICT(name) DO NOTHING").bind(uuid::Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,'OAuth')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,'built-in',$2,'Global admin','unused',true)").bind(&admin).bind(&admin_name).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type,email,email_verified) VALUES($1,$2,'existing','Existing','Password42!','plain','same@example.test',false)").bind(&user).bind(&owner).execute(&pool).await.unwrap();
        let name = format!("wire-{}", uuid::Uuid::new_v4());
        let mut response=TestClient::post("http://localhost/api/providers").bearer_auth(token(&admin,"built-in",&admin_name,true))
            .json(&json!({"owner":owner,"name":name,"display_name":"Wire OAuth","category":"OAuth","type":"Custom","client_id":"wire-client","client_secret":"wire-secret","custom_auth_url":format!("{}/authorize",wire.origin),"custom_token_url":format!("{}/token",wire.origin),"custom_user_info_url":format!("{}/userinfo",wire.origin),"scopes":"openid custom-scope","user_mapping":fields()})).send(&service).await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
        let provider = body["id"].as_str().unwrap().to_owned();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_idp_signup,providers) VALUES($1,$2,$1,'Wire',$2,$1,'secret','',true,$3)").bind(&app).bind(&owner).bind(json!([{"name":format!("{owner}/{name}"),"canSignIn":true,"canSignUp":true,"canUnlink":true}])).execute(&pool).await.unwrap();
        Self {
            pool,
            service,
            wire,
            owner,
            app,
            provider,
            name,
            admin,
            admin_name,
            user,
        }
    }
    fn admin_token(&self) -> String {
        token(&self.admin, "built-in", &self.admin_name, true)
    }
    async fn approve(&self) {
        let response = TestClient::post(format!(
            "http://localhost/api/providers/{}/network-approval",
            self.provider
        ))
        .bearer_auth(self.admin_token())
        .json(&json!({"allow_private":true}))
        .send(&self.service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
    }
    async fn revoke(&self) {
        assert_eq!(
            TestClient::delete(format!(
                "http://localhost/api/providers/{}/network-approval",
                self.provider
            ))
            .bearer_auth(self.admin_token())
            .send(&self.service)
            .await
            .status_code,
            Some(StatusCode::OK)
        );
    }
    async fn begin(&self) -> (String, String) {
        let mut response = TestClient::get(format!(
            "http://localhost/api/auth/{}?application={}",
            self.name, self.app
        ))
        .send(&self.service)
        .await;
        let browser = cookie(&response, "casdog_oauth_browser=");
        let body: Value = response.take_json().await.unwrap();
        let url = reqwest::Url::parse(body["url"].as_str().unwrap()).unwrap();
        assert_eq!(
            url.query_pairs().find(|(k, _)| k == "scope").unwrap().1,
            "openid custom-scope"
        );
        (
            url.query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1
                .into_owned(),
            browser,
        )
    }
    async fn callback(&self, state: &str, browser: &str) -> Response {
        TestClient::get(format!(
            "http://localhost/api/auth/{}/callback?state={state}&code=wire-code",
            self.name
        ))
        .add_header("cookie", browser, true)
        .send(&self.service)
        .await
    }
    async fn complete(&self, proof: &str, body: Value) -> Response {
        TestClient::post("http://localhost/api/auth/session")
            .add_header("origin", origin(), true)
            .add_header("cookie", proof, true)
            .json(&body)
            .send(&self.service)
            .await
    }
    async fn cleanup(&self) {
        for sql in [
            "DELETE FROM social_oauth_completions WHERE organization=$1",
            "DELETE FROM social_oauth_flows WHERE organization=$1",
            "DELETE FROM users WHERE owner=$1",
            "DELETE FROM applications WHERE organization=$1",
            "DELETE FROM providers WHERE owner=$1",
            "DELETE FROM organizations WHERE name=$1",
        ] {
            sqlx::query(sql)
                .bind(&self.owner)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(&self.admin)
            .execute(&self.pool)
            .await
            .unwrap();
    }
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through OAuth network approval"]
async fn native_provider_mapping_persists_profile_and_does_not_merge_an_existing_email_account() {
    let f = Fixture::new().await;
    f.approve().await;
    let (state, browser) = f.begin().await;
    let response = f.callback(&state, &browser).await;
    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let proof = cookie(&response, "casdog_oauth_completion=");
    let mut complete = f.complete(&proof, json!({})).await;
    let status = complete.status_code;
    let body: Value = complete.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert_ne!(body["user"]["id"], f.user);
    let user = body["user"]["id"].as_str().unwrap();
    let row: Value = sqlx::query_scalar("SELECT to_jsonb(u) FROM users u WHERE id=$1")
        .bind(user)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(row["name"], "wire-user");
    assert_eq!(row["display_name"], "Mapped User");
    assert_eq!(row["phone"], "+12025550123");
    assert_eq!(row["email_verified"], true);
    assert_eq!(row["properties"]["oauth_profile"]["phoneVerified"], true);
    assert_eq!(
        row["provider_ids"][format!("oauth:{}", f.provider)],
        "1234567890123456789"
    );
    let original: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE id=$1")
        .bind(&f.user)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(!original);
    assert_eq!(
        f.complete(&proof, json!({})).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through OAuth network approval"]
async fn callback_and_completion_reject_changed_mapping_or_revoked_reapproved_network_grants() {
    let f = Fixture::new().await;
    f.approve().await;
    let (state, browser) = f.begin().await;
    f.revoke().await;
    f.approve().await;
    let before = f.wire.hits.load(Ordering::SeqCst);
    assert_eq!(
        f.callback(&state, &browser).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.wire.hits.load(Ordering::SeqCst), before);
    let (state, browser) = f.begin().await;
    let response = f.callback(&state, &browser).await;
    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let proof = cookie(&response, "casdog_oauth_completion=");
    f.revoke().await;
    f.approve().await;
    assert_eq!(
        f.complete(&proof, json!({})).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let (state, browser) = f.begin().await;
    let update = TestClient::put(format!("http://localhost/api/providers/{}", f.provider))
        .bearer_auth(f.admin_token())
        .json(&json!({"user_mapping":{"id":"data.other.id"}}))
        .send(&f.service)
        .await;
    assert_eq!(update.status_code, Some(StatusCode::OK));
    assert_eq!(
        f.callback(&state, &browser).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through OAuth network approval"]
async fn linking_uses_configured_scope_and_preserves_existing_contacts_and_local_verification() {
    let f = Fixture::new().await;
    f.approve().await;
    let mut begin = TestClient::post(format!("http://localhost/api/auth/{}/link", f.name))
        .bearer_auth(token(&f.user, &f.owner, "existing", false))
        .add_header("origin", origin(), true)
        .json(&json!({"application":f.app}))
        .send(&f.service)
        .await;
    let status = begin.status_code;
    let browser = cookie(&begin, "casdog_oauth_browser=");
    let body: Value = begin.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    let url = reqwest::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert_eq!(
        url.query_pairs().find(|(k, _)| k == "scope").unwrap().1,
        "openid custom-scope"
    );
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(
        f.callback(&state, &browser).await.status_code,
        Some(StatusCode::SEE_OTHER)
    );
    sqlx::query("UPDATE users SET mfa_enabled=true,totp_secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' WHERE id=$1").bind(&f.user).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO user_mfa(id,user_id,mfa_type,secret,is_enabled,recovery_codes) VALUES($1,$2,'totp','JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',true,'[\"wire-recovery\"]')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&f.user).execute(&f.pool).await.unwrap();
    let (state, browser) = f.begin().await;
    let response = f.callback(&state, &browser).await;
    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let proof = cookie(&response, "casdog_oauth_completion=");
    let mut response = f.complete(&proof, json!({})).await;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["mfa_required"], true);
    assert!(
        body.get("token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .is_empty()
    );
    let mut response = f
        .complete(
            &proof,
            json!({"mfaType":"recovery","passcode":"wire-recovery"}),
        )
        .await;
    let body: Value = response.take_json().await.unwrap();
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert_eq!(body["user"]["id"], f.user);
    assert_eq!(body["user"]["email_verified"], false);
    assert!(body["user"]["phone"].is_null());
    f.cleanup().await;
}
