//! Official WeChat protocol on a loopback HTTP fixture, real shared PG/browser paths.
use casdog::{
    config::AppConfig,
    diesel_pool::{DieselPool, create_diesel_pool},
    services::{
        AuthService, UserService,
        mfa_service::MfaService,
        providers::{
            oauth_provider::OAuthProviderTrait,
            wechat::{WeChatProvider, WeChatVariant},
        },
        social_state_service,
        wechat_flow::{self, WeChatTestTransport},
    },
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Wire {
    origin: String,
    requests: Arc<Mutex<Vec<reqwest::Url>>>,
    mode: Arc<AtomicU8>,
    task: tokio::task::JoinHandle<()>,
}
impl Wire {
    async fn new() -> Self {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", socket.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mode = Arc::new(AtomicU8::new(0));
        let (saved, behavior) = (requests.clone(), mode.clone());
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = socket.accept().await.unwrap();
                let saved = saved.clone();
                let behavior = behavior.clone();
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    loop {
                        let mut buffer = [0; 2048];
                        let count = stream.read(&mut buffer).await.unwrap();
                        if count == 0 {
                            return;
                        }
                        data.extend_from_slice(&buffer[..count]);
                        if data.windows(4).any(|v| v == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&data);
                    let path = text
                        .lines()
                        .next()
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap();
                    let url = reqwest::Url::parse(&format!("http://fixture{path}")).unwrap();
                    saved.lock().unwrap().push(url.clone());
                    let mode = behavior.load(Ordering::SeqCst);
                    let token = url.path() == "/sns/oauth2/access_token";
                    let mut body = if token {
                        json!({"access_token":"fixture-access-secret","openid":"shared-openid","unionid":"shared-union","expires_in":7200,"scope":"snsapi_userinfo"})
                    } else {
                        json!({"openid":"shared-openid","unionid":"shared-union","nickname":"微信昵称","headimgurl":"https://example.test/wechat.png","email":"same@example.test"})
                    };
                    if mode == 1 && !token {
                        body["openid"] = json!("wrong-user");
                    }
                    if mode == 2 && !token {
                        body["unionid"] = json!("wrong-union");
                    }
                    if mode == 3 {
                        body = json!({"errcode":40029,"errmsg":"LEAK-fixture-access-secret?secret=mobile-secret"});
                    }
                    if mode == 6 {
                        body.as_object_mut().unwrap().remove("unionid");
                    }
                    if mode == 7 && token {
                        body["openid"] = Value::Null;
                    }
                    if mode == 8 && !token {
                        body.as_object_mut().unwrap().remove("unionid");
                    }
                    let body = if mode == 5 {
                        "x".repeat(65537)
                    } else {
                        body.to_string()
                    };
                    let status = if mode == 4 {
                        "302 Found\r\nLocation: /credential-sink"
                    } else {
                        "200 OK"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            origin,
            requests,
            mode,
            task,
        }
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn adapter(&self, variant: WeChatVariant) -> WeChatProvider {
        let (id, secret) = if variant == WeChatVariant::Desktop {
            ("desktop-app", "desktop-secret")
        } else {
            ("mobile-app", "mobile-secret")
        };
        WeChatTestTransport::new(&self.origin)
            .unwrap()
            .apply(WeChatProvider::with_variant(
                id.into(),
                secret.into(),
                variant,
            ))
            .unwrap()
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn record() -> casdog::models::Provider {
    let now = chrono::Utc::now();
    serde_json::from_value(json!({"id":"fixture","owner":"tenant","name":"wechat","display_name":"WeChat","category":"OAuth","type":"WeChat","client_id":"desktop-app","client_secret":"desktop-secret","client_id2":"mobile-app","client_secret2":"mobile-secret","created_at":now,"updated_at":now,"disable_ssl":false,"enable_sign_authn_request":false})).unwrap()
}
#[test]
fn browser_variant_and_secondary_credentials_are_bound_to_server_state() {
    let p = record();
    for (ua, expected) in [
        ("Mozilla", "desktop"),
        ("Mozilla MicroMessenger/8.0", "micromessenger"),
    ] {
        let flow = wechat_flow::prepare(&p, ua).unwrap().unwrap();
        assert_eq!(flow["variant"], expected);
        assert!(!flow.to_string().contains("mobile-secret"));
        let adapter = wechat_flow::provider(&p, &flow, None).unwrap().unwrap();
        let url = reqwest::Url::parse(&adapter.get_auth_url(
            "https://app.test/callback?a=b",
            "state-proof",
            None,
        ))
        .unwrap();
        let pairs: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            pairs["appid"],
            if expected == "desktop" {
                "desktop-app"
            } else {
                "mobile-app"
            }
        );
        assert_eq!(
            pairs["scope"],
            if expected == "desktop" {
                "snsapi_login"
            } else {
                "snsapi_userinfo"
            }
        );
        assert_eq!(
            url.path(),
            if expected == "desktop" {
                "/connect/qrconnect"
            } else {
                "/connect/oauth2/authorize"
            }
        );
        assert_eq!(pairs["redirect_uri"], "https://app.test/callback?a=b");
        let mut forged = flow.clone();
        forged["variant"] = json!(if expected == "desktop" {
            "micromessenger"
        } else {
            "desktop"
        });
        assert!(wechat_flow::provider(&p, &forged, None).is_err());
        let mut changed = p.clone();
        changed.client_secret2 = Some("rotated".into());
        assert!(wechat_flow::provider(&changed, &flow, None).is_err());
        changed = p.clone();
        changed.owner = "other".into();
        assert!(wechat_flow::provider(&changed, &flow, None).is_err());
    }
    let mut missing = p;
    missing.client_secret2 = None;
    assert!(wechat_flow::prepare(&missing, "MicroMessenger").is_err());
    assert!(wechat_flow::prepare(&missing, "Desktop").is_ok());
    assert!(WeChatTestTransport::new("https://api.weixin.qq.com/").is_err());
}
#[tokio::test]
async fn actual_token_and_profile_protocol_matches_ids_and_does_not_leak_remote_errors() {
    let wire = Wire::new().await;
    for variant in [WeChatVariant::Desktop, WeChatVariant::Micromessenger] {
        let adapter = wire.adapter(variant);
        let token = adapter
            .exchange_code("code +&中文", "https://ignored.test")
            .await
            .unwrap();
        let info = adapter.get_user_info(&token).await.unwrap();
        assert_eq!(info.id, "shared-union");
        assert_eq!(info.email, None);
        assert_eq!(info.display_name, "微信昵称");
        let requests = wire.requests.lock().unwrap();
        let token_request = &requests[requests.len() - 2];
        let params: std::collections::BTreeMap<_, _> =
            token_request.query_pairs().into_owned().collect();
        assert_eq!(
            params["appid"],
            if variant == WeChatVariant::Desktop {
                "desktop-app"
            } else {
                "mobile-app"
            }
        );
        assert_eq!(
            params["secret"],
            if variant == WeChatVariant::Desktop {
                "desktop-secret"
            } else {
                "mobile-secret"
            }
        );
        assert_eq!(params["code"], "code +&中文");
        let profile = &requests[requests.len() - 1];
        assert_eq!(profile.path(), "/sns/userinfo");
        assert!(
            profile
                .query_pairs()
                .any(|(k, v)| k == "openid" && v == "shared-openid")
        );
    }
    let adapter = wire.adapter(WeChatVariant::Micromessenger);
    for mode in [1, 2, 8] {
        wire.mode.store(0, Ordering::SeqCst);
        let token = adapter.exchange_code("code", "").await.unwrap();
        wire.mode.store(mode, Ordering::SeqCst);
        assert!(adapter.get_user_info(&token).await.is_err());
    }
    for mode in [3, 4, 5, 7] {
        wire.mode.store(mode, Ordering::SeqCst);
        let before = wire.count();
        let error = adapter
            .exchange_code("code", "")
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret"));
        assert!(!error.contains("fixture-access"));
        assert_eq!(wire.count(), before + 1);
    }
    wire.mode.store(6, Ordering::SeqCst);
    let desktop = wire.adapter(WeChatVariant::Desktop);
    let token = desktop.exchange_code("code", "").await.unwrap();
    assert_eq!(
        desktop.get_user_info(&token).await.unwrap().id,
        "shared-openid"
    );
    assert!(adapter.get_user_info(&token).await.is_err());
    let mobile = adapter.exchange_code("code", "").await.unwrap();
    assert_eq!(
        adapter.get_user_info(&mobile).await.unwrap().id,
        "openid:mobile-app:shared-openid"
    );
}

struct Fixture {
    pool: PgPool,
    other_pool: PgPool,
    diesel: DieselPool,
    first: Service,
    other: Service,
    owner: String,
    app: String,
    provider: String,
    name: String,
    user: String,
    second_user: String,
    wire: Wire,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let other_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let wire = Wire::new().await;
        let transport = Arc::new(WeChatTestTransport::new(&wire.origin).unwrap());
        let build = |pool: PgPool| {
            Service::new(casdog::routes::create_router()).hoop(
                salvo::affix_state::AffixList::new()
                    .inject(pool)
                    .inject(diesel.clone())
                    .inject(transport.clone()),
            )
        };
        let first = build(pool.clone());
        let other = build(other_pool.clone());
        let owner = format!("wx-{}", uuid::Uuid::new_v4());
        let app = uuid::Uuid::new_v4().to_string();
        let provider = uuid::Uuid::new_v4().to_string();
        let name = format!("wechat-{}", uuid::Uuid::new_v4());
        let user = uuid::Uuid::new_v4().to_string();
        let second_user = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'WeChat test')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,client_id,client_secret,client_id2,client_secret2) VALUES($1,$2,$3,'WeChat','OAuth','WeChat','desktop-app','desktop-secret','mobile-app','mobile-secret')").bind(&provider).bind(&owner).bind(&name).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password,enable_idp_signup,providers) VALUES($1,$2,'app','WeChat test',$2,$1,'secret','[]',true,true,$3)").bind(&app).bind(&owner).bind(json!([{"name":format!("{owner}/{name}"),"canSignIn":true,"canSignUp":true,"canUnlink":true}])).execute(&pool).await.unwrap();
        for (id, name, links) in [
            (
                &user,
                "alice",
                json!({format!("oauth:{provider}"):"shared-union"}),
            ),
            (&second_user, "bob", json!({})),
        ] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type,provider_ids,email) VALUES($1,$2,$3,$3,'Password42!','plain',$4,'same@example.test')").bind(id).bind(&owner).bind(name).bind(links).execute(&pool).await.unwrap();
        }
        Self {
            pool,
            other_pool,
            diesel,
            first,
            other,
            owner,
            app,
            provider,
            name,
            user,
            second_user,
            wire,
        }
    }
    async fn start(&self, mobile: bool) -> (String, String, Value) {
        let mut response = TestClient::get(format!(
            "http://localhost/api/auth/{}?application={}",
            self.name, self.app
        ))
        .add_header(
            "User-Agent",
            if mobile {
                "MicroMessenger/8.0"
            } else {
                "Desktop"
            },
            true,
        )
        .send(&self.first)
        .await;
        let status = response.status_code.unwrap_or(StatusCode::OK);
        if status != StatusCode::OK {
            panic!("start {status}: {}", response.take_string().await.unwrap());
        }
        let cookie = cookie(&response, "casdog_oauth_browser=");
        let body: Value = response.take_json().await.unwrap();
        let url = reqwest::Url::parse(body["url"].as_str().unwrap()).unwrap();
        let state = url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .into_owned();
        (state, cookie, body)
    }
    async fn callback(&self, state: &str, browser: &str, mobile: bool) -> Response {
        TestClient::get(format!(
            "http://localhost/api/auth/{}/callback?state={state}&code=valid-code",
            self.name
        ))
        .add_header("Cookie", browser, true)
        .add_header(
            "User-Agent",
            if mobile {
                "MicroMessenger/8.0"
            } else {
                "Desktop"
            },
            true,
        )
        .send(&self.other)
        .await
    }
    async fn session(&self, proof: &str, body: Value) -> Response {
        TestClient::post("http://localhost/api/auth/session")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .add_header("Cookie", proof, true)
            .json(&body)
            .send(&self.first)
            .await
    }
    async fn token(&self, id: &str) -> String {
        let users = UserService::new(self.diesel.clone());
        AuthService::new(users.clone())
            .generate_token(&users.get_by_id(id).await.unwrap())
            .unwrap()
    }
    async fn cleanup(self) {
        for table in ["social_oauth_completions", "social_oauth_flows"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE organization=$1"))
                .bind(&self.owner)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM users WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM applications WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM providers WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE name=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        self.pool.close().await;
        self.other_pool.close().await;
    }
}
fn cookie(response: &Response, prefix: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(prefix))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}
async fn success(response: &mut Response) -> Value {
    let status = response.status_code.unwrap_or(StatusCode::OK);
    if status != StatusCode::OK {
        panic!(
            "response {status}: {}",
            response.take_string().await.unwrap()
        );
    }
    response.take_json().await.unwrap()
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn shared_browser_mobile_and_desktop_callbacks_pin_credentials_despite_changed_user_agent() {
    let f = Fixture::new().await;
    for mobile in [true, false] {
        let (state, browser, auth) = f.start(mobile).await;
        assert!(auth["url"].as_str().unwrap().contains(if mobile {
            "appid=mobile-app"
        } else {
            "appid=desktop-app"
        }));
        let context: Value =
            sqlx::query_scalar("SELECT context FROM social_oauth_flows WHERE state_hash=$1")
                .bind(social_state_service::proof_hash(&state))
                .fetch_one(&f.other_pool)
                .await
                .unwrap();
        assert_eq!(
            context["wechat_flow"]["variant"],
            if mobile { "micromessenger" } else { "desktop" }
        );
        assert!(!context.to_string().contains("mobile-secret"));
        let mut callback = f.callback(&state, &browser, !mobile).await;
        let status = callback.status_code;
        if status != Some(StatusCode::SEE_OTHER) {
            panic!(
                "callback {:?}: {}",
                status,
                callback.take_string().await.unwrap()
            );
        }
        let completion = cookie(&callback, "casdog_oauth_completion=");
        let mut session = f.session(&completion, json!({})).await;
        let signed = success(&mut session).await;
        assert_eq!(signed["user"]["id"], f.user);
        assert!(!signed["token"].as_str().unwrap().is_empty());
        assert_eq!(
            f.callback(&state, &browser, mobile).await.status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            f.session(&completion, json!({})).await.status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
        let requests = f.wire.requests.lock().unwrap();
        let token = &requests[requests.len() - 2];
        let pairs: std::collections::BTreeMap<_, _> = token.query_pairs().into_owned().collect();
        assert_eq!(
            pairs["secret"],
            if mobile {
                "mobile-secret"
            } else {
                "desktop-secret"
            }
        );
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE owner=$1")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn pending_wechat_flow_rejects_rotation_expiry_scope_change_and_identity_mismatch_without_linking()
 {
    let f = Fixture::new().await;
    let (state, browser, _) = f.start(true).await;
    let before = f.wire.count();
    sqlx::query("UPDATE providers SET client_secret2='rotated' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.callback(&state, &browser, false).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.wire.count(), before);
    sqlx::query("UPDATE providers SET client_secret2='mobile-secret' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    let (state, browser, _) = f.start(true).await;
    sqlx::query("UPDATE social_oauth_flows SET expires_at=clock_timestamp()-interval '1 second' WHERE state_hash=$1").bind(social_state_service::proof_hash(&state)).execute(&f.other_pool).await.unwrap();
    assert_eq!(
        f.callback(&state, &browser, false).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.wire.count(), before);
    let (state, browser, _) = f.start(false).await;
    sqlx::query("UPDATE applications SET providers='[]'::jsonb WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    let denied = f.callback(&state, &browser, true).await;
    assert!(matches!(
        denied.status_code,
        Some(StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED)
    ));
    assert_eq!(f.wire.count(), before);
    sqlx::query("UPDATE applications SET providers=$2 WHERE id=$1")
        .bind(&f.app)
        .bind(json!([{"name":format!("{}/{}",f.owner,f.name),"canSignIn":true,"canSignUp":true}]))
        .execute(&f.pool)
        .await
        .unwrap();
    for mode in [1, 2, 8] {
        f.wire.mode.store(mode, Ordering::SeqCst);
        let (state, browser, _) = f.start(true).await;
        let callback = f.callback(&state, &browser, false).await;
        assert_eq!(callback.status_code, Some(StatusCode::UNAUTHORIZED));
        assert!(!callback.headers().get_all("set-cookie").iter().any(|v| {
            v.to_str()
                .unwrap_or_default()
                .starts_with("casdog_oauth_completion=")
        }));
    }
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE owner=$1")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(users, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn actual_wechat_login_requires_totp_and_rechecks_secondary_configuration_before_session() {
    let f = Fixture::new().await;
    let (secret, _) = MfaService::initiate_totp_setup("alice", "WeChat").unwrap();
    sqlx::query("UPDATE users SET mfa_enabled=true,totp_secret=$2 WHERE id=$1")
        .bind(&f.user)
        .bind(&secret)
        .execute(&f.pool)
        .await
        .unwrap();
    MfaService::save_mfa(&f.pool, &f.user, "totp", Some(&secret))
        .await
        .unwrap();
    MfaService::enable_mfa(&f.pool, &f.user, "totp")
        .await
        .unwrap();
    let code = || {
        use totp_rs::{Algorithm, Secret, TOTP};
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
    let (state, browser, _) = f.start(true).await;
    let callback = f.callback(&state, &browser, false).await;
    assert_eq!(callback.status_code, Some(StatusCode::SEE_OTHER));
    let completion = cookie(&callback, "casdog_oauth_completion=");
    let mut response = f.session(&completion, json!({})).await;
    let challenge = success(&mut response).await;
    assert_eq!(challenge["mfa_required"], true);
    assert_eq!(challenge["token"], "");
    assert_eq!(
        f.session(&completion, json!({"mfaType":"app","passcode":"wrong"}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE providers SET client_id2='another-mobile-app' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.other_pool)
        .await
        .unwrap();
    assert_eq!(
        f.session(&completion, json!({"mfaType":"app","passcode":code()}))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE providers SET client_id2='mobile-app' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    let (state, browser, _) = f.start(true).await;
    let callback = f.callback(&state, &browser, false).await;
    let completion = cookie(&callback, "casdog_oauth_completion=");
    let mut response = f
        .session(&completion, json!({"mfaType":"app","passcode":code()}))
        .await;
    let signed = success(&mut response).await;
    assert_eq!(signed["user"]["id"], f.user);
    assert!(signed["token"].as_str().unwrap().len() > 30);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn explicit_wechat_link_uses_pinned_mobile_credentials_and_never_takes_another_users_unionid()
{
    let f = Fixture::new().await;
    let token = f.token(&f.second_user).await;
    let begin = || {
        TestClient::post(format!("http://localhost/api/auth/{}/link", f.name))
            .bearer_auth(&token)
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .add_header("User-Agent", "MicroMessenger/8", true)
            .json(&json!({"application":f.app}))
    };
    let mut response = begin().send(&f.first).await;
    let browser = cookie(&response, "casdog_oauth_browser=");
    let auth = success(&mut response).await;
    let url = reqwest::Url::parse(auth["url"].as_str().unwrap()).unwrap();
    assert!(
        url.query_pairs()
            .any(|(k, v)| k == "appid" && v == "mobile-app")
    );
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(
        f.callback(&state, &browser, false).await.status_code,
        Some(StatusCode::CONFLICT)
    );
    let unchanged: Value = sqlx::query_scalar("SELECT provider_ids FROM users WHERE id=$1")
        .bind(&f.second_user)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(unchanged, json!({}));
    sqlx::query("UPDATE users SET provider_ids='{}'::jsonb WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut response = begin().send(&f.first).await;
    let browser = cookie(&response, "casdog_oauth_browser=");
    let auth = success(&mut response).await;
    let url = reqwest::Url::parse(auth["url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let callback = f.callback(&state, &browser, false).await;
    assert_eq!(callback.status_code, Some(StatusCode::SEE_OTHER));
    assert_eq!(
        callback.headers().get("location").unwrap(),
        "/?social=linked"
    );
    let linked: Value = sqlx::query_scalar("SELECT provider_ids FROM users WHERE id=$1")
        .bind(&f.second_user)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(linked[format!("oauth:{}", f.provider)], "shared-union");
    assert_eq!(
        f.callback(&state, &browser, true).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn wechat_shared_state_rechecks_network_revocation_and_confines_identical_unionids_to_tenants()
 {
    let f = Fixture::new().await;
    sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin','built-in','Built in') ON CONFLICT(name) DO NOTHING").bind(uuid::Uuid::new_v4().to_string()).execute(&f.pool).await.unwrap();
    let admin = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,'built-in',$1,'WeChat network reviewer','unused',true)").bind(&admin).execute(&f.pool).await.unwrap();
    let token = f.token(&admin).await;
    let mut approve = TestClient::post(format!(
        "http://localhost/api/providers/{}/network-approval",
        f.provider
    ))
    .bearer_auth(&token)
    .json(&json!({"allow_private":true}))
    .send(&f.first)
    .await;
    // Official built-ins deliberately cannot acquire arbitrary private endpoint
    // exceptions. Verify that normal API boundary before simulating a historical
    // durable grant; its later revocation must still invalidate a pending flow.
    let status = approve.status_code;
    let body: Value = approve.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::BAD_REQUEST), "{body}");
    assert!(
        body["details"]
            .as_str()
            .unwrap_or_default()
            .contains("explicit authorization, token and user-info URLs"),
        "{body}"
    );
    let saved: casdog::models::Provider = sqlx::query_as("SELECT * FROM providers WHERE id=$1")
        .bind(&f.provider)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO oauth_provider_network_approvals(provider_id,configuration_stamp,generation,approved_by) VALUES($1,$2,$3,$4)")
        .bind(&f.provider).bind(casdog::services::provider_network_service::configuration_stamp(&saved)).bind(uuid::Uuid::new_v4().to_string()).bind(&admin).execute(&f.pool).await.unwrap();
    let (state, browser, _) = f.start(true).await;
    let count = f.wire.count();
    let revoke = TestClient::delete(format!(
        "http://localhost/api/providers/{}/network-approval",
        f.provider
    ))
    .bearer_auth(&token)
    .send(&f.other)
    .await;
    assert_eq!(revoke.status_code, Some(StatusCode::OK));
    assert_eq!(
        f.callback(&state, &browser, false).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.wire.count(), count);
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(&admin)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut g = Fixture::new().await;
    sqlx::query("UPDATE providers SET name=$2 WHERE id=$1")
        .bind(&g.provider)
        .bind(&f.name)
        .execute(&g.pool)
        .await
        .unwrap();
    g.name = f.name.clone();
    sqlx::query("UPDATE applications SET providers=$2 WHERE id=$1")
        .bind(&g.app)
        .bind(json!([{"name":format!("{}/{}",g.owner,g.name),"canSignIn":true,"canSignUp":true}]))
        .execute(&g.pool)
        .await
        .unwrap();
    for fixture in [&f, &g] {
        let (state, browser, _) = fixture.start(true).await;
        let callback = fixture.callback(&state, &browser, false).await;
        assert_eq!(callback.status_code, Some(StatusCode::SEE_OTHER));
        let completion = cookie(&callback, "casdog_oauth_completion=");
        let mut session = fixture.session(&completion, json!({})).await;
        let login = success(&mut session).await;
        assert_eq!(login["user"]["id"], fixture.user);
        assert_eq!(login["user"]["owner"], fixture.owner);
    }
    g.cleanup().await;
    f.cleanup().await;
}
