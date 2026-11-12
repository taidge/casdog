//! Real custom-template / OIDC discovery HTTP protocols and PostgreSQL browser proofs.
use base64::Engine;
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    models::Provider,
    services::providers::{
        generic_oauth::{self as generic, GenericOAuthProvider},
        oauth_provider::{self as oauth, OAuthExchangeContext, OAuthProviderTrait, OAuthToken},
    },
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sha2::Digest;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const SECRET: &str = "secret &/=+?#value";
const ACCESS: &str = "token+&/=percent%value";
const SUBJECT: &str = "person/+&?=#value";
fn mapping() -> Value {
    json!({"id":"data.id","username":"data.username","displayName":"data.name","email":"data.email"})
}
fn record(origin: &str, oidc: bool) -> Provider {
    let now = chrono::Utc::now();
    let mut data = json!({"id":"provider-id","owner":"tenant","name":"provider","created_at":now,"updated_at":now,"display_name":"Provider","category":"OAuth","type":if oidc{"OIDC"}else{"Custom"},"disable_ssl":false,"enable_sign_authn_request":false,
        "client_id":"client-id","client_secret":SECRET,"scopes":"openid custom-scope","user_mapping":mapping().to_string(),"http_headers":json!({"X-Endpoint-Key":"header-secret"}).to_string()});
    if oidc {
        data["domain"] = json!(format!("{origin}/issuer"));
    } else {
        data["custom_auth_url"] = json!(format!("{origin}/authorize"));
        data["custom_token_url"] = json!(format!(
            "{origin}/template-token?appid={{clientId}}&secret={{clientSecret}}&code={{code}}&redirect={{redirectUri}}&state={{state}}&verifier={{codeVerifier}}&fixed=retained"
        ));
        data["custom_user_info_url"] = json!(format!(
            "{origin}/template-userinfo?token={{access_token}}&openid={{openid}}&appid={{clientId}}&state={{state}}"
        ));
    }
    serde_json::from_value(data).unwrap()
}
#[test]
fn template_authority_parameter_keys_and_protocol_headers_cannot_be_substituted() {
    for endpoint in [
        "https://{clientId}/token?code={code}",
        "https://idp.test/{clientSecret}?code={code}",
        "https://idp.test/token?{code}=x",
        "https://idp.test/token?x={unknown}",
        "https://idp.test/token?x={bad-name}",
    ] {
        assert!(
            generic::validate_template(endpoint, true).is_err(),
            "{endpoint}"
        );
    }
    assert!(
        generic::validate_template("https://idp.test/user/{openid}?token={access_token}", false)
            .is_ok()
    );
    let mut provider = record("https://idp.test", false);
    provider.custom_auth_url = Some("https://idp.test/auth?secret={clientSecret}".into());
    assert!(oauth::validate_oauth_configuration(&provider).is_err());
    provider = record("https://idp.test", false);
    for name in [
        "Host",
        "Authorization",
        "Content-Type",
        "Content-Length",
        "Connection",
        "Cookie",
        "X-Forwarded-Host",
    ] {
        provider.http_headers = Some(json!({name:"header-secret"}).to_string());
        let error = oauth::validate_oauth_configuration(&provider)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("header-secret"));
    }
    provider = record("https://idp.test", false);
    provider.http_headers = Some(json!({"X-Key":"secret\r\nHost: attacker"}).to_string());
    assert!(oauth::validate_oauth_configuration(&provider).is_err());
    provider = record("https://idp.test", false);
    let stamp = oauth::configuration_stamp(&provider);
    provider.http_headers = Some(json!({"X-Endpoint-Key":"changed"}).to_string());
    assert_ne!(stamp, oauth::configuration_stamp(&provider));
}
struct Wire {
    origin: String,
    mode: Arc<AtomicU8>,
    hits: Arc<AtomicUsize>,
    discovery: Arc<AtomicUsize>,
    trap: Arc<AtomicUsize>,
    expected: Arc<Mutex<(String, String, String)>>,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Wire {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let hits = Arc::new(AtomicUsize::new(0));
        let discovery = Arc::new(AtomicUsize::new(0));
        let trap = Arc::new(AtomicUsize::new(0));
        let expected = Arc::new(Mutex::new((String::new(), String::new(), String::new())));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (o, m, h, d, t, e, r) = (
            origin.clone(),
            mode.clone(),
            hits.clone(),
            discovery.clone(),
            trap.clone(),
            expected.clone(),
            requests.clone(),
        );
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (o, m, h, d, t, e, r) = (
                    o.clone(),
                    m.clone(),
                    h.clone(),
                    d.clone(),
                    t.clone(),
                    e.clone(),
                    r.clone(),
                );
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let end = loop {
                        let mut data = [0; 4096];
                        let n = stream.read(&mut data).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&data[..n]);
                        assert!(bytes.len() < 131072);
                        if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                            let length = String::from_utf8_lossy(&bytes[..end])
                                .lines()
                                .find_map(|line| {
                                    let (k, v) = line.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            if bytes.len() >= end + 4 + length {
                                break end;
                            }
                        }
                    };
                    h.fetch_add(1, Ordering::SeqCst);
                    let head = String::from_utf8_lossy(&bytes[..end]);
                    let line = head.lines().next().unwrap().to_owned();
                    r.lock().unwrap().push(line.clone());
                    let target = line.split(' ').nth(1).unwrap();
                    let mode = m.load(Ordering::SeqCst);
                    assert!(
                        head.to_ascii_lowercase()
                            .contains("x-endpoint-key: header-secret")
                    );
                    let mut status = "200 OK";
                    let mut extra = String::new();
                    let body;
                    if target == "/issuer/.well-known/openid-configuration" {
                        d.fetch_add(1, Ordering::SeqCst);
                        let mut doc = json!({"issuer":format!("{o}/issuer"),"authorization_endpoint":format!("{o}/authorize"),"token_endpoint":format!("{o}/oidc-token"),"userinfo_endpoint":format!("{o}/oidc-userinfo"),"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["client_secret_post"]});
                        if mode == 1 {
                            doc["issuer"] = json!(format!("{o}/wrong-issuer"));
                        }
                        if mode == 2 {
                            status = "302 Found";
                            extra = "Location: /trap\r\n".into();
                        }
                        if mode == 3 {
                            doc.as_object_mut().unwrap().remove("userinfo_endpoint");
                        }
                        if mode == 9 {
                            // JWKS advertises a possible ID-token-only flow,
                            // but metadata alone must never authenticate it.
                            doc.as_object_mut().unwrap().remove("userinfo_endpoint");
                            doc["jwks_uri"] = json!(format!("{o}/jwks"));
                        }
                        if mode == 5 {
                            doc["userinfo_endpoint"] = json!("https://127.0.0.1:1/other-service");
                        }
                        body = if mode == 4 {
                            "x".repeat(1024 * 1024 + 1)
                        } else {
                            doc.to_string()
                        };
                    } else if target == "/jwks" && mode == 9 {
                        body = json!({"keys":[]}).to_string();
                    } else if target == "/template-token" || target == "/oidc-token" {
                        assert!(line.starts_with("POST "));
                        assert!(!line.contains('?'));
                        assert!(!line.contains("secret"));
                        let parsed = reqwest::Url::parse(&format!(
                            "http://local/?{}",
                            String::from_utf8_lossy(&bytes[end + 4..])
                        ))
                        .unwrap();
                        let form: std::collections::BTreeMap<_, _> =
                            parsed.query_pairs().into_owned().collect();
                        assert_eq!(
                            form[if target == "/template-token" {
                                "secret"
                            } else {
                                "client_secret"
                            }],
                            SECRET
                        );
                        assert_eq!(form["code"], "good-code");
                        let verifier = &form[if target == "/template-token" {
                            "verifier"
                        } else {
                            "code_verifier"
                        }];
                        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(sha2::Sha256::digest(verifier.as_bytes()));
                        let expected = e.lock().unwrap();
                        assert_eq!(challenge, expected.1);
                        if target == "/template-token" {
                            assert_eq!(form["state"], expected.0);
                            assert_eq!(form["fixed"], "retained");
                            assert_eq!(form["redirect"], expected.2);
                        }
                        let mut token = json!({"access_token":ACCESS,"token_type":"Bearer","openid":SUBJECT,"id_token":"not-a-trusted-identity-token"});
                        if mode == 6 {
                            token.as_object_mut().unwrap().remove("openid");
                        }
                        if mode == 7 {
                            status = "400 Bad Request";
                        }
                        body = if mode == 8 {
                            format!("invalid JSON {SECRET}")
                        } else {
                            token.to_string()
                        };
                    } else if target.starts_with("/template-userinfo?")
                        || target == "/oidc-userinfo"
                    {
                        if target.starts_with("/template-") {
                            assert!(!head.to_ascii_lowercase().contains("authorization:"));
                            let url =
                                reqwest::Url::parse(&format!("http://local{target}")).unwrap();
                            let query: std::collections::BTreeMap<_, _> =
                                url.query_pairs().into_owned().collect();
                            assert_eq!(query["token"], ACCESS);
                            assert_eq!(query["openid"], SUBJECT);
                            assert_eq!(query["state"], e.lock().unwrap().0);
                        } else {
                            assert!(head.contains(&format!("Bearer {ACCESS}")));
                        }
                        body=json!({"data":{"id":SUBJECT,"username":"endpoint-user","name":"Endpoint User","email":"same@example.test"}}).to_string();
                    } else {
                        t.fetch_add(1, Ordering::SeqCst);
                        status = "500 Internal Server Error";
                        body = "unexpected endpoint".into();
                    }
                    let _=stream.write_all(format!("HTTP/1.1 {status}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await;
                });
            }
        });
        Self {
            origin,
            mode,
            hits,
            discovery,
            trap,
            expected,
            requests,
            task,
        }
    }
    fn expect(&self, state: &str, verifier: &str) {
        *self.expected.lock().unwrap() = (
            state.into(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(verifier.as_bytes())),
            "https://app.test/callback".into(),
        );
    }
    fn expect_url(&self, url: &str) {
        let url = reqwest::Url::parse(url).unwrap();
        let values: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(values["code_challenge_method"], "S256");
        *self.expected.lock().unwrap() = (
            values["state"].clone(),
            values["code_challenge"].clone(),
            values["redirect_uri"].clone(),
        );
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[tokio::test]
async fn templates_post_secrets_in_form_preserve_token_extras_and_never_follow_identity_defaults() {
    let wire = Wire::start().await;
    let provider = record(&wire.origin, false);
    let endpoints = generic::resolve_endpoints(&provider, true).await.unwrap();
    let client = GenericOAuthProvider::from_resolved(&provider, &endpoints, true).unwrap();
    let context = OAuthExchangeContext {
        state: "server-state".into(),
        code_verifier: Some("v".repeat(64)),
        ..Default::default()
    };
    wire.expect(&context.state, context.code_verifier.as_deref().unwrap());
    let token = client
        .exchange_code_token("good-code", "https://app.test/callback", &context)
        .await
        .unwrap();
    assert_eq!(token.extra["openid"], SUBJECT);
    // Reconstruct the adapter for another stage: no per-instance token cache.
    let other = GenericOAuthProvider::from_resolved(&provider, &endpoints, true).unwrap();
    let info = other.get_user_info_token(&token, &context).await.unwrap();
    assert_eq!(info.id, SUBJECT);
    assert_eq!(info.email.as_deref(), Some("same@example.test"));
    assert!(!wire.requests.lock().unwrap()[0].contains(SECRET));
    let mut imprecise = OAuthToken {
        access_token: token.access_token.clone(),
        extra: token.extra.clone(),
    };
    imprecise.extra["openid"] = json!(1.25);
    let before = wire.hits.load(Ordering::SeqCst);
    assert!(
        other
            .get_user_info_token(&imprecise, &context)
            .await
            .is_err()
    );
    assert_eq!(wire.hits.load(Ordering::SeqCst), before);
    wire.mode.store(6, Ordering::SeqCst);
    let token = client
        .exchange_code_token("good-code", "https://app.test/callback", &context)
        .await
        .unwrap();
    let before = wire.hits.load(Ordering::SeqCst);
    assert!(other.get_user_info_token(&token, &context).await.is_err());
    assert_eq!(wire.hits.load(Ordering::SeqCst), before);
    for mode in [7, 8] {
        wire.mode.store(mode, Ordering::SeqCst);
        let result = client
            .exchange_code_token("good-code", "https://app.test/callback", &context)
            .await;
        assert!(result.is_err());
        assert!(!result.err().unwrap().to_string().contains(SECRET));
    }
    assert_eq!(wire.trap.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn discovery_checks_issuer_http_status_bounds_userinfo_and_header_destination_before_authentication()
 {
    let wire = Wire::start().await;
    let provider = record(&wire.origin, true);
    assert!(generic::resolve_endpoints(&provider, false).await.is_err());
    assert_eq!(wire.hits.load(Ordering::SeqCst), 0);
    let resolved = generic::resolve_endpoints(&provider, true).await.unwrap();
    assert!(resolved.pkce_s256);
    assert_eq!(resolved.token_url, format!("{}/oidc-token", wire.origin));
    for mode in [1, 2, 3, 4, 5] {
        wire.mode.store(mode, Ordering::SeqCst);
        assert!(
            generic::resolve_endpoints(&provider, true).await.is_err(),
            "mode {mode}"
        );
    }
    wire.mode.store(9, Ordering::SeqCst);
    let identity_only = generic::resolve_endpoints(&provider, true).await.unwrap();
    assert!(identity_only.user_info_url.is_empty());
    assert_eq!(
        identity_only.jwks_url,
        Some(format!("{}/jwks", wire.origin))
    );
    assert_eq!(wire.trap.load(Ordering::SeqCst), 0);
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
fn jwt(id: &str, name: &str) -> String {
    let now = chrono::Utc::now();
    jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({"sub":id,"owner":"built-in","name":name,"is_admin":true,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"exp":now.timestamp()+3600,"iss":AppConfig::get().jwt.issuer}),&jsonwebtoken::EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
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
        .to_owned()
}
struct Fixture {
    pool: PgPool,
    service: Service,
    other: Service,
    wire: Wire,
    owner: String,
    foreign: String,
    app: String,
    other_app: String,
    provider: String,
    name: String,
    admin: String,
    admin_name: String,
    user: String,
}
impl Fixture {
    async fn new(oidc: bool) -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let other_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel.clone()),
        );
        let other = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(other_pool)
                .inject(diesel),
        );
        let owner = format!("endpoints-{}", uuid::Uuid::new_v4());
        let foreign = format!("foreign-{}", uuid::Uuid::new_v4());
        let app = uuid::Uuid::new_v4().to_string();
        let other_app = uuid::Uuid::new_v4().to_string();
        let admin = uuid::Uuid::new_v4().to_string();
        let admin_name = format!("endpoint-admin-{}", uuid::Uuid::new_v4());
        let user = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin','built-in','Built in') ON CONFLICT(name) DO NOTHING").bind(uuid::Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
        for org in [&owner, &foreign] {
            sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,'Endpoints')").bind(uuid::Uuid::new_v4().to_string()).bind(org).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,'built-in',$2,'Admin','unused',true)").bind(&admin).bind(&admin_name).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,email,email_verified) VALUES($1,$2,'existing','Existing','unused','same@example.test',true)").bind(&user).bind(&owner).execute(&pool).await.unwrap();
        let wire = Wire::start().await;
        let raw = record(&wire.origin, oidc);
        let name = format!("endpoint-{}", uuid::Uuid::new_v4());
        let body = json!({"owner":owner,"name":name,"display_name":"Endpoints","category":"OAuth","type":raw.provider_type,"client_id":raw.client_id,"client_secret":raw.client_secret,"scopes":raw.scopes,"domain":raw.domain,"issuer_url":raw.issuer_url,"custom_auth_url":raw.custom_auth_url,"custom_token_url":raw.custom_token_url,"custom_user_info_url":raw.custom_user_info_url,"user_mapping":mapping(),"http_headers":{"X-Endpoint-Key":"header-secret"}});
        let mut response = TestClient::post("http://localhost/api/providers")
            .bearer_auth(jwt(&admin, &admin_name))
            .json(&body)
            .send(&service)
            .await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
        let provider = body["id"].as_str().unwrap().to_owned();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_idp_signup,providers) VALUES($1,$2,$1,'Endpoints',$2,$1,'secret','',true,$3)").bind(&app).bind(&owner).bind(json!([{"name":format!("{owner}/{name}"),"canSignIn":true,"canSignUp":true}])).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_idp_signup,providers) VALUES($1,$2,$1,'Foreign',$2,$1,'secret','',true,'[]')").bind(&other_app).bind(&foreign).execute(&pool).await.unwrap();
        Self {
            pool,
            service,
            other,
            wire,
            owner,
            foreign,
            app,
            other_app,
            provider,
            name,
            admin,
            admin_name,
            user,
        }
    }
    async fn approve(&self) {
        assert_eq!(
            TestClient::post(format!(
                "http://localhost/api/providers/{}/network-approval",
                self.provider
            ))
            .bearer_auth(jwt(&self.admin, &self.admin_name))
            .json(&json!({"allow_private":true}))
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
        let status = response.status_code;
        let browser = cookie(&response, "casdog_oauth_browser=");
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
        let url = body["url"].as_str().unwrap();
        assert!(!url.contains(SECRET));
        self.wire.expect_url(url);
        let parsed = reqwest::Url::parse(url).unwrap();
        (
            parsed
                .query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1
                .into_owned(),
            browser,
        )
    }
    async fn callback(&self, state: &str, browser: &str) -> Response {
        TestClient::get(format!(
            "http://localhost/api/auth/{}/callback?code=good-code&state={state}&application={}",
            self.name, self.other_app
        ))
        .add_header("cookie", browser, true)
        .send(&self.other)
        .await
    }
    async fn complete(&self, proof: &str) -> Response {
        TestClient::post("http://localhost/api/auth/session")
            .add_header("origin", origin(), true)
            .add_header("cookie", proof, true)
            .send(&self.service)
            .await
    }
    async fn cleanup(&self) {
        for owner in [&self.owner, &self.foreign] {
            for sql in [
                "DELETE FROM social_oauth_completions WHERE organization=$1",
                "DELETE FROM social_oauth_flows WHERE organization=$1",
                "DELETE FROM users WHERE owner=$1",
                "DELETE FROM applications WHERE organization=$1",
                "DELETE FROM providers WHERE owner=$1",
                "DELETE FROM organizations WHERE name=$1",
            ] {
                sqlx::query(sql)
                    .bind(owner)
                    .execute(&self.pool)
                    .await
                    .unwrap();
            }
        }
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(&self.admin)
            .execute(&self.pool)
            .await
            .unwrap();
    }
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through OAuth approvals"]
async fn native_template_provider_cross_instance_callback_uses_token_extras_without_email_linking()
{
    let f = Fixture::new(false).await;
    f.approve().await;
    let (state, browser) = f.begin().await;
    // Template callback URI is fixed by the server, not the request's unrelated
    // application parameter; use it as the protocol fixture's expected value.
    let response = f.callback(&state, &browser).await;
    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let proof = cookie(&response, "casdog_oauth_completion=");
    let mut signed = f.complete(&proof).await;
    let status = signed.status_code;
    let body: Value = signed.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    assert_ne!(body["user"]["id"], f.user);
    assert_eq!(body["user"]["owner"], f.owner);
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert!(!body.to_string().contains(SECRET));
    assert_eq!(f.wire.trap.load(Ordering::SeqCst), 0);
    assert!(
        f.wire
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|line| line == "POST /template-token HTTP/1.1")
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through OAuth approvals"]
async fn issuer_only_discovery_is_visible_and_persists_pkce_and_endpoint_snapshot_across_instances()
{
    let f = Fixture::new(true).await;
    let mut listed = TestClient::get(format!(
        "http://localhost/api/auth/providers?application={}",
        f.app
    ))
    .send(&f.service)
    .await;
    assert!(listed.take_string().await.unwrap().contains(&f.name));
    assert_eq!(f.wire.hits.load(Ordering::SeqCst), 0);
    f.approve().await;
    let (state, browser) = f.begin().await;
    assert_eq!(f.wire.discovery.load(Ordering::SeqCst), 1);
    // Changing metadata after begin cannot swap endpoints or bypass the
    // browser-authorized issuer: the callback uses its persisted snapshot.
    f.wire.mode.store(1, Ordering::SeqCst);
    let response = f.callback(&state, &browser).await;
    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let proof = cookie(&response, "casdog_oauth_completion=");
    let mut response = f.complete(&proof).await;
    let body: Value = response.take_json().await.unwrap();
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert_eq!(f.wire.discovery.load(Ordering::SeqCst), 1);
    assert_ne!(body["user"]["id"], f.user);
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL migrated through OAuth approvals"]
async fn failed_discovery_creates_no_state_foreign_application_makes_no_requests_and_revocation_stops_exchange()
 {
    let f = Fixture::new(true).await;
    f.approve().await;
    for mode in [1, 2, 3, 4, 5] {
        f.wire.mode.store(mode, Ordering::SeqCst);
        let response = TestClient::get(format!(
            "http://localhost/api/auth/{}?application={}",
            f.name, f.app
        ))
        .send(&f.service)
        .await;
        assert_ne!(response.status_code, Some(StatusCode::OK));
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM social_oauth_flows WHERE organization=$1")
                .bind(&f.owner)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
    }
    let before = f.wire.hits.load(Ordering::SeqCst);
    let foreign = TestClient::get(format!(
        "http://localhost/api/auth/{}?application={}",
        f.name, f.other_app
    ))
    .send(&f.service)
    .await;
    assert_eq!(foreign.status_code, Some(StatusCode::FORBIDDEN));
    assert_eq!(f.wire.hits.load(Ordering::SeqCst), before);
    f.wire.mode.store(9, Ordering::SeqCst);
    let (state, browser) = f.begin().await;
    let denied = f.callback(&state, &browser).await;
    assert_eq!(denied.status_code, Some(StatusCode::UNAUTHORIZED));
    assert!(!denied.headers().get_all("set-cookie").iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|value| value.starts_with("casdog_oauth_completion="))
    }));
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE owner=$1")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        users, 1,
        "advertised JWKS must not authenticate an unverified token"
    );
    let completions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM social_oauth_completions WHERE organization=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(completions, 0);
    f.wire.mode.store(0, Ordering::SeqCst);
    let (state, browser) = f.begin().await;
    assert_eq!(
        TestClient::delete(format!(
            "http://localhost/api/providers/{}/network-approval",
            f.provider
        ))
        .bearer_auth(jwt(&f.admin, &f.admin_name))
        .send(&f.service)
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    let before = f.wire.hits.load(Ordering::SeqCst);
    assert_eq!(
        f.callback(&state, &browser).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.wire.hits.load(Ordering::SeqCst), before);
    f.cleanup().await;
}
