//! Signed OIDC identities over real discovery/token/JWKS HTTP and durable PG flows.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    models::Provider,
    services::providers::{
        generic_oauth::{self as generic, GenericOAuthProvider},
        oauth_provider::{self as oauth, OAuthExchangeContext, OAuthProviderTrait},
        oidc_identity,
    },
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::{pkcs8::EncodePrivateKey, traits::PublicKeyParts};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sha2::Digest;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{
    Arc, LazyLock, Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const SECRET: &str = "oidc-secret &+:/";
const SUBJECT: &str = "signed-subject";
const ACCESS: &str = "oidc-access-token";
const NONCE: &str = "server-owned-oidc-nonce-0123456789abcdef";
static RSA: LazyLock<rsa::RsaPrivateKey> =
    LazyLock::new(|| rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap());
fn rsa_jwk() -> Value {
    json!({"kty":"RSA","kid":"rsa-key","use":"sig","alg":"RS256","n":URL_SAFE_NO_PAD.encode(RSA.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(RSA.e().to_bytes_be())})
}
fn rsa_sign(claims: &Value) -> String {
    let pem = RSA.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("rsa-key".into());
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap()
}
fn claims(issuer: &str, nonce: &str) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({"iss":issuer,"sub":SUBJECT,"aud":"client-id","exp":now+300,"iat":now,"nonce":nonce,"preferred_username":"signed-user","name":"Signed User","email":"same@example.test","email_verified":true})
}
fn verify(raw: &str, keys: &Value, issuer: &str) -> bool {
    oidc_identity::verify(
        raw,
        keys,
        issuer,
        "client-id",
        NONCE,
        chrono::Utc::now().timestamp(),
        &["RS256".into(), "ES256".into()],
        ACCESS,
    )
    .is_ok()
}
#[test]
fn rsa_identity_rejects_claim_confusion_replay_ambiguous_private_and_weak_keys() {
    let issuer = "https://issuer.test/tenant";
    let jwks = json!({"keys":[rsa_jwk()]});
    let good = claims(issuer, NONCE);
    assert!(verify(&rsa_sign(&good), &jwks, issuer));
    for (name, alg) in [
        ("RS256", Algorithm::RS256),
        ("RS384", Algorithm::RS384),
        ("RS512", Algorithm::RS512),
        ("PS256", Algorithm::PS256),
        ("PS384", Algorithm::PS384),
        ("PS512", Algorithm::PS512),
    ] {
        let pem = RSA.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let mut header = Header::new(alg);
        header.kid = Some("rsa-key".into());
        let raw = jsonwebtoken::encode(
            &header,
            &good,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap();
        let mut key = rsa_jwk();
        key["alg"] = json!(name);
        assert!(
            oidc_identity::verify(
                &raw,
                &json!({"keys":[key]}),
                issuer,
                "client-id",
                NONCE,
                chrono::Utc::now().timestamp(),
                &[name.into()],
                ACCESS
            )
            .is_ok(),
            "{name}"
        );
    }
    for (key, value) in [
        ("iss", json!("https://other.test")),
        ("aud", json!("other-client")),
        ("aud", json!(["client-id", "other"])),
        ("azp", json!("other-client")),
        ("exp", json!(chrono::Utc::now().timestamp() - 120)),
        ("iat", json!(chrono::Utc::now().timestamp() + 120)),
        ("iat", json!(chrono::Utc::now().timestamp() - 120)),
        ("nonce", json!("another-flow")),
        ("sub", json!("")),
        ("sub", json!(77)),
        ("at_hash", json!("invalid")),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(!verify(&rsa_sign(&bad), &jwks, issuer), "claim {key}");
    }
    let mut multi = good.clone();
    multi["aud"] = json!(["client-id", "other"]);
    multi["azp"] = json!("client-id");
    assert!(verify(&rsa_sign(&multi), &jwks, issuer));
    let mut hashed = good.clone();
    let digest = sha2::Sha256::digest(ACCESS.as_bytes());
    hashed["at_hash"] = json!(URL_SAFE_NO_PAD.encode(&digest[..16]));
    assert!(verify(&rsa_sign(&hashed), &jwks, issuer));
    let raw = rsa_sign(&good);
    let mut bytes = raw.into_bytes();
    let last = bytes.len() - 8;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    assert!(!verify(std::str::from_utf8(&bytes).unwrap(), &jwks, issuer));
    let mut jwk = rsa_jwk();
    jwk["d"] = json!("private");
    assert!(!verify(&rsa_sign(&good), &json!({"keys":[jwk]}), issuer));
    assert!(!verify(
        &rsa_sign(&good),
        &json!({"keys":[rsa_jwk(),rsa_jwk()]}),
        issuer
    ));
    for (key, value) in [
        ("kid", json!("wrong")),
        ("alg", json!("HS256")),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("n", json!("AQAB")),
    ] {
        let mut jwk = rsa_jwk();
        jwk[key] = value;
        assert!(!verify(&rsa_sign(&good), &json!({"keys":[jwk]}), issuer));
    }
    let mut h = Header::new(Algorithm::HS256);
    h.kid = Some("rsa-key".into());
    let raw = jsonwebtoken::encode(
        &h,
        &good,
        &EncodingKey::from_secret(b"public-key-is-not-an-HMAC-secret"),
    )
    .unwrap();
    assert!(!verify(&raw, &jwks, issuer));
    assert!(oidc_identity::strict_json(br#"{"keys":[],"keys":[{}]}"#).is_err());
    assert!(oidc_identity::strict_json(br#"{"nested":{"sub":"a","sub":"b"}}"#).is_err());
}
#[test]
fn es256_uses_a_real_p256_public_point_and_exact_curve_algorithm() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let key = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let point = key.public_key().to_encoded_point(false);
    let pem = key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("ec-key".into());
    let issuer = "https://ec.test";
    let raw = jsonwebtoken::encode(
        &header,
        &claims(issuer, NONCE),
        &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let mut jwk = json!({"kty":"EC","kid":"ec-key","alg":"ES256","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())});
    assert!(verify(&raw, &json!({"keys":[jwk.clone()]}), issuer));
    jwk["crv"] = json!("P-384");
    assert!(!verify(&raw, &json!({"keys":[jwk.clone()]}), issuer));
    jwk["crv"] = json!("P-256");
    jwk["x"] = json!(URL_SAFE_NO_PAD.encode([0u8; 32]));
    jwk["y"] = json!(URL_SAFE_NO_PAD.encode([0u8; 32]));
    assert!(!verify(&raw, &json!({"keys":[jwk]}), issuer));
}
fn record(origin: &str) -> Provider {
    let now = chrono::Utc::now();
    serde_json::from_value(json!({"id":"oidc-id","owner":"tenant","name":"oidc","display_name":"OIDC","created_at":now,"updated_at":now,"category":"OAuth","type":"OIDC","disable_ssl":false,"enable_sign_authn_request":false,"domain":format!("{origin}/issuer"),"client_id":"client-id","client_secret":SECRET})).unwrap()
}
struct Wire {
    origin: String,
    mode: Arc<AtomicU8>,
    hits: Arc<AtomicUsize>,
    jwks_hits: Arc<AtomicUsize>,
    token_hits: Arc<AtomicUsize>,
    expected: Arc<Mutex<(String, String)>>,
    revoke: Arc<Mutex<Option<(String, PgPool, String)>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Wire {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let hits = Arc::new(AtomicUsize::new(0));
        let jwks_hits = Arc::new(AtomicUsize::new(0));
        let token_hits = Arc::new(AtomicUsize::new(0));
        let expected: Arc<Mutex<(String, String)>> =
            Arc::new(Mutex::new((NONCE.to_owned(), String::new())));
        let revoke = Arc::new(Mutex::new(None::<(String, PgPool, String)>));
        let (o, m, h, j, t, e, r) = (
            origin.clone(),
            mode.clone(),
            hits.clone(),
            jwks_hits.clone(),
            token_hits.clone(),
            expected.clone(),
            revoke.clone(),
        );
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (o, m, h, j, t, e, r) = (
                    o.clone(),
                    m.clone(),
                    h.clone(),
                    j.clone(),
                    t.clone(),
                    e.clone(),
                    r.clone(),
                );
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let end = loop {
                        let mut buffer = [0; 4096];
                        let count = stream.read(&mut buffer).await.unwrap();
                        if count == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&buffer[..count]);
                        assert!(bytes.len() < 131072);
                        if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                            let size = String::from_utf8_lossy(&bytes[..end])
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            if bytes.len() >= end + 4 + size {
                                break end;
                            }
                        }
                    };
                    h.fetch_add(1, Ordering::SeqCst);
                    let head = String::from_utf8_lossy(&bytes[..end]);
                    let path = head.lines().next().unwrap().split(' ').nth(1).unwrap();
                    let mode = m.load(Ordering::SeqCst);
                    let mut status = "200 OK";
                    let mut extra = String::new();
                    let body;
                    if path == "/issuer/.well-known/openid-configuration" {
                        let mut doc = json!({"issuer":format!("{o}/issuer"),"authorization_endpoint":format!("{o}/authorize"),"token_endpoint":format!("{o}/token"),"jwks_uri":format!("{o}/jwks"),"id_token_signing_alg_values_supported":["RS256"],"code_challenge_methods_supported":["S256"]});
                        if [2, 3, 7, 8, 9].contains(&mode) {
                            doc["userinfo_endpoint"] = json!(format!("{o}/userinfo"));
                        }
                        if mode == 4 {
                            doc["token_endpoint_auth_methods_supported"] =
                                json!(["client_secret_post"]);
                        }
                        if mode == 5 {
                            doc["token_endpoint_auth_methods_supported"] = json!(["none"]);
                        }
                        if mode == 10 {
                            doc["jwks_uri"] = json!("http://127.0.0.1:1/private");
                        }
                        body = doc.to_string();
                    } else if path == "/token" {
                        t.fetch_add(1, Ordering::SeqCst);
                        assert!(head.starts_with("POST /token "));
                        assert!(!path.contains('?'));
                        let parsed = reqwest::Url::parse(&format!(
                            "http://local/?{}",
                            String::from_utf8_lossy(&bytes[end + 4..])
                        ))
                        .unwrap();
                        let form: std::collections::BTreeMap<_, _> =
                            parsed.query_pairs().into_owned().collect();
                        assert_eq!(form["code"], "good-code");
                        if mode == 4 {
                            assert_eq!(form["client_secret"], SECRET);
                            assert!(!head.to_ascii_lowercase().contains("authorization:"));
                        } else if mode == 5 {
                            assert_eq!(form["client_id"], "client-id");
                            assert!(!form.contains_key("client_secret"));
                            assert!(!head.to_ascii_lowercase().contains("authorization:"));
                        } else {
                            let header = head
                                .lines()
                                .find(|l| {
                                    l.to_ascii_lowercase().starts_with("authorization: basic ")
                                })
                                .unwrap();
                            let encoded = header.split_whitespace().nth(2).unwrap();
                            let decoded =
                                String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap();
                            let (id, secret) = decoded.split_once(':').unwrap();
                            assert_eq!(urlencoding::decode(id).unwrap(), "client-id");
                            assert_eq!(
                                urlencoding::decode(&secret.replace('+', " ")).unwrap(),
                                SECRET
                            );
                            assert!(!form.contains_key("client_secret"));
                        }
                        let expected = e.lock().unwrap().clone();
                        if !expected.1.is_empty() {
                            let verifier = &form["code_verifier"];
                            assert_eq!(
                                URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes())),
                                expected.1
                            );
                        }
                        let mut identity = claims(&format!("{o}/issuer"), &expected.0);
                        if mode == 1 {
                            identity["nonce"] = json!("other-flow-nonce");
                        }
                        if mode == 6 {
                            identity["aud"] = json!("foreign-client");
                        }
                        if mode == 9 {
                            identity["iss"] = json!("https://foreign-issuer.test");
                        }
                        let mut response =
                            json!({"id_token":rsa_sign(&identity),"token_type":"Bearer"});
                        if [2, 3, 7, 8, 9].contains(&mode) {
                            response["access_token"] = json!(ACCESS);
                        }
                        if mode == 7 {
                            response["id_token"] = json!("unsigned.not-a-jwt.forged");
                        }
                        body = response.to_string();
                    } else if path == "/jwks" {
                        j.fetch_add(1, Ordering::SeqCst);
                        if mode == 8 {
                            status = "302 Found";
                            extra = "Location: /trap\r\n".into();
                        }
                        body = json!({"keys":[rsa_jwk()]}).to_string();
                    } else if path == "/userinfo" {
                        assert!(head.contains(&format!("Bearer {ACCESS}")));
                        body=json!({"sub":if mode==3{"different-user"}else{SUBJECT},"name":"UserInfo Name","email":"same@example.test","email_verified":true}).to_string();
                    } else {
                        status = "500 Internal Server Error";
                        body = "unexpected endpoint".into();
                    }
                    let revoke = {
                        let mut revoke = r.lock().unwrap();
                        if revoke.as_ref().is_some_and(|(target, _, _)| target == path) {
                            revoke.take()
                        } else {
                            None
                        }
                    };
                    if let Some((_, pool, provider)) = revoke {
                        sqlx::query(
                            "DELETE FROM oauth_provider_network_approvals WHERE provider_id=$1",
                        )
                        .bind(provider)
                        .execute(&pool)
                        .await
                        .unwrap();
                    }
                    let _=stream.write_all(format!("HTTP/1.1 {status}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await;
                });
            }
        });
        Self {
            origin,
            mode,
            hits,
            jwks_hits,
            token_hits,
            expected,
            revoke,
            task,
        }
    }
    fn expect_url(&self, value: &str) -> String {
        let url = reqwest::Url::parse(value).unwrap();
        let pairs: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        let nonce = pairs["nonce"].clone();
        assert!(nonce.len() >= 32);
        *self.expected.lock().unwrap() = (nonce, pairs["code_challenge"].clone());
        pairs["state"].clone()
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[tokio::test]
async fn discovery_client_auth_methods_id_token_only_and_userinfo_subject_agreement_over_real_http()
{
    let wire = Wire::start().await;
    let mut provider = record(&wire.origin);
    let context = OAuthExchangeContext {
        nonce: Some(NONCE.into()),
        started_at: Some(chrono::Utc::now().timestamp()),
        ..Default::default()
    };
    for mode in [0, 2, 4, 5] {
        wire.mode.store(mode, Ordering::SeqCst);
        provider.method = None;
        if mode == 5 {
            provider.client_secret = None;
        } else {
            provider.client_secret = Some(SECRET.into());
        }
        let endpoints = generic::resolve_endpoints(&provider, true).await.unwrap();
        assert_eq!(
            endpoints.client_auth,
            match mode {
                4 => "client_secret_post",
                5 => "none",
                _ => "client_secret_basic",
            }
        );
        let client = GenericOAuthProvider::from_resolved(&provider, &endpoints, true).unwrap();
        let token = client
            .exchange_code_token("good-code", "https://app.test/callback", &context)
            .await
            .unwrap();
        let info = client.get_user_info_token(&token, &context).await.unwrap();
        assert_eq!(info.id, SUBJECT);
        assert_eq!(
            info.display_name,
            if mode == 2 {
                "UserInfo Name"
            } else {
                "Signed User"
            }
        );
    }
    provider = record(&wire.origin);
    for mode in [1, 3, 6, 7, 8, 9] {
        wire.mode.store(mode, Ordering::SeqCst);
        let endpoints = generic::resolve_endpoints(&provider, true).await.unwrap();
        let client = GenericOAuthProvider::from_resolved(&provider, &endpoints, true).unwrap();
        let token = client
            .exchange_code_token("good-code", "https://app.test/callback", &context)
            .await
            .unwrap();
        assert!(
            client.get_user_info_token(&token, &context).await.is_err(),
            "mode {mode}"
        );
    }
    wire.mode.store(0, Ordering::SeqCst);
    provider.method = Some("private_key_jwt".into());
    assert!(oauth::validate_oauth_configuration(&provider).is_err());
    provider.method = Some("client_secret_post".into());
    assert!(generic::resolve_endpoints(&provider, true).await.is_err());
    provider.method = None;
    wire.mode.store(10, Ordering::SeqCst);
    assert!(generic::resolve_endpoints(&provider, true).await.is_err());
    assert!(wire.jwks_hits.load(Ordering::SeqCst) > 0);
}

fn server_origin() -> String {
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
fn jwt(id: &str, owner: &str, name: &str, admin: bool) -> String {
    let now = chrono::Utc::now();
    jsonwebtoken::encode(&Header::default(),&json!({"sub":id,"owner":owner,"name":name,"is_admin":admin,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"exp":now.timestamp()+3600,"iss":AppConfig::get().jwt.issuer}),&EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
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
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let database = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database)
            .await
            .unwrap();
        let other_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&database).await.unwrap();
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
        let owner = format!("oidc-{}", uuid::Uuid::new_v4());
        let foreign = format!("foreign-{}", uuid::Uuid::new_v4());
        let app = uuid::Uuid::new_v4().to_string();
        let other_app = uuid::Uuid::new_v4().to_string();
        let admin = uuid::Uuid::new_v4().to_string();
        let admin_name = format!("oidc-admin-{}", uuid::Uuid::new_v4());
        let user = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin','built-in','Built in') ON CONFLICT(name) DO NOTHING").bind(uuid::Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
        for org in [&owner, &foreign] {
            sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,'OIDC')").bind(uuid::Uuid::new_v4().to_string()).bind(org).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,'built-in',$2,'Admin','unused',true)").bind(&admin).bind(&admin_name).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,email,email_verified) VALUES($1,$2,'existing','Existing','unused','same@example.test',false)").bind(&user).bind(&owner).execute(&pool).await.unwrap();
        let wire = Wire::start().await;
        let name = format!("oidc-{}", uuid::Uuid::new_v4());
        let mut response=TestClient::post("http://localhost/api/providers").bearer_auth(jwt(&admin,"built-in",&admin_name,true)).json(&json!({"owner":owner,"name":name,"display_name":"OIDC","category":"OAuth","type":"OIDC","domain":format!("{}/issuer",wire.origin),"client_id":"client-id","client_secret":SECRET})).send(&service).await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
        let provider = body["id"].as_str().unwrap().to_owned();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_idp_signup,providers) VALUES($1,$2,$1,'OIDC',$2,$1,'secret','',true,$3)").bind(&app).bind(&owner).bind(json!([{"name":format!("{owner}/{name}"),"canSignIn":true,"canSignUp":true}])).execute(&pool).await.unwrap();
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
        let response = TestClient::post(format!(
            "http://localhost/api/providers/{}/network-approval",
            self.provider
        ))
        .bearer_auth(jwt(&self.admin, "built-in", &self.admin_name, true))
        .json(&json!({"allow_private":true}))
        .send(&self.service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
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
        let state = self.wire.expect_url(body["url"].as_str().unwrap());
        (state, browser)
    }
    async fn callback(&self, state: &str, browser: &str) -> Response {
        TestClient::get(format!(
            "http://localhost/api/auth/{}/callback?state={state}&code=good-code&application={}",
            self.name, self.other_app
        ))
        .add_header("cookie", browser, true)
        .send(&self.other)
        .await
    }
    async fn complete(&self, proof: &str, body: Value) -> Response {
        TestClient::post("http://localhost/api/auth/session")
            .add_header("cookie", proof, true)
            .add_header("origin", server_origin(), true)
            .json(&body)
            .send(&self.service)
            .await
    }
    async fn cleanup(&self) {
        for org in [&self.owner, &self.foreign] {
            for sql in [
                "DELETE FROM social_oauth_completions WHERE organization=$1",
                "DELETE FROM social_oauth_flows WHERE organization=$1",
                "DELETE FROM users WHERE owner=$1",
                "DELETE FROM applications WHERE organization=$1",
                "DELETE FROM providers WHERE owner=$1",
                "DELETE FROM organizations WHERE name=$1",
            ] {
                sqlx::query(sql)
                    .bind(org)
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
#[ignore = "requires disposable migrated PostgreSQL"]
async fn signed_id_token_only_nonce_is_durable_cross_instance_and_never_email_links() {
    let f = Fixture::new().await;
    f.approve().await;
    let (state, browser) = f.begin().await;
    let context: Value =
        sqlx::query_scalar("SELECT context FROM social_oauth_flows WHERE organization=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(context["oauth_nonce"], f.wire.expected.lock().unwrap().0);
    assert!(!context["oauth_code_verifier"].as_str().unwrap().is_empty());
    let response = f.callback(&state, &browser).await;
    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let proof = cookie(&response, "casdog_oauth_completion=");
    let mut response = f.complete(&proof, json!({})).await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    assert_ne!(body["user"]["id"], f.user);
    assert_eq!(body["user"]["owner"], f.owner);
    assert_eq!(body["user"]["email_verified"], true);
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert!(!body.to_string().contains(SECRET));
    assert_eq!(
        f.callback(&state, &browser).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.wire.jwks_hits.load(Ordering::SeqCst), 1);
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires disposable migrated PostgreSQL"]
async fn oidc_tampered_identity_and_cross_tenant_application_never_create_user_or_completion() {
    let f = Fixture::new().await;
    f.approve().await;
    let foreign = TestClient::get(format!(
        "http://localhost/api/auth/{}?application={}",
        f.name, f.other_app
    ))
    .send(&f.service)
    .await;
    assert_eq!(foreign.status_code, Some(StatusCode::FORBIDDEN));
    assert_eq!(f.wire.hits.load(Ordering::SeqCst), 0);
    for mode in [1, 3, 6, 7, 8, 9] {
        f.wire.mode.store(mode, Ordering::SeqCst);
        let (state, browser) = f.begin().await;
        assert_eq!(
            f.callback(&state, &browser).await.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "mode {mode}"
        );
    }
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE owner=$1")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
    let completions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM social_oauth_completions WHERE organization=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(completions, 0);
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires disposable migrated PostgreSQL"]
async fn revocation_between_token_jwks_and_userinfo_stops_the_next_network_request() {
    let f = Fixture::new().await;
    for target in ["/token", "/jwks"] {
        f.approve().await;
        f.wire.mode.store(2, Ordering::SeqCst);
        let (state, browser) = f.begin().await;
        let before = f.wire.hits.load(Ordering::SeqCst);
        *f.wire.revoke.lock().unwrap() = Some((target.into(), f.pool.clone(), f.provider.clone()));
        assert_eq!(
            f.callback(&state, &browser).await.status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            f.wire.hits.load(Ordering::SeqCst) - before,
            if target == "/token" { 1 } else { 2 }
        );
    }
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires disposable migrated PostgreSQL"]
async fn signed_oidc_account_linking_and_mfa_require_current_approval_without_contact_overwrite() {
    let f = Fixture::new().await;
    f.approve().await;
    let mut response = TestClient::post(format!("http://localhost/api/auth/{}/link", f.name))
        .bearer_auth(jwt(&f.user, &f.owner, "existing", false))
        .add_header("origin", server_origin(), true)
        .json(&json!({"application":f.app}))
        .send(&f.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let browser = cookie(&response, "casdog_oauth_browser=");
    let body: Value = response.take_json().await.unwrap();
    let state = f.wire.expect_url(body["url"].as_str().unwrap());
    assert_eq!(
        f.callback(&state, &browser).await.status_code,
        Some(StatusCode::SEE_OTHER)
    );
    sqlx::query("UPDATE users SET mfa_enabled=true,totp_secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' WHERE id=$1").bind(&f.user).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO user_mfa(id,user_id,mfa_type,secret,is_enabled,recovery_codes) VALUES($1,$2,'totp','JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',true,'[\"signed-recovery\"]')").bind(uuid::Uuid::new_v4().to_string()).bind(&f.user).execute(&f.pool).await.unwrap();
    let (state, browser) = f.begin().await;
    let response = f.callback(&state, &browser).await;
    assert_eq!(response.status_code, Some(StatusCode::SEE_OTHER));
    let proof = cookie(&response, "casdog_oauth_completion=");
    let mut response = f.complete(&proof, json!({})).await;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["mfa_required"], true);
    assert!(body["token"].as_str().unwrap_or_default().is_empty());
    assert_eq!(
        TestClient::delete(format!(
            "http://localhost/api/providers/{}/network-approval",
            f.provider
        ))
        .bearer_auth(jwt(&f.admin, "built-in", &f.admin_name, true))
        .send(&f.service)
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        f.complete(
            &proof,
            json!({"mfaType":"recovery","passcode":"signed-recovery"})
        )
        .await
        .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.approve().await;
    assert_eq!(
        f.complete(
            &proof,
            json!({"mfaType":"recovery","passcode":"signed-recovery"})
        )
        .await
        .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let (state, browser) = f.begin().await;
    let response = f.callback(&state, &browser).await;
    let proof = cookie(&response, "casdog_oauth_completion=");
    let mut response = f
        .complete(
            &proof,
            json!({"mfaType":"recovery","passcode":"signed-recovery"}),
        )
        .await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    assert_eq!(body["user"]["id"], f.user);
    assert_eq!(body["user"]["email_verified"], false);
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert_eq!(
        f.complete(
            &proof,
            json!({"mfaType":"recovery","passcode":"signed-recovery"})
        )
        .await
        .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
