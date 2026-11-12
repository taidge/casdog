//! Real first-factor proofs through PostgreSQL, HTTP delivery and LDAP BER.
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    handlers::{password_mfa, primary_auth},
    services::{
        PasswordService, auth_service::LoginRequest, mfa_service::MfaService,
        social_state_service::proof_hash,
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
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
};

// Small LDAP server, speaking the same bind/search protocol used by ldap3.
// It does not replace the directory client with a trusted authentication stub.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        out.extend([0x82, (value.len() >> 8) as u8, value.len() as u8]);
    }
    out.extend(value);
    out
}
fn item(bytes: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = bytes[0];
    let mut offset = 2;
    let mut length = bytes[1] as usize;
    if length & 128 != 0 {
        let n = length & 127;
        length = 0;
        for byte in &bytes[2..2 + n] {
            length = (length << 8) | (*byte as usize);
        }
        offset += n;
    }
    (
        tag,
        &bytes[offset..offset + length],
        &bytes[offset + length..],
    )
}
async fn packet(socket: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0; 2];
    socket.read_exact(&mut header).await.ok()?;
    let mut length = header[1] as usize;
    if length & 128 != 0 {
        let mut bytes = vec![0; length & 127];
        socket.read_exact(&mut bytes).await.ok()?;
        length = 0;
        for byte in bytes {
            length = (length << 8) | (byte as usize);
        }
    }
    if length > 100_000 {
        return None;
    }
    let mut body = vec![0; length];
    socket.read_exact(&mut body).await.ok()?;
    Some(body)
}
async fn ldap_reply(socket: &mut TcpStream, id: &[u8], tag: u8, payload: &[u8]) {
    let mut body = tlv(2, id);
    body.extend(tlv(tag, payload));
    socket.write_all(&tlv(0x30, &body)).await.unwrap();
}
async fn directory() -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("ldap://{}", listener.local_addr().unwrap());
    let searches = Arc::new(AtomicUsize::new(0));
    let entries = Arc::new(AtomicUsize::new(1));
    let count = searches.clone();
    let matches = entries.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let count = count.clone();
            let matches = matches.clone();
            tokio::spawn(async move {
                while let Some(message) = packet(&mut socket).await {
                    let (_, id, rest) = item(&message);
                    let (tag, body, _) = item(rest);
                    match tag {
                        0x60 => {
                            let (_, _, rest) = item(body);
                            let (_, dn, rest) = item(rest);
                            let (_, password, _) = item(rest);
                            let accepted = (dn == b"cn=service,dc=example,dc=test"
                                && password == b"search-password")
                                || (dn == b"uid=alice,dc=example,dc=test"
                                    && password == b"directory-password");
                            let mut response = tlv(0x0a, &[if accepted { 0 } else { 49 }]);
                            response.extend(tlv(4, b""));
                            response.extend(tlv(4, b""));
                            ldap_reply(&mut socket, id, 0x61, &response).await;
                        }
                        0x63 => {
                            count.fetch_add(1, Ordering::SeqCst);
                            for index in 0..matches.load(Ordering::SeqCst) {
                                let dn = if index == 0 {
                                    "uid=alice,dc=example,dc=test"
                                } else {
                                    "uid=duplicate,dc=example,dc=test"
                                };
                                let mut entry = tlv(4, dn.as_bytes());
                                let mut attr = tlv(4, b"uid");
                                attr.extend(tlv(0x31, &tlv(4, b"alice")));
                                entry.extend(tlv(0x30, &tlv(0x30, &attr)));
                                ldap_reply(&mut socket, id, 0x64, &entry).await;
                            }
                            let mut done = tlv(0x0a, &[0]);
                            done.extend(tlv(4, b""));
                            done.extend(tlv(4, b""));
                            ldap_reply(&mut socket, id, 0x65, &done).await;
                        }
                        0x42 => break,
                        _ => panic!("unexpected LDAP request tag {tag}"),
                    }
                }
            });
        }
    });
    (address, searches, entries, server)
}
async fn delivery() -> (String, mpsc::UnboundedReceiver<Value>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/deliver", listener.local_addr().unwrap());
    let (sender, receiver) = mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            let (start, length) = loop {
                let n = socket.read(&mut buffer).await.unwrap();
                if n == 0 {
                    return;
                }
                bytes.extend_from_slice(&buffer[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..end]);
                    let length = header
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while bytes.len() < start + length {
                let n = socket.read(&mut buffer).await.unwrap();
                if n == 0 {
                    return;
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            let body = serde_json::from_slice(&bytes[start..start + length]).unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
            sender.send(body).unwrap();
        }
    });
    (endpoint, receiver, server)
}
struct Fixture {
    pool: PgPool,
    other_pool: PgPool,
    service: Service,
    other: Service,
    owner: String,
    user: String,
    app: String,
    ldap: String,
    messages: mpsc::UnboundedReceiver<Value>,
    searches: Arc<AtomicUsize>,
    entries: Arc<AtomicUsize>,
    servers: Vec<JoinHandle<()>>,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let other_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let router = || {
            Router::new()
                .push(Router::with_path("api/login").post(password_mfa::login))
                .push(Router::with_path("api/auth/code/start").post(primary_auth::start_code))
                .push(
                    Router::with_path("api/auth/password/session")
                        .post(password_mfa::consume_password_session),
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
        let owner = format!("primary-{}", uuid::Uuid::new_v4());
        let user = uuid::Uuid::new_v4().to_string();
        let app = uuid::Uuid::new_v4().to_string();
        let ldap = uuid::Uuid::new_v4().to_string();
        let (endpoint, messages, http) = delivery().await;
        let (address, searches, entries, ldap_server) = directory().await;
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Primary auth')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        let password = PasswordService::hash_password("LocalPassword42!", "bcrypt", None).unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type,email,phone,country_code,ldap) VALUES($1,$2,'alice','Alice',$3,'bcrypt','alice@example.test','+15555550123','US',$4)")
            .bind(&user).bind(&owner).bind(password).bind(&ldap).execute(&pool).await.unwrap();
        for (name, category, kind) in [("email", "Email", "Custom HTTP"), ("sms", "SMS", "HTTP")] {
            sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,endpoint,client_secret) VALUES($1,$2,$3,$3,$4,$5,$6,'send-secret')")
                .bind(uuid::Uuid::new_v4().to_string()).bind(&owner).bind(name).bind(category).bind(kind).bind(&endpoint).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,host,client_id,client_secret,metadata,disable_ssl) VALUES($1,$2,'ldap','Directory','LDAP','LDAP',$3,'cn=service,dc=example,dc=test','search-password',$4,true)")
            .bind(&ldap).bind(&owner).bind(address).bind(json!({"base_dn":"dc=example,dc=test","filter":"(objectClass=person)"}).to_string()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password,enable_code_signin,signin_methods,providers,grant_types) VALUES($1,$2,'app','App',$2,$1,'secret','https://example.test/callback',true,true,$3,$4,$5)")
            .bind(&app).bind(&owner).bind(json!([{"name":"Password"},{"name":"Verification code","rule":"All"},{"name":"LDAP"}]))
            .bind(json!([{"name":format!("{owner}/email"),"rule":"All"},{"name":format!("{owner}/sms"),"rule":"All"}]))
            .bind(json!(["authorization_code"])).execute(&pool).await.unwrap();
        Self {
            pool,
            other_pool,
            service,
            other,
            owner,
            user,
            app,
            ldap,
            messages,
            searches,
            entries,
            servers: vec![http, ldap_server],
        }
    }
    fn body(&self) -> Value {
        json!({"owner":self.owner,"name":"alice","clientId":self.app})
    }
    async fn start_body(&mut self, body: Value) -> (String, String, Value) {
        let mut response = TestClient::post("http://localhost/api/auth/code/start")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&body)
            .send(&self.service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let secret = cookie(&response, "casdog_primary_auth");
        let header = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(header.contains("Path=/api;"));
        assert!(header.contains("HttpOnly"));
        let receipt: Value = response.take_json().await.unwrap();
        assert_eq!(receipt["pending"], true);
        assert!(!receipt.to_string().contains(&secret));
        let delivery =
            tokio::time::timeout(std::time::Duration::from_secs(3), self.messages.recv())
                .await
                .unwrap()
                .unwrap();
        let code = delivery["body"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .find_map(|s| {
                let s = s.trim_end_matches('.');
                (s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.to_owned())
            })
            .unwrap();
        (secret, code, delivery)
    }
    async fn start(&mut self, method: &str) -> (String, String, Value) {
        let mut body = self.body();
        body["method"] = json!(method);
        self.start_body(body).await
    }
    async fn login(
        service: &Service,
        mut body: Value,
        secret: Option<&str>,
        code: Option<&str>,
    ) -> Response {
        if let Some(code) = code {
            body["type"] = json!("code");
            body["code"] = json!(code);
        }
        let mut request = TestClient::post("http://localhost/api/login")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&body);
        if let Some(secret) = secret {
            request = request.add_header("Cookie", format!("casdog_primary_auth={secret}"), true);
        }
        request.send(service).await
    }
    async fn mfa(service: &Service, proof: &str, method: &str, code: &str) -> Response {
        TestClient::post("http://localhost/api/auth/password/session")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .add_header("Cookie", format!("casdog_password_mfa={proof}"), true)
            .json(&json!({"mfaType":method,"passcode":code}))
            .send(service)
            .await
    }
    async fn enroll(&self) {
        let (secret, _) = MfaService::initiate_totp_setup("alice", "test").unwrap();
        MfaService::save_mfa(&self.pool, &self.user, "totp", Some(&secret))
            .await
            .unwrap();
        MfaService::enable_mfa(&self.pool, &self.user, "totp")
            .await
            .unwrap();
        sqlx::query("UPDATE user_mfa SET recovery_codes='[\"recovery-one\",\"recovery-two\"]' WHERE user_id=$1").bind(&self.user).execute(&self.pool).await.unwrap();
    }
    async fn age_proof(&self) {
        sqlx::query("UPDATE primary_auth_challenges SET created_at=created_at-INTERVAL '61 seconds' WHERE user_id=$1").bind(&self.user).execute(&self.pool).await.unwrap();
    }
    fn ldap_body(&self, password: &str) -> Value {
        let mut body = self.body();
        body["type"] = json!("ldap");
        body["password"] = json!(password);
        body
    }
    async fn cleanup(self) {
        for server in self.servers {
            server.abort();
        }
        for (table, column) in [
            ("primary_auth_challenges", "organization"),
            ("password_mfa_challenges", "organization"),
            ("tokens", "owner"),
            ("verifications", "owner"),
            ("permissions", "owner"),
            ("applications", "owner"),
            ("users", "owner"),
            ("providers", "owner"),
            ("organizations", "owner"),
        ] {
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
fn cookie(response: &Response, name: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|header| {
            header
                .to_str()
                .ok()?
                .split(';')
                .next()?
                .strip_prefix(&format!("{name}="))
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        })
        .unwrap()
}

#[test]
fn login_method_aliases_are_explicit_and_missing_password_is_valid_for_code() {
    assert!(
        serde_json::from_value::<LoginRequest>(
            json!({"owner":"org","name":"alice","type":"password"})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<LoginRequest>(json!({"owner":"org","name":"alice"})).is_err());
    let request:LoginRequest=serde_json::from_value(json!({"organization":"org","username":"alice","type":"login","signinMethod":"LDAP","password":"directory"})).unwrap();
    assert_eq!(request.login_type.as_deref(), Some("ldap"));
    let request: LoginRequest =
        serde_json::from_value(json!({"owner":"org","name":"alice","type":"code","code":"123456"}))
            .unwrap();
    assert!(request.password.is_empty());
    for body in [
        json!({"type":"unknown"}),
        json!({"signinMethod":"unknown"}),
        json!({"type":"password","signinMethod":"LDAP"}),
        json!({"type":"code","codeMethod":"push"}),
    ] {
        let mut input = json!({"owner":"org","name":"alice","password":"local"});
        input
            .as_object_mut()
            .unwrap()
            .extend(body.as_object().unwrap().clone());
        assert!(serde_json::from_value::<LoginRequest>(input).is_err());
    }
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn email_first_factor_is_browser_bound_single_use_and_oauth_context_is_immutable() {
    let mut f = Fixture::new().await;
    let mut start = f.body();
    start["method"] = json!("email");
    start["receiver"] = json!("attacker@example.test");
    start["provider"] = json!("other/evil");
    start["responseType"] = json!("code");
    start["redirectUri"] = json!("https://example.test/callback");
    start["state"] = json!("bound-state");
    let (proof, code, delivery) = f.start_body(start).await;
    assert_eq!(delivery["to"], "alice@example.test");
    let (stored, context): (String, Value) = sqlx::query_as(
        "SELECT code_hash,context FROM primary_auth_challenges WHERE secret_hash=$1",
    )
    .bind(proof_hash(&proof))
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_ne!(stored, code);
    assert!(!context.to_string().contains(&proof));
    assert!(!context.to_string().contains(&code));
    assert_eq!(
        Fixture::login(&f.other, f.body(), None, Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let mut switched = f.body();
    switched["codeMethod"] = json!("sms");
    assert_eq!(
        Fixture::login(&f.other, switched, Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let mut modified = f.body();
    modified["codeMethod"] = json!("email");
    modified["redirectUri"] = json!("https://attacker.invalid");
    modified["state"] = json!("evil");
    let (mut a, mut b) = tokio::join!(
        Fixture::login(&f.service, modified, Some(&proof), Some(&code)),
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
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
    let result: Value = if a.status_code == Some(StatusCode::OK) {
        a.take_json().await.unwrap()
    } else {
        b.take_json().await.unwrap()
    };
    assert!(!result["token"].as_str().unwrap().is_empty());
    assert!(!result["code"].as_str().unwrap().is_empty());
    assert_eq!(result["state"], "bound-state");
    assert_eq!(result["redirect_uri"], "https://example.test/callback");
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn sms_delivery_and_application_channel_rules_are_enforced_before_and_after_proof() {
    let mut f = Fixture::new().await;
    sqlx::query("UPDATE applications SET signin_methods=$1 WHERE id=$2")
        .bind(json!([{"name":"Verification code","rule":"Phone only"}]))
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut email = f.body();
    email["method"] = json!("email");
    assert_eq!(
        TestClient::post("http://localhost/api/auth/code/start")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&email)
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let (proof, code, delivery) = f.start("sms").await;
    assert_eq!(delivery["to"], "+15555550123");
    sqlx::query("UPDATE applications SET enable_code_signin=false WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let mut sms = f.body();
    sms["method"] = json!("sms");
    assert_eq!(
        TestClient::post("http://localhost/api/auth/code/start")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&sms)
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE applications SET enable_code_signin=true WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE applications SET signin_methods=$1 WHERE id=$2")
        .bind(json!([{"name":"Verification code","rule":"Email only"}]))
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE applications SET signin_methods=$1 WHERE id=$2")
        .bind(json!([{"name":"Verification code","rule":"Phone only"}]))
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn code_error_budget_persists_across_new_browser_proofs_and_resends_are_rate_limited() {
    let mut f = Fixture::new().await;
    let (proof, _, _) = f.start("email").await;
    let mut start = f.body();
    start["method"] = json!("email");
    assert_eq!(
        TestClient::post("http://localhost/api/auth/code/start")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&start)
            .send(&f.other)
            .await
            .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    for _ in 0..2 {
        assert_eq!(
            Fixture::login(&f.other, f.body(), Some(&proof), Some("invalid"))
                .await
                .status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    f.age_proof().await;
    let (next, correct, _) = f.start("email").await;
    for _ in 0..3 {
        assert_eq!(
            Fixture::login(&f.other, f.body(), Some(&next), Some("invalid"))
                .await
                .status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    assert_eq!(
        Fixture::login(&f.service, f.body(), Some(&next), Some(&correct))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let errors: i32 = sqlx::query_scalar("SELECT signin_wrong_times FROM users WHERE id=$1")
        .bind(&f.user)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(errors, 5);
    f.age_proof().await;
    assert_eq!(
        TestClient::post("http://localhost/api/auth/code/start")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&start)
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn generic_recovery_and_mfa_codes_cannot_replace_the_first_factor() {
    let mut f = Fixture::new().await;
    let (proof, code, _) = f.start("email").await;
    let generic = if code == "000000" { "111111" } else { "000000" };
    for kind in ["email", "reset:email", "social:email"] {
        sqlx::query("INSERT INTO verifications(id,owner,name,type,user_id,provider,receiver,code) VALUES($1,$2,'unrelated',$3,$4,'email','alice@example.test',$5)").bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(kind).bind(&f.user).bind(generic).execute(&f.pool).await.unwrap();
    }
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(generic))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let mut other = f.body();
    other["owner"] = json!("another-tenant");
    assert_eq!(
        Fixture::login(&f.other, other, Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE users SET email='new@example.test' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn code_first_factor_requires_an_independent_mfa_and_email_only_mfa_fails_closed() {
    let mut f = Fixture::new().await;
    f.enroll().await;
    sqlx::query("UPDATE users SET mfa_email_enabled=true WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let (proof, code, _) = f.start("email").await;
    let mut response = Fixture::login(&f.other, f.body(), Some(&proof), Some(&code)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let pending = cookie(&response, "casdog_password_mfa");
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["mfa_required"], true);
    assert_eq!(body["token"], "");
    assert!(
        !body["mfa_types"]
            .as_array()
            .unwrap()
            .contains(&json!("email"))
    );
    assert_eq!(
        Fixture::mfa(&f.service, &pending, "email", &code)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        Fixture::mfa(&f.service, &pending, "recovery", "recovery-one")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    sqlx::query("DELETE FROM user_mfa WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET mfa_enabled=false WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    // Consumed proofs retain the delivery cooldown; advance only fixture time.
    f.age_proof().await;
    let (proof, code, _) = f.start("email").await;
    let mut response = Fixture::login(&f.other, f.body(), Some(&proof), Some(&code)).await;
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    let body = response.take_string().await.unwrap();
    assert!(body.contains("independent MFA factor"));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn directory_first_factor_uses_real_bind_and_never_falls_back_to_local_password() {
    let f = Fixture::new().await;
    let mut unknown = f.ldap_body("directory-password");
    unknown["name"] = json!("unknown");
    assert_eq!(
        Fixture::login(&f.service, unknown, None, None)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.searches.load(Ordering::SeqCst), 0);
    assert_eq!(
        Fixture::login(&f.service, f.ldap_body("LocalPassword42!"), None, None)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        Fixture::login(&f.service, f.ldap_body(""), None, None)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let mut response =
        Fixture::login(&f.other, f.ldap_body("directory-password"), None, None).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert_eq!(body["user"]["id"], f.user);
    assert_eq!(f.searches.load(Ordering::SeqCst), 2);
    f.entries.store(2, Ordering::SeqCst);
    assert_eq!(
        Fixture::login(&f.other, f.ldap_body("directory-password"), None, None)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn code_proof_rechecks_expiry_session_epoch_organization_and_account_before_jwt() {
    let mut f = Fixture::new().await;
    let (proof, code, _) = f.start("email").await;
    sqlx::query("UPDATE primary_auth_challenges SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE user_id=$1").bind(&f.user).execute(&f.pool).await.unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE primary_auth_challenges SET expires_at=clock_timestamp()+INTERVAL '5 minutes' WHERE user_id=$1").bind(&f.user).execute(&f.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO user_session_epochs(user_id,invalid_before) VALUES($1,clock_timestamp())",
    )
    .bind(&f.user)
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("DELETE FROM user_session_epochs WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE organizations SET disable_signin=true WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE organizations SET disable_signin=false WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET is_forbidden=true WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE users SET is_forbidden=false WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE applications SET organization='other-tenant' WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE applications SET organization=$1 WHERE id=$2")
        .bind(&f.owner)
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::login(&f.other, f.body(), Some(&proof), Some(&code))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn directory_wrong_credentials_lock_persistently_before_another_bind() {
    let f = Fixture::new().await;
    for _ in 0..5 {
        assert_eq!(
            Fixture::login(&f.other, f.ldap_body("wrong"), None, None)
                .await
                .status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    assert_eq!(f.searches.load(Ordering::SeqCst), 5);
    assert_eq!(
        Fixture::login(&f.service, f.ldap_body("directory-password"), None, None)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.searches.load(Ordering::SeqCst), 5);
    let errors: i32 = sqlx::query_scalar("SELECT signin_wrong_times FROM users WHERE id=$1")
        .bind(&f.user)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(errors, 5);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn directory_login_rechecks_local_tenant_account_application_and_provider_during_mfa() {
    let f = Fixture::new().await;
    f.enroll().await;
    let mut pending =
        Fixture::login(&f.service, f.ldap_body("directory-password"), None, None).await;
    assert_eq!(pending.status_code, Some(StatusCode::OK));
    let proof = cookie(&pending, "casdog_password_mfa");
    let body: Value = pending.take_json().await.unwrap();
    assert_eq!(body["token"], "");
    sqlx::query("UPDATE providers SET owner='another-tenant' WHERE id=$1")
        .bind(&f.ldap)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::mfa(&f.other, &proof, "recovery", "recovery-one")
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        Fixture::login(&f.other, f.ldap_body("directory-password"), None, None)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.searches.load(Ordering::SeqCst), 1);
    sqlx::query("UPDATE providers SET owner=$1 WHERE id=$2")
        .bind(&f.owner)
        .bind(&f.ldap)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET is_forbidden=true WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::mfa(&f.other, &proof, "recovery", "recovery-one")
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE users SET is_forbidden=false WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE applications SET signin_methods='[]' WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::mfa(&f.other, &proof, "recovery", "recovery-one")
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE applications SET signin_methods=$1,enable_password=false WHERE id=$2")
        .bind(json!([{"name":"LDAP"},{"name":"Password"}]))
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        Fixture::mfa(&f.other, &proof, "recovery", "recovery-one")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let mut password = f.body();
    password["password"] = json!("LocalPassword42!");
    assert_eq!(
        Fixture::login(&f.other, password, None, None)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
