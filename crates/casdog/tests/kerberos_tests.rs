//! Real Kerby KDC -> JDK GSS -> Rust acceptor -> PostgreSQL/API regressions.
//! Prepare test jars with scripts/prepare-kerberos-fixture.ps1; no AD or Docker.
use base64::{Engine, engine::general_purpose::STANDARD};
use casdog::{
    config::AppConfig, diesel_pool::create_diesel_pool, models::Organization,
    services::kerberos_service::KerberosService,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
};

fn origin() -> String {
    let config = AppConfig::get();
    reqwest::Url::parse(
        &config
            .server
            .public_url
            .unwrap_or_else(|| format!("http://{}:{}", config.server.host, config.server.port)),
    )
    .unwrap()
    .origin()
    .ascii_serialization()
}

struct Kdc {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    directory: tempfile::TempDir,
    realm: String,
}
impl Kdc {
    async fn start() -> Self {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let cases = workspace.join("target/phase13/kerberos-cases");
        std::fs::create_dir_all(&cases).unwrap();
        let directory = tempfile::tempdir_in(cases).unwrap();
        let realm = format!("R{}.CASDOG.TEST", uuid::Uuid::new_v4().simple());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let classpath = std::env::var("CASDOG_KERBY_CLASSPATH").unwrap_or_else(|_| {
            workspace
                .join("target/phase13/kerby/*")
                .to_string_lossy()
                .to_string()
        });
        let mut command = Command::new("java");
        command
            .arg("--class-path")
            .arg(classpath)
            .arg(workspace.join("scripts/KerberosFixture.java"))
            .arg(directory.path())
            .arg(&realm)
            .arg(port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(
                std::fs::File::create(directory.path().join("kdc.log")).unwrap(),
            ))
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut child = command
            .spawn()
            .expect("JDK 21 and prepared Apache Kerby test jars required");
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut fixture = Self {
            child,
            input,
            output,
            directory,
            realm,
        };
        assert_eq!(fixture.read().await, "READY");
        fixture
    }
    async fn read(&mut self) -> String {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(40), self.output.read_line(&mut line))
            .await
            .expect("KDC timeout")
            .unwrap();
        assert!(
            !line.is_empty(),
            "KDC exited: {}",
            std::fs::read_to_string(self.directory.path().join("kdc.log")).unwrap_or_default()
        );
        line.trim().to_owned()
    }
    async fn command(&mut self, command: &str) -> String {
        self.input
            .write_all(format!("{command}\n").as_bytes())
            .await
            .unwrap();
        self.input.flush().await.unwrap();
        self.read().await
    }
    async fn token(&mut self, user: &str, mechanism: &str, host: &str) -> (String, String) {
        let line = self
            .command(&format!("TOKEN {user} {mechanism} {host}"))
            .await;
        let mut parts = line.split(' ');
        assert_eq!(
            parts.next(),
            Some("TOKEN"),
            "Independent KDC rejected token generation"
        );
        (
            parts.next().unwrap().to_owned(),
            parts.next().unwrap().to_owned(),
        )
    }
    fn keytab(&self, host: &str) -> String {
        STANDARD
            .encode(std::fs::read(self.directory.path().join(format!("{host}.keytab"))).unwrap())
    }
    async fn check(&mut self, id: &str, reply: &str) {
        assert_eq!(
            self.command(&format!("CHECK {id} {reply}")).await,
            "VERIFIED"
        );
    }
    async fn stop(mut self) {
        self.input.write_all(b"QUIT\n").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(10), self.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
}
struct Fixture {
    pool: PgPool,
    service: Service,
    org: Organization,
    alice: String,
    admin: String,
    app: String,
    client: String,
    keytab: String,
}
impl Fixture {
    async fn new(kdc: &Kdc) -> Self {
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
        let owner = format!("kerberos-{}", uuid::Uuid::new_v4());
        let keytab = kdc.keytab("casdog.localhost");
        let org:Organization=sqlx::query_as("INSERT INTO organizations(id,owner,name,display_name,kerberos_realm,kerberos_kdc_host,kerberos_keytab,kerberos_service_name) VALUES($1,'admin',$2,'Kerberos',$3,'127.0.0.1:88',$4,'HTTP/casdog.localhost') RETURNING *")
            .bind(uuid::Uuid::new_v4().to_string()).bind(&owner).bind(&kdc.realm).bind(&keytab).fetch_one(&pool).await.unwrap();
        let alice = uuid::Uuid::new_v4().to_string();
        let admin = uuid::Uuid::new_v4().to_string();
        for (id, name, is_admin) in [(&alice, "alice", false), (&admin, "admin", true)] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,$3,'placeholder',$4)")
                .bind(id).bind(&owner).bind(name).bind(is_admin).execute(&pool).await.unwrap();
        }
        let app = uuid::Uuid::new_v4().to_string();
        let client = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password,grant_types) VALUES($1,'admin',$1,'Kerberos',$2,$3,'confidential','[\"http://localhost/callback\"]',false,'[\"authorization_code\"]')")
            .bind(&app).bind(&owner).bind(&client).execute(&pool).await.unwrap();
        Self {
            pool,
            service,
            org,
            alice,
            admin,
            app,
            client,
            keytab,
        }
    }
    fn bearer(&self, admin: bool) -> String {
        let now = chrono::Utc::now();
        encode(&Header::default(),&json!({"sub":if admin{&self.admin}else{&self.alice},"owner":self.org.name,"name":if admin{"admin"}else{"alice"},"is_admin":admin,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"exp":now.timestamp()+3600,"iss":AppConfig::get().jwt.issuer}),&EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
    }
    async fn login(&self, token: &str, suffix: &str) -> salvo::Response {
        TestClient::get(format!(
            "http://localhost/api/kerberos-login?application={}{}",
            self.app, suffix
        ))
        .add_header("Authorization", format!("Negotiate {token}"), true)
        .send(&self.service)
        .await
    }
    async fn cleanup(&self) {
        for sql in [
            "DELETE FROM tokens WHERE organization=$1",
            "DELETE FROM password_mfa_challenges WHERE organization=$1",
            "DELETE FROM users WHERE owner=$1",
            "DELETE FROM applications WHERE organization=$1",
            "DELETE FROM organizations WHERE name=$1",
        ] {
            sqlx::query(sql)
                .bind(&self.org.name)
                .execute(&self.pool)
                .await
                .unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL and prepared Kerby jars/JDK21"]
async fn independent_kdc_mutual_authentication_issues_local_jwt_and_oauth_code() {
    let mut kdc = Kdc::start().await;
    let f = Fixture::new(&kdc).await;
    let challenge = TestClient::get("http://localhost/api/kerberos-login")
        .send(&f.service)
        .await;
    assert_eq!(challenge.status_code, Some(StatusCode::UNAUTHORIZED));
    assert_eq!(
        challenge.headers().get("www-authenticate").unwrap(),
        "Negotiate"
    );
    let (id, token) = kdc.token("alice", "spnego", "casdog.localhost").await;
    let mut login = f.login(&token, "").await;
    assert_eq!(login.status_code, Some(StatusCode::OK));
    let reply = login
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("Negotiate ")
        .unwrap()
        .to_owned();
    let body: Value = login.take_json().await.unwrap();
    assert_eq!(body["user"]["id"], f.alice);
    assert!(!body["token"].as_str().unwrap().is_empty());
    kdc.check(&id, &reply).await;
    // Exercise an AES128 session independently of the default AES256 one.
    let (id, token) = kdc.token("alice", "spnego128", "casdog.localhost").await;
    let mut aes128 = f.login(&token, "").await;
    assert_eq!(aes128.status_code, Some(StatusCode::OK));
    let reply = aes128
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("Negotiate ")
        .unwrap()
        .to_owned();
    let body: Value = aes128.take_json().await.unwrap();
    assert!(!body["token"].as_str().unwrap().is_empty());
    kdc.check(&id, &reply).await;
    let (id, token) = kdc.token("alice", "krb5", "casdog.localhost").await;
    let mut oauth=f.login(&token,&format!("&response_type=code&client_id={}&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=kerberos-state&nonce=kerberos-nonce",f.client)).await;
    assert_eq!(oauth.status_code, Some(StatusCode::OK));
    let reply = oauth
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("Negotiate ")
        .unwrap()
        .to_owned();
    let body: Value = oauth.take_json().await.unwrap();
    assert_eq!(body["state"], "kerberos-state");
    assert!(!body["code"].as_str().unwrap().is_empty());
    let identity: (String, String) =
        sqlx::query_as("SELECT user_id,nonce FROM tokens WHERE code=$1")
            .bind(body["code"].as_str().unwrap())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(identity, (f.alice.clone(), "kerberos-nonce".into()));
    kdc.check(&id, &reply).await;
    f.cleanup().await;
    kdc.stop().await;
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL and prepared Kerby jars/JDK21"]
async fn tickets_bind_realm_service_keys_and_full_client_name_and_never_accept_caller_identity() {
    let mut kdc = Kdc::start().await;
    let f = Fixture::new(&kdc).await;
    let (_, token) = kdc.token("alice", "spnego", "casdog.localhost").await;
    assert_eq!(
        KerberosService::verify(&f.org, &token).unwrap().username,
        "alice"
    );
    let mut wrong = f.org.clone();
    wrong.kerberos_realm = Some("FOREIGN.TEST".into());
    assert!(KerberosService::verify(&wrong, &token).is_err());
    // A structurally valid keytab with the correct realm/SPN/kvno but wrong
    // cryptographic keys must fail integrity validation.
    let mut keys = STANDARD.decode(&f.keytab).unwrap();
    let mut offset = 2;
    while offset < keys.len() {
        let size = i32::from_be_bytes(keys[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let end = offset + size;
        let components = u16::from_be_bytes(keys[offset..offset + 2].try_into().unwrap()) as usize;
        let mut position = offset + 2;
        for _ in 0..=components {
            let count =
                u16::from_be_bytes(keys[position..position + 2].try_into().unwrap()) as usize;
            position += 2 + count;
        }
        position += 9;
        let length =
            u16::from_be_bytes(keys[position + 2..position + 4].try_into().unwrap()) as usize;
        keys[position + 4..position + 4 + length].fill(0);
        offset = end;
    }
    wrong = f.org.clone();
    wrong.kerberos_keytab = Some(STANDARD.encode(keys));
    assert!(KerberosService::validate_configuration(&wrong).is_ok());
    assert!(KerberosService::verify(&wrong, &token).is_err());
    wrong = f.org.clone();
    wrong.kerberos_keytab = Some(kdc.keytab("other.localhost"));
    wrong.kerberos_service_name = Some("HTTP/other.localhost".into());
    assert!(KerberosService::verify(&wrong, &token).is_err());
    let (_, wrong_service) = kdc.token("alice", "spnego", "other.localhost").await;
    assert!(KerberosService::verify(&f.org, &wrong_service).is_err());
    let mut damaged = STANDARD.decode(&token).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(KerberosService::verify(&f.org, &STANDARD.encode(damaged)).is_err());
    let (_, other_user) = kdc.token("alice/admin", "spnego", "casdog.localhost").await;
    assert_eq!(
        KerberosService::verify(&f.org, &other_user)
            .unwrap()
            .username,
        "alice/admin"
    );
    assert_eq!(
        f.login(&other_user, "").await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let forged = TestClient::get(format!(
        "http://localhost/api/kerberos-login?application={}&username=admin",
        f.app
    ))
    .add_header("Authorization", "Negotiate invalid", true)
    .add_header("X-Remote-User", "admin", true)
    .send(&f.service)
    .await;
    assert_eq!(forged.status_code, Some(StatusCode::UNAUTHORIZED));
    sqlx::query("UPDATE organizations SET kerberos_keytab=NULL WHERE id=$1")
        .bind(&f.org.id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.login(&token, "").await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
    kdc.stop().await;
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL and prepared Kerby jars/JDK21"]
async fn authenticators_are_consumed_atomically_across_pools_and_login_replay_cannot_issue_another_jwt()
 {
    let mut kdc = Kdc::start().await;
    let f = Fixture::new(&kdc).await;
    let (_, token) = kdc.token("alice", "spnego", "casdog.localhost").await;
    let first = KerberosService::verify(&f.org, &token).unwrap();
    let second = KerberosService::verify(&f.org, &token).unwrap();
    let other = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let consume = |pool: PgPool, proof| {
        let org = f.org.clone();
        async move {
            let mut tx = pool.begin().await.unwrap();
            let result = KerberosService::consume(&mut tx, &org, &proof).await;
            if result.is_ok() {
                tx.commit().await.unwrap();
            }
            result.is_ok()
        }
    };
    let (a, b) = tokio::join!(consume(f.pool.clone(), first), consume(other, second));
    assert_ne!(a, b);
    assert_eq!(
        f.login(&token, "").await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let (_, fresh) = kdc.token("alice", "spnego", "casdog.localhost").await;
    assert_eq!(f.login(&fresh, "").await.status_code, Some(StatusCode::OK));
    assert_eq!(
        f.login(&fresh, "").await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
    kdc.stop().await;
}
fn mfa_cookie(response: &salvo::Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("casdog_password_mfa="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL and prepared Kerby jars/JDK21"]
async fn kerberos_mfa_uses_browser_challenge_and_rechecks_current_org_configuration_and_account() {
    let mut kdc = Kdc::start().await;
    let f = Fixture::new(&kdc).await;
    sqlx::query("UPDATE users SET mfa_enabled=true,totp_secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' WHERE id=$1").bind(&f.alice).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO user_mfa(id,user_id,mfa_type,secret,is_enabled,recovery_codes) VALUES($1,$2,'totp','JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',true,'[\"kerberos-recovery-one\",\"kerberos-recovery-two\"]')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&f.alice).execute(&f.pool).await.unwrap();
    let (_, token) = kdc.token("alice", "spnego", "casdog.localhost").await;
    let mut response = f.login(&token, "").await;
    let cookie = mfa_cookie(&response);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["mfa_required"], true);
    assert_eq!(body["token"], "");
    let mut finish = TestClient::post("http://localhost/api/auth/password/session")
        .add_header("origin", origin(), true)
        .add_header("cookie", &cookie, true)
        .json(&json!({"mfaType":"recovery","passcode":"kerberos-recovery-one"}))
        .send(&f.service)
        .await;
    assert_eq!(finish.status_code, Some(StatusCode::OK));
    let result: Value = finish.take_json().await.unwrap();
    assert!(!result["token"].as_str().unwrap().is_empty());
    let replay = TestClient::post("http://localhost/api/auth/password/session")
        .add_header("origin", origin(), true)
        .add_header("cookie", &cookie, true)
        .json(&json!({"mfaType":"recovery","passcode":"kerberos-recovery-two"}))
        .send(&f.service)
        .await;
    assert_eq!(replay.status_code, Some(StatusCode::UNAUTHORIZED));
    let (_, token) = kdc.token("alice", "spnego", "casdog.localhost").await;
    let response = f.login(&token, "").await;
    let cookie = mfa_cookie(&response);
    sqlx::query("UPDATE organizations SET kerberos_service_name='HTTP' WHERE id=$1")
        .bind(&f.org.id)
        .execute(&f.pool)
        .await
        .unwrap();
    let stale = TestClient::post("http://localhost/api/auth/password/session")
        .add_header("origin", origin(), true)
        .add_header("cookie", &cookie, true)
        .json(&json!({"mfaType":"recovery","passcode":"kerberos-recovery-two"}))
        .send(&f.service)
        .await;
    assert_eq!(stale.status_code, Some(StatusCode::UNAUTHORIZED));
    for sql in [
        "UPDATE users SET is_forbidden=true WHERE id=$1",
        "UPDATE users SET is_forbidden=false,is_deleted=true WHERE id=$1",
    ] {
        sqlx::query(sql)
            .bind(&f.alice)
            .execute(&f.pool)
            .await
            .unwrap();
        let (_, token) = kdc.token("alice", "spnego", "casdog.localhost").await;
        assert_eq!(
            f.login(&token, "").await.status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    f.cleanup().await;
    kdc.stop().await;
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL and prepared Kerby jars/JDK21"]
async fn organization_apis_mask_retain_and_validate_effective_kerberos_configuration_atomically() {
    let mut kdc = Kdc::start().await;
    let f = Fixture::new(&kdc).await;
    for path in [
        format!("/api/organizations/{}", f.org.id),
        format!("/api/get-organization?id=admin/{}", f.org.name),
    ] {
        let mut response = TestClient::get(format!("http://localhost{path}"))
            .bearer_auth(f.bearer(true))
            .send(&f.service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let value: Value = response.take_json().await.unwrap();
        let object = value.get("data").unwrap_or(&value);
        assert_eq!(
            object
                .get("kerberosKeytab")
                .or_else(|| object.get("kerberos_keytab"))
                .unwrap(),
            "***"
        );
        assert!(!value.to_string().contains(&f.keytab));
    }
    let mut native = TestClient::put(format!("http://localhost/api/organizations/{}", f.org.id))
        .bearer_auth(f.bearer(true))
        .json(&json!({"display_name":"Retained","kerberosKeytab":"***"}))
        .send(&f.service)
        .await;
    assert_eq!(native.status_code, Some(StatusCode::OK));
    let body: Value = native.take_json().await.unwrap();
    assert!(!body.to_string().contains(&f.keytab));
    let legacy=TestClient::post(format!("http://localhost/api/update-organization?id=admin/{}",f.org.name)).bearer_auth(f.bearer(true))
        .json(&json!({"owner":"admin","name":f.org.name,"displayName":"Legacy retained","kerberosKeytab":"***"})).send(&f.service).await;
    assert_eq!(legacy.status_code, Some(StatusCode::OK));
    for body in [
        json!({"kerberosKeytab":""}),
        json!({"kerberosRealm":"FOREIGN.TEST"}),
        json!({"kerberosKdcHost":"https://untrusted.invalid/path"}),
        json!({"kerberosServiceName":"HTTP/other.localhost"}),
    ] {
        let response = TestClient::put(format!("http://localhost/api/organizations/{}", f.org.id))
            .bearer_auth(f.bearer(true))
            .json(&body)
            .send(&f.service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        let stored: String =
            sqlx::query_scalar("SELECT kerberos_keytab FROM organizations WHERE id=$1")
                .bind(&f.org.id)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(stored, f.keytab);
    }
    let denied = TestClient::put(format!("http://localhost/api/organizations/{}", f.org.id))
        .bearer_auth(f.bearer(false))
        .json(&json!({"kerberosKeytab":""}))
        .send(&f.service)
        .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    let (_, token) = kdc.token("alice", "spnego", "casdog.localhost").await;
    assert_eq!(f.login(&token, "").await.status_code, Some(StatusCode::OK));
    let disabled=TestClient::put(format!("http://localhost/api/organizations/{}",f.org.id)).bearer_auth(f.bearer(true))
        .json(&json!({"kerberosRealm":"","kerberosKdcHost":"","kerberosKeytab":"","kerberosServiceName":""})).send(&f.service).await;
    assert_eq!(disabled.status_code, Some(StatusCode::OK));
    let (_, token) = kdc.token("alice", "spnego", "casdog.localhost").await;
    assert_eq!(
        f.login(&token, "").await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
    kdc.stop().await;
}
