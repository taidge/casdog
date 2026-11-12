//! Real source connectors and shared scheduler state, exercised through normal
//! Syncer CRUD/run APIs. Source PostgreSQL is a different database.
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    models::{User, UserResponse},
    services::{
        AuthService, PasswordService, SyncerService, UserService, syncer_executor::SyncerExecutor,
    },
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn columns() -> Value {
    json!([
        {"name":"source_id","type":"String","casdoorName":"Id","isKey":true},
        {"name":"login","type":"String","casdoorName":"Name"},
        {"name":"fullname","type":"String","casdoorName":"DisplayName"},
        {"name":"mail","type":"String","casdoorName":"Email"}
    ])
}

#[test]
fn keycloak_pbkdf2_base64_interoperability_vectors_are_algorithm_and_parameter_bound() {
    // SHA256 is Casdoor's Keycloak-compatible pbkdf2-salt vector;
    // SHA512 was independently computed with Python hashlib.pbkdf2_hmac.
    for (kind, key) in [
        (
            "keycloak-pbkdf2-sha256",
            "p6XETX9kSIy9ZwWTiGafUdPW9KUJsfJSWQD9lWRuomav7bGCMfY03kxznJu2emdUprJ3DVemHMlpE5c0+dmsAA==",
        ),
        (
            "keycloak-pbkdf2-sha512",
            "s49/4jq/ybaidrqwij0i+yoONDNkwHvuCmjXms4FJsc=",
        ),
    ] {
        let encoded = format!("${kind}$27500$c2FsdA==${key}");
        assert!(PasswordService::verify_password("password", &encoded, kind, None).unwrap());
        assert!(!PasswordService::verify_password("wrong", &encoded, kind, None).unwrap());
        assert!(PasswordService::import_credential(&encoded, None, None, true).is_ok());
        assert!(
            !PasswordService::verify_password(
                "password",
                &encoded.replace("27500", "27501"),
                kind,
                None
            )
            .unwrap()
        );
        assert!(
            !PasswordService::verify_password(
                "password",
                &encoded.replace("27500", "2000001"),
                kind,
                None
            )
            .unwrap()
        );
    }
}
struct Fixture {
    pool: PgPool,
    other: PgPool,
    source: PgPool,
    service: Service,
    owner: String,
    foreign: String,
    user: String,
    schema: String,
    auth: String,
    source_url: reqwest::Url,
    password: String,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").expect("CASDOG_TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let other = PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .unwrap();
        let remote = std::env::var("CASDOG_TEST_SYNC_SOURCE_URL")
            .expect("CASDOG_TEST_SYNC_SOURCE_URL must reference another database");
        let source_url = reqwest::Url::parse(&remote).unwrap();
        assert_ne!(
            reqwest::Url::parse(&url).unwrap().path(),
            source_url.path(),
            "source must be a separate database"
        );
        let source = PgPoolOptions::new()
            .max_connections(3)
            .connect(&remote)
            .await
            .unwrap();
        let schema = format!("sync_{}", uuid::Uuid::new_v4().simple());
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
            .execute(&source)
            .await
            .unwrap();
        sqlx::raw_sql(&format!("CREATE TABLE {schema}.people(source_id text,login text,fullname text,mail text,secret text,kind text,salt text)")).execute(&source).await.unwrap();
        sqlx::raw_sql(&format!("INSERT INTO {schema}.people VALUES('s1','alice','Source Alice','source@example.test',NULL,NULL,NULL),('s2','bob','Source Bob','bob@example.test',NULL,NULL,NULL)")).execute(&source).await.unwrap();
        let owner = format!("sync-{}", uuid::Uuid::new_v4().simple());
        let foreign = format!("other-{}", uuid::Uuid::new_v4().simple());
        for org in [&owner, &foreign] {
            sqlx::query(
                "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(org)
            .execute(&pool)
            .await
            .unwrap();
        }
        let admin = uuid::Uuid::new_v4().to_string();
        let user = uuid::Uuid::new_v4().to_string();
        let hash = PasswordService::hash_password("LocalPassword42!", "argon2", None).unwrap();
        for (id, org, name, is_admin, display) in [
            (&admin, &owner, "admin", true, "Admin"),
            (&user, &owner, "alice", false, "Local Alice"),
        ] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type,is_admin,external_id,phone) VALUES($1,$2,$3,$4,$5,'argon2',$6,CASE WHEN $6 THEN NULL ELSE 's1' END,'123456')")
                .bind(id).bind(org).bind(name).bind(display).bind(&hash).bind(is_admin).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,external_id) VALUES($1,$2,'alice','Foreign Alice','foreign-hash','s1')").bind(uuid::Uuid::new_v4().to_string()).bind(&foreign).execute(&pool).await.unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let account: User = sqlx::query_as("SELECT * FROM users WHERE id=$1")
            .bind(&admin)
            .fetch_one(&pool)
            .await
            .unwrap();
        let token = AuthService::new(UserService::new(diesel.clone()))
            .generate_token(&UserResponse::from(account))
            .unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        let password = source_url
            .password()
            .unwrap_or("fixture-source-secret")
            .to_string();
        Self {
            pool,
            other,
            source,
            service,
            owner,
            foreign,
            user,
            schema,
            auth: format!("Bearer {token}"),
            source_url,
            password,
        }
    }
    fn database_body(&self, name: &str, table: &str) -> Value {
        json!({"owner":self.owner,"name":name,"organization":self.owner,"type":"Database","databaseType":"postgres","sslMode":"disable","host":self.source_url.host_str().unwrap(),"port":self.source_url.port().unwrap_or(5432),"user":self.source_url.username(),"password":self.password,"database":self.source_url.path().trim_start_matches('/'),"table":format!("{}.{}",self.schema,table),"tableColumns":columns(),"syncInterval":60,"isReadOnly":true,"isEnabled":true})
    }
    async fn request(&self, method: &str, path: &str, body: Option<Value>) -> Response {
        let url = format!("http://localhost{path}");
        let request = match method {
            "GET" => TestClient::get(url),
            "POST" => TestClient::post(url),
            "PUT" => TestClient::put(url),
            "DELETE" => TestClient::delete(url),
            _ => panic!("unsupported fixture method"),
        }
        .add_header("Authorization", &self.auth, true);
        match body {
            Some(body) => request.json(&body).send(&self.service).await,
            None => request.send(&self.service).await,
        }
    }
    async fn json(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let mut response = self.request(method, path, body).await;
        let status = response.status_code;
        let body = response.take_string().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
        serde_json::from_str(&body).unwrap()
    }
    async fn create(&self, name: &str, table: &str) -> String {
        self.json(
            "POST",
            "/api/syncers",
            Some(self.database_body(name, table)),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .into()
    }
    async fn run(&self, id: &str) -> Value {
        self.json("POST", &format!("/api/syncers/{id}/run"), None)
            .await
    }
    async fn user(&self) -> User {
        sqlx::query_as("SELECT * FROM users WHERE id=$1")
            .bind(&self.user)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn cleanup(self) {
        sqlx::query("DELETE FROM syncer_operations WHERE organization=$1 OR organization=$2")
            .bind(&self.owner)
            .bind(&self.foreign)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM syncers WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE owner=$1 OR owner=$2")
            .bind(&self.owner)
            .bind(&self.foreign)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE name=$1 OR name=$2")
            .bind(&self.owner)
            .bind(&self.foreign)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::raw_sql(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.source)
            .await
            .unwrap();
        self.source.close().await;
        self.pool.close().await;
        self.other.close().await;
    }
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and separate CASDOG_TEST_SYNC_SOURCE_URL"]
async fn normal_syncer_crud_uses_real_schema_masks_credentials_and_imports_external_postgres() {
    let f = Fixture::new().await;
    let before = f.user().await;
    let id = f.create("external", "people").await;
    let rest = f.json("GET", &format!("/api/syncers/{id}"), None).await;
    assert_eq!(rest["password"], "***");
    assert_eq!(rest["table_columns"].as_array().unwrap().len(), 4);
    assert_eq!(
        rest["database"],
        f.source_url.path().trim_start_matches('/')
    );
    let legacy = f
        .json(
            "GET",
            &format!("/api/get-syncer?id={}/external", f.owner),
            None,
        )
        .await;
    assert_eq!(legacy["data"]["password"], "***");
    assert_eq!(legacy["data"]["tableColumns"][0]["isKey"], true);
    assert!(!legacy.to_string().contains(&f.password));
    f.json(
        "POST",
        &format!("/api/update-syncer?id={}/external", f.owner),
        Some(json!({"owner":f.owner,"name":"external","password":"***","syncInterval":3})),
    )
    .await;
    assert_eq!(
        SyncerService::get_by_id_internal(&f.pool, &id)
            .await
            .unwrap()
            .password,
        f.password
    );
    let run = f.run(&id).await;
    assert_eq!(run["recordsSynced"], 2);
    let user = f.user().await;
    assert_eq!(user.id, before.id);
    assert_eq!(user.password_hash, before.password_hash);
    assert_eq!(user.phone, before.phone);
    assert_eq!(user.display_name, "Source Alice");
    let foreign: String =
        sqlx::query_scalar("SELECT display_name FROM users WHERE owner=$1 AND name='alice'")
            .bind(&f.foreign)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(foreign, "Foreign Alice");
    sqlx::raw_sql(&format!("UPDATE {}.people SET login='renamed-alice',fullname='Renamed Source Alice',mail=NULL WHERE source_id='s1'",f.schema)).execute(&f.source).await.unwrap();
    f.run(&id).await;
    let renamed = f.user().await;
    assert_eq!(renamed.name, "renamed-alice");
    assert_eq!(renamed.id, before.id);
    assert_eq!(renamed.password_hash, before.password_hash);
    assert_eq!(renamed.email.as_deref(), Some("source@example.test"));
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM syncer_user_links WHERE syncer_id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 2);
    let mut cross = f.database_body("global-cross-target", "people");
    cross["organization"] = json!(f.foreign);
    let cross = SyncerService::create(&f.pool, serde_json::from_value(cross).unwrap())
        .await
        .unwrap();
    assert_eq!(
        f.request("GET", &format!("/api/syncers/{}", cross.id), None)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let list = f
        .json("GET", &format!("/api/get-syncers?owner={}", f.owner), None)
        .await;
    assert_eq!(list["data2"], 1);
    assert_eq!(list["data"][0]["password"], "***");
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/update-syncer?id={}/external", f.owner),
            Some(json!({"organization":f.foreign}))
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        f.request(
            "POST",
            "/api/syncers",
            Some({
                let mut body = f.database_body("cross", "people");
                body["organization"] = json!(f.foreign);
                body
            })
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    f.json(
        "POST",
        "/api/delete-syncer",
        Some(json!({"owner":f.owner,"name":"external"})),
    )
    .await;
    let runtime: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM syncer_runtime_state WHERE syncer_id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(runtime, 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and separate CASDOG_TEST_SYNC_SOURCE_URL"]
async fn password_mapping_is_explicit_idempotent_and_failed_batches_roll_back_without_leaking_secrets()
 {
    let f = Fixture::new().await;
    let id = f.create("passwords", "people").await;
    let before = f.user().await;
    let mut mapping = columns();
    mapping
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"secret","type":"String","casdoorName":"Password","isHashed":false}));
    f.json(
        "PUT",
        &format!("/api/syncers/{id}"),
        Some(json!({"table_columns":mapping})),
    )
    .await;
    sqlx::raw_sql(&format!(
        "UPDATE {}.people SET secret='ImportedPassword42!' WHERE source_id='s1'",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    f.run(&id).await;
    let updated = f.user().await;
    assert_ne!(updated.password_hash, before.password_hash);
    assert!(updated.last_change_password_time.is_some());
    assert!(
        PasswordService::verify_password(
            "ImportedPassword42!",
            &updated.password_hash,
            updated.password_type.as_deref().unwrap(),
            updated.password_salt.as_deref()
        )
        .unwrap()
    );
    f.run(&id).await;
    let repeat = f.user().await;
    assert_eq!(repeat.password_hash, updated.password_hash);
    assert_eq!(
        repeat.last_change_password_time,
        updated.last_change_password_time
    );
    let encoded = PasswordService::hash_password("HashedPassword42!", "bcrypt", None).unwrap();
    sqlx::query(&format!(
        "UPDATE {}.people SET secret=$1,kind='bcrypt',salt=NULL WHERE source_id='s1'",
        f.schema
    ))
    .bind(&encoded)
    .execute(&f.source)
    .await
    .unwrap();
    let mut hashed = columns();
    hashed.as_array_mut().unwrap().extend([
        json!({"name":"secret","type":"String","casdoorName":"Password","isHashed":true}),
        json!({"name":"kind","type":"String","casdoorName":"PasswordType"}),
        json!({"name":"salt","type":"String","casdoorName":"PasswordSalt"}),
    ]);
    f.json(
        "PUT",
        &format!("/api/syncers/{id}"),
        Some(json!({"tableColumns":hashed})),
    )
    .await;
    f.run(&id).await;
    let updated = f.user().await;
    assert_eq!(updated.password_hash, encoded);
    assert_eq!(updated.password_type.as_deref(), Some("bcrypt"));
    assert!(
        PasswordService::verify_password(
            "HashedPassword42!",
            &updated.password_hash,
            "bcrypt",
            None
        )
        .unwrap()
    );
    // A later local SQL error must also roll back earlier users in this batch.
    sqlx::raw_sql(&format!("UPDATE {}.people SET fullname=CASE WHEN source_id='s1' THEN 'Must roll back' ELSE repeat('X',300) END",f.schema)).execute(&f.source).await.unwrap();
    let mut response = f
        .request("POST", &format!("/api/syncers/{id}/run"), None)
        .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert!(!response.take_string().await.unwrap().contains(&f.password));
    assert_eq!(f.user().await.display_name, updated.display_name);
    assert_eq!(f.user().await.password_hash, updated.password_hash);
    let state:(i32,bool,bool)=sqlx::query_as("SELECT consecutive_failures,lease_token IS NULL,next_run_at>clock_timestamp() FROM syncer_runtime_state WHERE syncer_id=$1").bind(&id).fetch_one(&f.pool).await.unwrap();
    assert_eq!(state, (1, true, true));
    assert!(
        !SyncerExecutor::execute_all_due(&f.other)
            .await
            .unwrap()
            .contains_key(&id)
    );
    sqlx::raw_sql(&format!(
        "UPDATE {}.people SET fullname='Recovered source'",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    sqlx::query("UPDATE syncer_runtime_state SET next_run_at=clock_timestamp()-INTERVAL '1 second' WHERE syncer_id=$1").bind(&id).execute(&f.pool).await.unwrap();
    assert!(SyncerExecutor::execute_all_due(&f.other).await.unwrap()[&id].success);
    let failures: i32 = sqlx::query_scalar(
        "SELECT consecutive_failures FROM syncer_runtime_state WHERE syncer_id=$1",
    )
    .bind(&id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(failures, 0);
    sqlx::raw_sql(&format!(
        "UPDATE {}.people SET secret='not-an-encoded-bcrypt-hash' WHERE source_id='s1'",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    assert_eq!(
        f.request("POST", &format!("/api/syncers/{id}/run"), None)
            .await
            .status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert_eq!(f.user().await.password_hash, encoded);
    let mut forbidden = f.database_body("unsafe", "people");
    forbidden["tableColumns"][1]["casdoorName"] = json!("IsAdmin");
    assert_eq!(
        f.request("POST", "/api/add-syncer", Some(forbidden))
            .await
            .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and separate CASDOG_TEST_SYNC_SOURCE_URL"]
async fn shared_scheduler_fences_simultaneous_runs_recovers_expired_leases_and_persists_due_disabled_state()
 {
    let f = Fixture::new().await;
    sqlx::raw_sql(&format!("CREATE FUNCTION {}.delay_text(text) RETURNS text LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(0.4);RETURN $1;END$$",f.schema)).execute(&f.source).await.unwrap();
    sqlx::raw_sql(&format!("CREATE VIEW {}.slow AS SELECT source_id,login,{}.delay_text(fullname) fullname,mail,secret,kind,salt FROM {}.people WHERE source_id='s1'",f.schema,f.schema,f.schema)).execute(&f.source).await.unwrap();
    let id = f.create("shared", "slow").await;
    let pool = f.pool.clone();
    let key = id.clone();
    let first = tokio::spawn(async move { SyncerService::run_sync(&pool, &key).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let leased: bool = sqlx::query_scalar(
                "SELECT lease_token IS NOT NULL FROM syncer_runtime_state WHERE syncer_id=$1",
            )
            .bind(&id)
            .fetch_one(&f.other)
            .await
            .unwrap();
            if leased {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        SyncerService::run_sync(&f.other, &id).await,
        Err(casdog::error::AppError::Conflict(_))
    ));
    assert!(first.await.unwrap().unwrap().success);
    assert!(
        !SyncerExecutor::execute_all_due(&f.other)
            .await
            .unwrap()
            .contains_key(&id)
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM syncer_user_links WHERE syncer_id=$1")
        .bind(&id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    sqlx::query("UPDATE syncer_runtime_state SET next_run_at=clock_timestamp()-INTERVAL '1 hour',lease_token=$2,lease_until=clock_timestamp()+INTERVAL '1 hour' WHERE syncer_id=$1").bind(&id).bind(uuid::Uuid::new_v4().to_string()).execute(&f.pool).await.unwrap();
    assert!(
        !SyncerExecutor::execute_all_due(&f.other)
            .await
            .unwrap()
            .contains_key(&id)
    );
    sqlx::query("UPDATE syncer_runtime_state SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE syncer_id=$1").bind(&id).execute(&f.pool).await.unwrap();
    assert!(SyncerExecutor::execute_all_due(&f.other).await.unwrap()[&id].success);
    f.json(
        "PUT",
        &format!("/api/syncers/{id}"),
        Some(json!({"is_enabled":false})),
    )
    .await;
    assert!(
        !SyncerExecutor::execute_all_due(&f.other)
            .await
            .unwrap()
            .contains_key(&id)
    );
    assert!(SyncerService::run_sync(&f.other, &id).await.is_err());
    f.json(
        "PUT",
        &format!("/api/syncers/{id}"),
        Some(json!({"is_enabled":true})),
    )
    .await;
    sqlx::query("UPDATE organizations SET disable_signin=true WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        !SyncerExecutor::execute_all_due(&f.other)
            .await
            .unwrap()
            .contains_key(&id)
    );
    assert!(SyncerService::run_sync(&f.other, &id).await.is_err());
    sqlx::query("UPDATE organizations SET disable_signin=false WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    f.cleanup().await;
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if value.len() < 128 {
        bytes.push(value.len() as u8);
    } else {
        bytes.extend([0x82, (value.len() >> 8) as u8, value.len() as u8]);
    }
    bytes.extend(value);
    bytes
}
fn item(bytes: &[u8]) -> (u8, &[u8], &[u8]) {
    let mut offset = 2;
    let mut len = bytes[1] as usize;
    if len & 128 != 0 {
        let count = len & 127;
        len = 0;
        for byte in &bytes[2..2 + count] {
            len = (len << 8) | (*byte as usize);
        }
        offset += count;
    }
    (
        bytes[0],
        &bytes[offset..offset + len],
        &bytes[offset + len..],
    )
}
async fn packet(socket: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = [0; 2];
    socket.read_exact(&mut head).await.ok()?;
    let mut len = head[1] as usize;
    if len & 128 != 0 {
        let mut bytes = vec![0; len & 127];
        socket.read_exact(&mut bytes).await.ok()?;
        len = 0;
        for byte in bytes {
            len = (len << 8) | (byte as usize);
        }
    }
    if len > 100000 {
        return None;
    }
    let mut bytes = vec![0; len];
    socket.read_exact(&mut bytes).await.ok()?;
    Some(bytes)
}
async fn ldap_reply(socket: &mut TcpStream, id: &[u8], tag: u8, payload: &[u8]) {
    let mut body = tlv(2, id);
    body.extend(tlv(tag, payload));
    socket.write_all(&tlv(0x30, &body)).await.unwrap();
}
async fn ldap_paged_done(
    socket: &mut TcpStream,
    id: &[u8],
    rc: u8,
    cookie: &[u8],
    malformed: bool,
    missing: bool,
) {
    let mut done = tlv(0x0a, &[rc]);
    done.extend(tlv(4, b""));
    done.extend(tlv(4, b""));
    let mut body = tlv(2, id);
    body.extend(tlv(0x65, &done));
    if !missing {
        // The size is an estimate, deliberately larger than the real fixture.
        let mut payload = tlv(2, &[0x40, 0x00]);
        payload.extend(tlv(4, cookie));
        let value = if malformed {
            vec![0x30, 0x80, 0xff]
        } else {
            tlv(0x30, &payload)
        };
        let mut control = tlv(4, b"1.2.840.113556.1.4.319");
        control.extend(tlv(4, &value));
        body.extend(tlv(0xa0, &tlv(0x30, &control)));
    }
    socket.write_all(&tlv(0x30, &body)).await.unwrap();
}
async fn directory() -> (
    String,
    Arc<Mutex<String>>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ldap://{}", listener.local_addr().unwrap());
    let uid = Arc::new(Mutex::new("ldap-alice".to_string()));
    let state = uid.clone();
    let count = Arc::new(AtomicUsize::new(0));
    let binds = count.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let state = state.clone();
            let count = binds.clone();
            tokio::spawn(async move {
                while let Some(message) = packet(&mut socket).await {
                    let (_, id, rest) = item(&message);
                    let (tag, body, _) = item(rest);
                    match tag {
                        0x60 => {
                            count.fetch_add(1, Ordering::SeqCst);
                            let (_, _, rest) = item(body);
                            let (_, dn, rest) = item(rest);
                            let (_, secret, _) = item(rest);
                            let okay = dn == b"cn=sync,dc=test" && secret == b"directory-secret";
                            let mut response = tlv(0x0a, &[if okay { 0 } else { 49 }]);
                            response.extend(tlv(4, b""));
                            response.extend(tlv(4, b""));
                            ldap_reply(&mut socket, id, 0x61, &response).await;
                        }
                        0x63 => {
                            let mut entry = tlv(4, b"uid=stable,dc=test");
                            let mut attributes = Vec::new();
                            for (name, value) in [
                                ("uid", state.lock().unwrap().clone()),
                                ("cn", "Directory Alice".into()),
                                ("mail", "directory@example.test".into()),
                            ] {
                                let mut attr = tlv(4, name.as_bytes());
                                attr.extend(tlv(0x31, &tlv(4, value.as_bytes())));
                                attributes.extend(tlv(0x30, &attr));
                            }
                            entry.extend(tlv(0x30, &attributes));
                            ldap_reply(&mut socket, id, 0x64, &entry).await;
                            ldap_paged_done(&mut socket, id, 0, b"", false, false).await;
                        }
                        0x42 => break,
                        _ => panic!("unexpected LDAP operation {tag}"),
                    }
                }
            });
        }
    });
    (endpoint, uid, count, task)
}
#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and separate CASDOG_TEST_SYNC_SOURCE_URL"]
async fn real_ldap_bind_search_uses_mapping_preserves_password_and_tenant_and_rejects_bad_bind() {
    let f = Fixture::new().await;
    let before = f.user().await;
    let (endpoint, uid, binds, server) = directory().await;
    sqlx::query(
        "UPDATE users SET ldap='uid=stable,dc=test' WHERE (owner=$1 OR owner=$2) AND name='alice'",
    )
    .bind(&f.owner)
    .bind(&f.foreign)
    .execute(&f.pool)
    .await
    .unwrap();
    let mapping = json!([{"name":"dn","type":"String","casdoorName":"Id","isKey":true},{"name":"uid","type":"String","casdoorName":"Name"},{"name":"cn","type":"String","casdoorName":"DisplayName"},{"name":"MAIL","type":"String","casdoorName":"Email"}]);
    let body = json!({"owner":f.owner,"name":"directory","organization":f.owner,"type":"LDAP","host":endpoint,"port":389,"user":"cn=sync,dc=test","password":"directory-secret","database":"dc=test","table":"(objectClass=person)","tableColumns":mapping,"isReadOnly":true});
    f.json("POST", "/api/add-syncer", Some(body)).await;
    f.json(
        "POST",
        &format!("/api/update-syncer?id={}/directory", f.owner),
        Some(json!({"password":"***"})),
    )
    .await;
    f.json(
        "POST",
        &format!("/api/run-syncer?id={}/directory", f.owner),
        None,
    )
    .await;
    let imported = f.user().await;
    assert_eq!(imported.password_hash, before.password_hash);
    assert_eq!(imported.name, "ldap-alice");
    assert_eq!(imported.email.as_deref(), Some("directory@example.test"));
    *uid.lock().unwrap() = "renamed-ldap-alice".into();
    f.json(
        "POST",
        &format!("/api/run-syncer?id={}/directory", f.owner),
        None,
    )
    .await;
    assert_eq!(f.user().await.name, "renamed-ldap-alice");
    assert_eq!(f.user().await.id, before.id);
    f.json(
        "POST",
        &format!("/api/update-syncer?id={}/directory", f.owner),
        Some(json!({"password":"wrong-directory-secret"})),
    )
    .await;
    let mut rejected = f
        .request(
            "POST",
            &format!("/api/run-syncer?id={}/directory", f.owner),
            None,
        )
        .await;
    assert_eq!(
        rejected.status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert!(
        !rejected
            .take_string()
            .await
            .unwrap()
            .contains("wrong-directory-secret")
    );
    assert_eq!(f.user().await.password_hash, before.password_hash);
    let foreign: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE owner=$1 AND name='alice'")
            .bind(&f.foreign)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(foreign, "foreign-hash");
    assert_eq!(binds.load(Ordering::SeqCst), 3);
    server.abort();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and separate CASDOG_TEST_SYNC_SOURCE_URL"]
async fn complete_snapshot_deletions_only_forbid_managed_accounts_and_values_affiliation_are_applied()
 {
    let f = Fixture::new().await;
    sqlx::raw_sql(&format!("ALTER TABLE {}.people ADD COLUMN department integer DEFAULT 1,ADD COLUMN banned text DEFAULT 'N'",f.schema)).execute(&f.source).await.unwrap();
    sqlx::raw_sql(&format!("CREATE TABLE {}.departments(id integer PRIMARY KEY,name text); INSERT INTO {}.departments VALUES(1,'Engineering'),(2,'Support')",f.schema,f.schema)).execute(&f.source).await.unwrap();
    let unmanaged = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,external_id) VALUES($1,$2,'unmanaged','Unmanaged','unused','not-managed')")
        .bind(&unmanaged).bind(&f.owner).execute(&f.pool).await.unwrap();
    let mut body = f.database_body("mapped", "people");
    body["affiliation_table"] = json!(format!("{}.departments", f.schema));
    body["tableColumns"][2]["values"] =
        json!(["Source Alice=Translated Alice", "Source Bob=Translated Bob"]);
    body["tableColumns"].as_array_mut().unwrap().extend([
        json!({"name":"department","type":"Number","casdoorName":"Score"}),
        json!({"name":"banned","type":"Boolean","casdoorName":"IsForbidden","values":["N","Y"]}),
    ]);
    let id = f.json("POST", "/api/syncers", Some(body)).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(f.run(&id).await["status"], "ok");
    let imported = f.user().await;
    assert_eq!(imported.display_name, "Translated Alice");
    assert_eq!(imported.affiliation.as_deref(), Some("Engineering"));
    assert_eq!(imported.score, 1);
    assert!(!imported.is_forbidden);
    sqlx::raw_sql(&format!("DELETE FROM {}.people WHERE source_id='s1'; ALTER TABLE {}.departments RENAME TO unavailable_departments",f.schema,f.schema)).execute(&f.source).await.unwrap();
    let failed = f
        .request("POST", &format!("/api/syncers/{id}/run"), None)
        .await;
    assert_eq!(failed.status_code, Some(StatusCode::INTERNAL_SERVER_ERROR));
    assert!(
        !f.user().await.is_forbidden,
        "failed snapshot must never imply source deletion"
    );
    sqlx::raw_sql(&format!(
        "ALTER TABLE {}.unavailable_departments RENAME TO departments",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    assert_eq!(f.run(&id).await["recordsForbidden"], 1);
    assert!(f.user().await.is_forbidden);
    let untouched:i64=sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE ((id=$1) OR (owner=$2 AND name='alice')) AND NOT is_forbidden")
        .bind(&unmanaged).bind(&f.foreign).fetch_one(&f.pool).await.unwrap();
    assert_eq!(untouched, 2);
    sqlx::raw_sql(&format!("INSERT INTO {}.people(source_id,login,fullname,mail) VALUES('s1','alice','Source Alice','restored@example.test')",f.schema)).execute(&f.source).await.unwrap();
    assert_eq!(f.run(&id).await["status"], "ok");
    assert!(
        !f.user().await.is_forbidden,
        "unchanged automatic ban is restored on reappearance"
    );
    sqlx::raw_sql(&format!("DELETE FROM {}.people", f.schema))
        .execute(&f.source)
        .await
        .unwrap();
    assert_eq!(
        f.run(&id).await["recordsForbidden"],
        2,
        "a verified empty snapshot is a complete deletion snapshot"
    );
    f.json(
        "PUT",
        &format!("/api/users/{}", f.user),
        Some(json!({"display_name":"Manual review needed"})),
    )
    .await;
    sqlx::raw_sql(&format!("INSERT INTO {}.people(source_id,login,fullname,mail) VALUES('s1','alice','Source Alice','restored@example.test')",f.schema)).execute(&f.source).await.unwrap();
    let reviewed = f.run(&id).await;
    assert_eq!(reviewed["conflicts"], 1);
    assert!(
        f.user().await.is_forbidden,
        "manual edits after an automatic ban must not be overwritten"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and separate CASDOG_TEST_SYNC_SOURCE_URL"]
async fn postgres_bidirectional_sync_uses_persisted_three_way_baselines_and_normal_user_crud() {
    let f = Fixture::new().await;
    sqlx::raw_sql(&format!(
        "ALTER TABLE {}.people ADD UNIQUE(login)",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    let mut body = f.database_body("bidirectional", "people");
    body["isReadOnly"] = json!(false);
    body["tableColumns"] = json!([
        {"name":"login","type":"String","casdoorName":"Name","isKey":true},
        {"name":"fullname","type":"String","casdoorName":"DisplayName"},
        {"name":"mail","type":"String","casdoorName":"Email"}]);
    let id = f.json("POST", "/api/syncers", Some(body)).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(f.run(&id).await["status"], "ok");
    f.json(
        "PUT",
        &format!("/api/users/{}", f.user),
        Some(json!({"display_name":"Local Alice changed"})),
    )
    .await;
    let due: bool = sqlx::query_scalar(
        "SELECT next_run_at<=clock_timestamp() FROM syncer_runtime_state WHERE syncer_id=$1",
    )
    .bind(&id)
    .fetch_one(&f.other)
    .await
    .unwrap();
    assert!(due, "normal user CRUD must persist a scheduler wakeup");
    sqlx::raw_sql(&format!(
        "UPDATE {}.people SET fullname='Remote Bob changed' WHERE login='bob'",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    let run = SyncerService::run_sync(&f.other, &id).await.unwrap();
    assert!(run.success);
    assert_eq!(run.records_exported, 1);
    let source: String = sqlx::query_scalar(&format!(
        "SELECT fullname FROM {}.people WHERE login='alice'",
        f.schema
    ))
    .fetch_one(&f.source)
    .await
    .unwrap();
    assert_eq!(source, "Local Alice changed");
    let bob: String =
        sqlx::query_scalar("SELECT display_name FROM users WHERE owner=$1 AND name='bob'")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(bob, "Remote Bob changed");
    f.json(
        "PUT",
        &format!("/api/users/{}", f.user),
        Some(json!({"display_name":"Concurrent local edit"})),
    )
    .await;
    sqlx::raw_sql(&format!(
        "UPDATE {}.people SET fullname='Concurrent source edit' WHERE login='alice'",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    let conflict = f.run(&id).await;
    assert_eq!(conflict["status"], "error");
    assert_eq!(conflict["conflicts"], 1);
    assert_eq!(f.user().await.display_name, "Concurrent local edit");
    assert_eq!(
        sqlx::query_scalar::<_, String>(&format!(
            "SELECT fullname FROM {}.people WHERE login='alice'",
            f.schema
        ))
        .fetch_one(&f.source)
        .await
        .unwrap(),
        "Concurrent source edit"
    );
    let state: Option<String> = sqlx::query_scalar(
        "SELECT conflict_state FROM syncer_user_links WHERE syncer_id=$1 AND source_key='alice'",
    )
    .bind(&id)
    .fetch_one(&f.other)
    .await
    .unwrap();
    assert!(state.unwrap().contains("Both local and source"));
    f.json(
        "PUT",
        &format!("/api/users/{}", f.user),
        Some(json!({"display_name":"Concurrent source edit"})),
    )
    .await;
    assert_eq!(
        f.run(&id).await["conflicts"],
        0,
        "explicit convergence acknowledges the conflict"
    );
    let created=f.json("POST","/api/users",Some(json!({"owner":f.owner,"name":"charlie","display_name":"Local Charlie","email":"charlie@example.test","password":"CharliePassword42!"}))).await;
    assert!(created["id"].is_string());
    assert_eq!(f.run(&id).await["recordsExported"], 1);
    let charlie: (String, String) = sqlx::query_as(&format!(
        "SELECT fullname,mail FROM {}.people WHERE login='charlie'",
        f.schema
    ))
    .fetch_one(&f.source)
    .await
    .unwrap();
    assert_eq!(
        charlie,
        ("Local Charlie".into(), "charlie@example.test".into())
    );
    let mut password_columns = json!([
        {"name":"login","type":"String","casdoorName":"Name","isKey":true},
        {"name":"fullname","type":"String","casdoorName":"DisplayName"},
        {"name":"mail","type":"String","casdoorName":"Email"},
        {"name":"secret","type":"String","casdoorName":"Password","isHashed":true}]);
    f.json(
        "PUT",
        &format!("/api/syncers/{id}"),
        Some(json!({"tableColumns":password_columns})),
    )
    .await;
    assert_eq!(
        f.run(&id).await["status"],
        "ok",
        "unchanged old fields may be safely rebaselined when adding mappings"
    );
    let dave=f.json("POST","/api/users",Some(json!({"owner":f.owner,"name":"dave","display_name":"Local Dave","email":"dave@example.test","password":"DavePassword42!"}))).await;
    assert!(dave["id"].is_string());
    assert_eq!(f.run(&id).await["conflicts"], 1);
    let rejected:(Option<Value>,Option<Value>)=sqlx::query_as("SELECT baseline_local,baseline_source FROM syncer_user_links WHERE syncer_id=$1 AND source_key='dave'").bind(&id).fetch_one(&f.other).await.unwrap();
    assert_eq!(rejected, (None, None));
    assert!(
        !sqlx::query_scalar::<_, bool>(&format!(
            "SELECT EXISTS(SELECT 1 FROM {}.people WHERE login='dave')",
            f.schema
        ))
        .fetch_one(&f.source)
        .await
        .unwrap()
    );
    password_columns
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"kind","type":"String","casdoorName":"PasswordType"}));
    f.json(
        "PUT",
        &format!("/api/syncers/{id}"),
        Some(json!({"tableColumns":password_columns})),
    )
    .await;
    let repaired = f.run(&id).await;
    assert_eq!(
        repaired["status"], "ok",
        "repairing explicit credential capability retries the original pending binding"
    );
    assert_eq!(repaired["recordsExported"], 1);
    let credential: (String, String) = sqlx::query_as(&format!(
        "SELECT secret,kind FROM {}.people WHERE login='dave'",
        f.schema
    ))
    .fetch_one(&f.source)
    .await
    .unwrap();
    assert!(
        PasswordService::verify_password("DavePassword42!", &credential.0, &credential.1, None)
            .unwrap()
    );
    let foreign: String =
        sqlx::query_scalar("SELECT display_name FROM users WHERE owner=$1 AND name='alice'")
            .bind(&f.foreign)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(foreign, "Foreign Alice");
    let mut moved = f
        .request(
            "PUT",
            &format!("/api/syncers/{id}"),
            Some(json!({"table":format!("{}.other",f.schema)})),
        )
        .await;
    assert_ne!(moved.status_code, Some(StatusCode::OK));
    assert!(moved.take_string().await.unwrap().contains("new syncer"));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and separate CASDOG_TEST_SYNC_SOURCE_URL"]
async fn queued_writeback_compares_source_under_lock_and_recovers_after_remote_commit_without_reapplying()
 {
    let f = Fixture::new().await;
    sqlx::raw_sql(&format!(
        "ALTER TABLE {}.people ADD PRIMARY KEY(source_id)",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    let mut body = f.database_body("recoverable", "people");
    body["isReadOnly"] = json!(false);
    let id = f.json("POST", "/api/syncers", Some(body)).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    f.run(&id).await;
    f.json(
        "PUT",
        &format!("/api/users/{}", f.user),
        Some(json!({"display_name":"Queued local edit"})),
    )
    .await;
    let mut remote = f.source.begin().await.unwrap();
    sqlx::raw_sql(&format!(
        "SELECT source_id FROM {}.people WHERE source_id='s1' FOR UPDATE",
        f.schema
    ))
    .execute(&mut *remote)
    .await
    .unwrap();
    let pool = f.other.clone();
    let syncer = id.clone();
    let running = tokio::spawn(async move { SyncerService::run_sync(&pool, &syncer).await });
    let mut queued = false;
    for _ in 0..100 {
        queued=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM syncer_operations WHERE syncer_id=$1 AND status='pending')").bind(&id).fetch_one(&f.pool).await.unwrap();
        if queued {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(queued, "export intent must commit before remote I/O");
    sqlx::raw_sql(&format!(
        "UPDATE {}.people SET fullname='Source changed after planning' WHERE source_id='s1'",
        f.schema
    ))
    .execute(&mut *remote)
    .await
    .unwrap();
    remote.commit().await.unwrap();
    let result = running.await.unwrap().unwrap();
    assert!(!result.success);
    assert_eq!(result.conflicts, 1);
    assert_eq!(
        sqlx::query_scalar::<_, String>(&format!(
            "SELECT fullname FROM {}.people WHERE source_id='s1'",
            f.schema
        ))
        .fetch_one(&f.source)
        .await
        .unwrap(),
        "Source changed after planning"
    );
    f.json(
        "PUT",
        &format!("/api/users/{}", f.user),
        Some(json!({"display_name":"Source changed after planning"})),
    )
    .await;
    assert_eq!(f.run(&id).await["status"], "ok");
    sqlx::raw_sql(&format!(
        "CREATE TABLE {}.write_count(n integer); INSERT INTO {}.write_count VALUES(0)",
        f.schema, f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    sqlx::raw_sql(&format!("CREATE FUNCTION {}.count_write() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN UPDATE {}.write_count SET n=n+1; RETURN NEW; END$$; CREATE TRIGGER count_write AFTER UPDATE ON {}.people FOR EACH ROW EXECUTE FUNCTION {}.count_write()",f.schema,f.schema,f.schema,f.schema)).execute(&f.source).await.unwrap();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let trap = format!("syncer_ack_{suffix}");
    sqlx::raw_sql(&format!("CREATE FUNCTION {trap}() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.syncer_id='{id}' AND NEW.status='applied' THEN RAISE EXCEPTION 'fixture ack failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER {trap} BEFORE UPDATE ON syncer_operations FOR EACH ROW EXECUTE FUNCTION {trap}()"))
        .execute(&f.pool).await.unwrap();
    f.json(
        "PUT",
        &format!("/api/users/{}", f.user),
        Some(json!({"display_name":"Committed before acknowledgement"})),
    )
    .await;
    let failed = f
        .request("POST", &format!("/api/syncers/{id}/run"), None)
        .await;
    assert_eq!(failed.status_code, Some(StatusCode::INTERNAL_SERVER_ERROR));
    assert_eq!(
        sqlx::query_scalar::<_, i32>(&format!("SELECT n FROM {}.write_count", f.schema))
            .fetch_one(&f.source)
            .await
            .unwrap(),
        1
    );
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM syncer_operations WHERE syncer_id=$1 AND status='pending'",
    )
    .bind(&id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(pending, 1);
    sqlx::raw_sql(&format!(
        "DROP TRIGGER {trap} ON syncer_operations; DROP FUNCTION {trap}()"
    ))
    .execute(&f.pool)
    .await
    .unwrap();
    let recovered = SyncerService::run_sync(&f.other, &id).await.unwrap();
    assert!(recovered.success);
    assert_eq!(recovered.operations_pending, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i32>(&format!("SELECT n FROM {}.write_count", f.schema))
            .fetch_one(&f.source)
            .await
            .unwrap(),
        1,
        "retry must acknowledge committed source state without repeating UPDATE triggers"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and separate CASDOG_TEST_SYNC_SOURCE_URL"]
async fn writable_credentials_preserve_source_encoding_reject_algorithm_changes_and_block_iam_as_source()
 {
    let f = Fixture::new().await;
    sqlx::raw_sql(&format!(
        "ALTER TABLE {}.people ADD PRIMARY KEY(source_id)",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    let argon = PasswordService::hash_password("SourceArgonPassword42!", "argon2", None).unwrap();
    let bcrypt = PasswordService::hash_password("SourceBcryptPassword42!", "bcrypt", None).unwrap();
    sqlx::query(&format!("UPDATE {}.people SET secret=CASE WHEN source_id='s1' THEN $1 ELSE $2 END,kind=CASE WHEN source_id='s1' THEN 'ARGON2' ELSE 'BCRYPT' END",f.schema))
        .bind(&argon).bind(&bcrypt).execute(&f.source).await.unwrap();
    sqlx::raw_sql(&format!("INSERT INTO {}.people(source_id,login,fullname,mail,secret,kind) VALUES('s3','empty-password','Empty credential','empty@example.test',NULL,'BCRYPT')",f.schema)).execute(&f.source).await.unwrap();
    let mut body = f.database_body("credentials", "people");
    body["isReadOnly"] = json!(false);
    body["tableColumns"].as_array_mut().unwrap().extend([
        json!({"name":"secret","type":"String","casdoorName":"Password","isHashed":true}),
        json!({"name":"kind","type":"String","casdoorName":"PasswordType"}),
        json!({"name":"salt","type":"String","casdoorName":"PasswordSalt"}),
    ]);
    let id = f.json("POST", "/api/syncers", Some(body)).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(f.run(&id).await["status"], "ok");
    let empty: User =
        sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND name='empty-password'")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        empty.password_type.as_deref(),
        Some("argon2"),
        "an absent source credential must not label a generated Argon hash as bcrypt"
    );
    PasswordService::validate_encoded_hash(&empty.password_hash, "argon2", None).unwrap();
    let baseline: Value = sqlx::query_scalar(
        "SELECT baseline_source FROM syncer_user_links WHERE syncer_id=$1 AND source_key='s1'",
    )
    .bind(&id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(!baseline.to_string().contains(&argon));
    assert!(!baseline.to_string().contains("SourceArgonPassword42!"));
    let bob: String = sqlx::query_scalar("SELECT id FROM users WHERE owner=$1 AND name='bob'")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    f.json(
        "PUT",
        &format!("/api/users/{bob}"),
        Some(json!({"display_name":"Bob profile edit"})),
    )
    .await;
    assert_eq!(f.run(&id).await["recordsExported"], 1);
    let unchanged: (String, String, Option<String>) = sqlx::query_as(&format!(
        "SELECT secret,kind,salt FROM {}.people WHERE source_id='s2'",
        f.schema
    ))
    .fetch_one(&f.source)
    .await
    .unwrap();
    assert_eq!(
        unchanged,
        (bcrypt.clone(), "BCRYPT".into(), None),
        "unmodified encoded credential representation is preserved exactly"
    );
    f.json(
        "PUT",
        &format!("/api/users/{}", f.user),
        Some(json!({"password":"NewArgonPassword42!"})),
    )
    .await;
    assert_eq!(f.run(&id).await["recordsExported"], 1);
    let exported: (String, String) = sqlx::query_as(&format!(
        "SELECT secret,kind FROM {}.people WHERE source_id='s1'",
        f.schema
    ))
    .fetch_one(&f.source)
    .await
    .unwrap();
    assert!(
        PasswordService::verify_password("NewArgonPassword42!", &exported.0, "argon2", None)
            .unwrap()
    );
    assert_eq!(exported.1, "ARGON2");
    f.json(
        "PUT",
        &format!("/api/users/{}", empty.id),
        Some(json!({"password":"EmptySourceLocalPassword42!"})),
    )
    .await;
    assert_eq!(f.run(&id).await["conflicts"], 1);
    assert!(
        sqlx::query_scalar::<_, Option<String>>(&format!(
            "SELECT secret FROM {}.people WHERE source_id='s3'",
            f.schema
        ))
        .fetch_one(&f.source)
        .await
        .unwrap()
        .is_none(),
        "an empty source hash with a bcrypt declaration still forbids exporting Argon2"
    );
    f.json(
        "PUT",
        &format!("/api/users/{bob}"),
        Some(json!({"password":"NewLocalArgonPassword42!"})),
    )
    .await;
    let refused = f.run(&id).await;
    assert_eq!(refused["conflicts"], 2);
    assert_eq!(
        sqlx::query_scalar::<_, String>(&format!(
            "SELECT secret FROM {}.people WHERE source_id='s2'",
            f.schema
        ))
        .fetch_one(&f.source)
        .await
        .unwrap(),
        bcrypt,
        "an Argon2 local upgrade must never replace a bcrypt-only source credential"
    );
    let mut plaintext = f.database_body("plaintext-writeback", "people");
    plaintext["isReadOnly"] = json!(false);
    plaintext["tableColumns"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"secret","type":"String","casdoorName":"Password","isHashed":false}));
    assert_ne!(
        f.request("POST", "/api/syncers", Some(plaintext))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    // An isHashed flag cannot turn an explicitly plain PasswordType into a
    // reversible encoded source credential.
    sqlx::raw_sql(&format!(
        "UPDATE {}.people SET secret='ExplicitPlainPassword42!',kind='plain' WHERE source_id='s2'",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    let failed = f
        .request("POST", &format!("/api/syncers/{id}/run"), None)
        .await;
    assert_eq!(failed.status_code, Some(StatusCode::INTERNAL_SERVER_ERROR));
    let mut self_source = f.database_body("self-source", "people");
    self_source["database"] = json!(
        reqwest::Url::parse(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
            .unwrap()
            .path()
            .trim_start_matches('/')
    );
    self_source["table"] = json!("public.users");
    let own = f.json("POST", "/api/syncers", Some(self_source)).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut rejected = f
        .request("POST", &format!("/api/syncers/{own}/run"), None)
        .await;
    assert_eq!(
        rejected.status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert!(!rejected.take_string().await.unwrap().contains(&f.password));
    let own_status = f.json("GET", &format!("/api/syncers/{own}"), None).await;
    assert!(
        own_status["error_text"]
            .as_str()
            .unwrap()
            .contains("identity database")
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL and separate CASDOG_TEST_SYNC_SOURCE_URL"]
async fn postgres_writeback_reverses_affiliation_and_boolean_values_with_typed_numeric_keys() {
    let f = Fixture::new().await;
    sqlx::raw_sql(&format!("ALTER TABLE {}.people ALTER COLUMN source_id TYPE integer USING substring(source_id FROM 2)::integer; ALTER TABLE {}.people ADD PRIMARY KEY(source_id); ALTER TABLE {}.people ADD COLUMN department integer DEFAULT 1,ADD COLUMN banned text DEFAULT 'N'; CREATE TABLE {}.departments(id integer PRIMARY KEY,name text); INSERT INTO {}.departments VALUES(1,'Engineering'),(2,'Support')",f.schema,f.schema,f.schema,f.schema,f.schema)).execute(&f.source).await.unwrap();
    sqlx::query("UPDATE users SET external_id='1' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut body = f.database_body("reverse-values", "people");
    body["isReadOnly"] = json!(false);
    body["affiliationTable"] = json!(format!("{}.departments", f.schema));
    body["tableColumns"].as_array_mut().unwrap().extend([
        json!({"name":"department","type":"Number","casdoorName":"Score"}),
        json!({"name":"banned","type":"Boolean","casdoorName":"IsForbidden","values":["N","Y"]}),
    ]);
    let id = f.json("POST", "/api/syncers", Some(body)).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    f.run(&id).await;
    f.json(
        "PUT",
        &format!("/api/users/{}", f.user),
        Some(json!({"affiliation":"Support","is_forbidden":true})),
    )
    .await;
    assert_eq!(f.run(&id).await["recordsExported"], 1);
    let source: (i32, String) = sqlx::query_as(&format!(
        "SELECT department,banned FROM {}.people WHERE source_id=1",
        f.schema
    ))
    .fetch_one(&f.source)
    .await
    .unwrap();
    assert_eq!(source, (2, "Y".into()));
    assert_eq!(
        f.run(&id).await["status"],
        "ok",
        "typed key and converted values must settle to an idempotent acknowledged baseline"
    );
    f.cleanup().await;
}

async fn keycloak_fixture(f: &Fixture) -> (String, String) {
    sqlx::raw_sql(&format!("ALTER TABLE {s}.people ADD COLUMN enabled boolean DEFAULT true,ADD COLUMN federation_link text; CREATE TABLE {s}.credential(id text PRIMARY KEY,user_id text,type text,secret_data text,credential_data text,created_date bigint); CREATE TABLE {s}.keycloak_group(id text PRIMARY KEY,name text); CREATE TABLE {s}.user_group_membership(user_id text,group_id text); CREATE TABLE {s}.federated_identity(user_id text,identity_provider text); INSERT INTO {s}.keycloak_group VALUES('g1','Migrated application'); INSERT INTO {s}.user_group_membership VALUES('s1','g1')",s=f.schema)).execute(&f.source).await.unwrap();
    let app = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password) VALUES($1,$2,'kc-login','Keycloak test',$2,$1,'secret','',true)").bind(&app).bind(&f.owner).execute(&f.pool).await.unwrap();
    let mut body = f.database_body("keycloak", "people");
    body["type"] = json!("Keycloak");
    body["tableColumns"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"enabled","type":"Boolean","casdoorName":"IsForbidden"}));
    let id = f.json("POST", "/api/syncers", Some(body)).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    (id, app)
}
async fn keycloak_password(
    f: &Fixture,
    id: &str,
    algorithm: &str,
    key_bytes: usize,
    password: &str,
) {
    use base64::Engine;
    let salt = b"binary\0salt-12345";
    let mut key = vec![0; key_bytes];
    let rounds = 27500;
    match algorithm {
        "pbkdf2-sha256" => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, rounds, &mut key)
        }
        "pbkdf2-sha512" => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password.as_bytes(), salt, rounds, &mut key)
        }
        _ => unreachable!(),
    }
    let secret = json!({"value":base64::engine::general_purpose::STANDARD.encode(key),"salt":base64::engine::general_purpose::STANDARD.encode(salt)});
    sqlx::query(&format!("INSERT INTO {}.credential(id,user_id,type,secret_data,credential_data,created_date) VALUES($1,$1,'password',$2,$3,1) ON CONFLICT(id) DO UPDATE SET secret_data=$2,credential_data=$3",f.schema))
        .bind(id).bind(secret.to_string()).bind(json!({"algorithm":algorithm,"hashIterations":rounds}).to_string()).execute(&f.source).await.unwrap();
}
async fn keycloak_login(f: &Fixture, app: &str, name: &str, password: &str) -> Response {
    TestClient::post("http://localhost/api/login")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .json(&json!({"owner":f.owner,"name":name,"password":password,"clientId":app}))
        .send(&f.service)
        .await
}
async fn keycloak_cleanup(f: Fixture, app: &str) {
    sqlx::query("DELETE FROM tokens WHERE owner=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM applications WHERE id=$1")
        .bind(app)
        .execute(&f.pool)
        .await
        .unwrap();
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL main and separate source databases"]
async fn keycloak_real_pbkdf2_credentials_login_and_source_stability_preserve_rehashed_passwords() {
    let f = Fixture::new().await;
    let (id, app) = keycloak_fixture(&f).await;
    keycloak_password(&f, "s1", "pbkdf2-sha256", 64, "Keycloak256密码!").await;
    keycloak_password(&f, "s2", "pbkdf2-sha512", 32, "Keycloak512Password!").await;
    assert_eq!(f.run(&id).await["status"], "ok");
    let imported = f.user().await;
    assert_eq!(
        imported.password_type.as_deref(),
        Some("keycloak-pbkdf2-sha256")
    );
    assert_eq!(
        imported.signup_application.as_deref(),
        Some("Migrated application")
    );
    for (name, password) in [
        ("alice", "Keycloak256密码!"),
        ("bob", "Keycloak512Password!"),
    ] {
        assert_ne!(
            keycloak_login(&f, &app, name, "incorrect-password")
                .await
                .status_code,
            Some(StatusCode::OK)
        );
        assert_eq!(
            keycloak_login(&f, &app, name, password).await.status_code,
            Some(StatusCode::OK)
        );
    }
    let upgraded = f.user().await;
    assert!(upgraded.password_hash.starts_with("$argon2"));
    f.run(&id).await;
    let repeated = f.user().await;
    assert_eq!(repeated.password_hash, upgraded.password_hash);
    assert_eq!(
        repeated.last_change_password_time,
        upgraded.last_change_password_time
    );
    keycloak_password(&f, "s1", "pbkdf2-sha256", 32, "SourceChangedPassword!").await;
    f.run(&id).await;
    assert_ne!(
        keycloak_login(&f, &app, "alice", "Keycloak256密码!")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        keycloak_login(&f, &app, "alice", "SourceChangedPassword!")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    sqlx::raw_sql(&format!(
        "UPDATE {}.people SET enabled=false WHERE source_id='s2'",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    f.run(&id).await;
    assert_ne!(
        keycloak_login(&f, &app, "bob", "Keycloak512Password!")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let foreign: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE owner=$1 AND name='alice'")
            .bind(&f.foreign)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(foreign, "foreign-hash");
    keycloak_cleanup(f, &app).await;
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL main and separate source databases"]
async fn keycloak_invalid_credentials_and_group_read_failures_roll_back_and_federation_is_explicit()
{
    let f = Fixture::new().await;
    let (id, app) = keycloak_fixture(&f).await;
    keycloak_password(&f, "s1", "pbkdf2-sha256", 32, "ValidSourcePassword!").await;
    sqlx::raw_sql(&format!(
        "INSERT INTO {}.federated_identity VALUES('s2','external-idp')",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    let previous = f.user().await;
    f.run(&id).await;
    sqlx::raw_sql(&format!("INSERT INTO {s}.credential VALUES('bad-second','s2','password','{{}}','{{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":27500}}',2); UPDATE {s}.people SET fullname='Earlier valid row must roll back' WHERE source_id='s1'",s=f.schema)).execute(&f.source).await.unwrap();
    assert_eq!(
        f.request("POST", &format!("/api/syncers/{id}/run"), None)
            .await
            .status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert_eq!(f.user().await.display_name, "Source Alice");
    sqlx::raw_sql(&format!("DELETE FROM {s}.credential WHERE id='bad-second'; UPDATE {s}.people SET fullname='Source Alice' WHERE source_id='s1'",s=f.schema)).execute(&f.source).await.unwrap();
    let bob: User = sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND name='bob'")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(bob.password_hash.starts_with("$argon2"));
    assert_ne!(
        keycloak_login(&f, &app, "bob", "ValidSourcePassword!")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    for bad in [
        json!({"algorithm":"argon2","hashIterations":2}),
        json!({"algorithm":"unknown","hashIterations":1}),
        json!({"algorithm":"pbkdf2-sha512"}),
        json!({"algorithm":"pbkdf2-sha256","hashIterations":2000001}),
    ] {
        sqlx::query(&format!(
            "UPDATE {}.credential SET credential_data=$1",
            f.schema
        ))
        .bind(bad.to_string())
        .execute(&f.source)
        .await
        .unwrap();
        sqlx::raw_sql(&format!(
            "UPDATE {}.people SET fullname='Must roll back' WHERE source_id='s2'",
            f.schema
        ))
        .execute(&f.source)
        .await
        .unwrap();
        assert_eq!(
            f.request("POST", &format!("/api/syncers/{id}/run"), None)
                .await
                .status_code,
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        let stable = f.user().await;
        assert_eq!(stable.display_name, "Source Alice");
        assert_eq!(
            stable.password_type.as_deref(),
            Some("keycloak-pbkdf2-sha256")
        );
    }
    keycloak_password(&f, "s1", "pbkdf2-sha256", 32, "ValidSourcePassword!").await;
    for secret in [
        "not-json",
        "{}",
        "{\"value\":\"invalid base64\",\"salt\":\"c2FsdA==\"}",
    ] {
        sqlx::query(&format!(
            "UPDATE {}.credential SET secret_data=$1",
            f.schema
        ))
        .bind(secret)
        .execute(&f.source)
        .await
        .unwrap();
        assert_eq!(
            f.request("POST", &format!("/api/syncers/{id}/run"), None)
                .await
                .status_code,
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
    }
    keycloak_password(&f, "s1", "pbkdf2-sha256", 32, "ValidSourcePassword!").await;
    sqlx::raw_sql(&format!(
        "ALTER TABLE {}.keycloak_group RENAME TO unavailable_group",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    assert_eq!(
        f.request("POST", &format!("/api/syncers/{id}/run"), None)
            .await
            .status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    sqlx::raw_sql(&format!("ALTER TABLE {}.unavailable_group RENAME TO keycloak_group; DELETE FROM {}.federated_identity",f.schema,f.schema)).execute(&f.source).await.unwrap();
    assert_eq!(
        f.request("POST", &format!("/api/syncers/{id}/run"), None)
            .await
            .status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    sqlx::raw_sql(&format!(
        "UPDATE {}.people SET federation_link='ldap-provider' WHERE source_id='s2'",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    assert_eq!(f.run(&id).await["status"], "ok");
    let unchanged: User = sqlx::query_as("SELECT * FROM users WHERE id=$1")
        .bind(&bob.id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(unchanged.password_hash, bob.password_hash);
    assert_ne!(f.user().await.password_hash, previous.password_hash);
    keycloak_cleanup(f, &app).await;
}

// Independent vectors: Python argon2-cffi (libargon2), not this Rust verifier.
const KEYCLOAK_ARGON_VECTORS: [(&str, &str, &str); 6] = [
    ("id", "1.0", "anQ8TWEZggkDOEU0hrtlnznkJySCVfEHVnRir8MYayg"),
    ("id", "1.3", "01cSjhubKHaeetowtm3uVN7o7sXX0fx3AN8oOXgSmj4"),
    ("i", "1.0", "iO0xo7vCxh/RAtjZWkI2rE2IengHUsVHse3A/1K/pbc"),
    ("i", "1.3", "jGPD2RTvWJfxebmaXIKuSzwUxkMWgInihSuLqZMautY"),
    ("d", "1.0", "29C9xTby7otVklPtHK12LjCgYX0pkjhQYk+EQUDZxeE"),
    ("d", "1.3", "sslrY6egxILuin0mvFmJQ2XeYA4jGpw9yIjKKhxsw/Y"),
];
fn keycloak_argon_json(variant: &str, version: &str, digest: &str) -> (Value, Value) {
    (
        json!({"value":format!("{digest}="),"salt":"a2V5Y2xvYWstc2FsdC0xNg==","additionalParameters":{}}),
        json!({"algorithm":"argon2","hashIterations":5,"additionalParameters":{"type":[variant],"version":[version],"hashLength":["32"],"memory":["7168"],"parallelism":["1"]}}),
    )
}
#[test]
fn keycloak_native_argon_vectors_cover_types_versions_and_reject_resource_and_metadata_ambiguity() {
    for (variant, version, digest) in KEYCLOAK_ARGON_VECTORS {
        let (secret, metadata) = keycloak_argon_json(variant, version, digest);
        let imported = PasswordService::import_keycloak_argon(&secret, &metadata).unwrap();
        assert!(
            PasswordService::verify_password(
                "KeycloakArgonPassword!",
                &imported.hash,
                &imported.password_type,
                None
            )
            .unwrap()
        );
        assert!(
            !PasswordService::verify_password(
                "wrong-password",
                &imported.hash,
                &imported.password_type,
                None
            )
            .unwrap()
        );
    }
    let (secret, metadata) = keycloak_argon_json("id", "1.3", KEYCLOAK_ARGON_VECTORS[1].2);
    for (field, value) in [
        ("memory", json!(["262145"])),
        ("memory", json!(["262144"])),
        ("memory", json!(["-1"])),
        ("parallelism", json!(["17"])),
        ("parallelism", json!(["0"])),
        ("hashLength", json!(["64"])),
        ("type", json!(["unknown"])),
        ("version", json!(["19"])),
        ("memory", json!(["7168", "7168"])),
        ("memory", json!(7168)),
    ] {
        let mut bad = metadata.clone();
        bad["additionalParameters"][field] = value;
        assert!(
            PasswordService::import_keycloak_argon(&secret, &bad).is_err(),
            "accepted {field}: {bad}"
        );
    }
    for rounds in [0, 11, 1000000] {
        let mut bad = metadata.clone();
        bad["hashIterations"] = json!(rounds);
        assert!(PasswordService::import_keycloak_argon(&secret, &bad).is_err());
    }
    let mut bad = metadata.clone();
    bad["additionalParameters"]
        .as_object_mut()
        .unwrap()
        .remove("version");
    assert!(PasswordService::import_keycloak_argon(&secret, &bad).is_err());
    let mut bad = metadata.clone();
    bad["algorithmData"] = json!({});
    assert!(PasswordService::import_keycloak_argon(&secret, &bad).is_err());
    let mut bad = metadata.clone();
    bad["additionalParameters"]["secret"] = json!(["not-supported"]);
    assert!(PasswordService::import_keycloak_argon(&secret, &bad).is_err());
    for (field, value) in [
        ("salt", "!!!"),
        ("salt", "YQ=="),
        ("value", "invalid-base64!"),
    ] {
        let mut bad = secret.clone();
        bad[field] = json!(value);
        assert!(PasswordService::import_keycloak_argon(&bad, &metadata).is_err());
    }
}
async fn set_keycloak_raw_argon(f: &Fixture, id: &str, secret: &Value, metadata: &Value) {
    sqlx::query(&format!("INSERT INTO {}.credential(id,user_id,type,secret_data,credential_data,created_date) VALUES($1,$1,'password',$2,$3,1) ON CONFLICT(id) DO UPDATE SET secret_data=$2,credential_data=$3",f.schema))
 .bind(id).bind(secret.to_string()).bind(metadata.to_string()).execute(&f.source).await.unwrap();
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL main and separate source databases"]
async fn keycloak_native_argon_raw_credentials_sync_login_defaults_rehash_and_batch_failure() {
    let f = Fixture::new().await;
    let (id, app) = keycloak_fixture(&f).await;
    sqlx::raw_sql(&format!(
        "INSERT INTO {}.federated_identity VALUES('s2','idp')",
        f.schema
    ))
    .execute(&f.source)
    .await
    .unwrap();
    for (variant, version, digest) in KEYCLOAK_ARGON_VECTORS {
        let (secret, metadata) = keycloak_argon_json(variant, version, digest);
        set_keycloak_raw_argon(&f, "s1", &secret, &metadata).await;
        assert_eq!(f.run(&id).await["status"], "ok");
        let imported = f.user().await;
        assert!(imported.password_hash.starts_with(&format!(
            "$argon2{variant}$v={}",
            if version == "1.3" { 19 } else { 16 }
        )));
        assert!(imported.password_hash.contains("m=7168,t=5,p=1"));
        assert_ne!(
            keycloak_login(&f, &app, "alice", "wrong-password")
                .await
                .status_code,
            Some(StatusCode::OK)
        );
        assert_eq!(
            keycloak_login(&f, &app, "alice", "KeycloakArgonPassword!")
                .await
                .status_code,
            Some(StatusCode::OK)
        );
        let upgraded = f.user().await;
        assert!(upgraded.password_hash.contains("m=19456,t=2,p=1"));
        f.run(&id).await;
        let repeated = f.user().await;
        assert_eq!(repeated.password_hash, upgraded.password_hash);
        assert_eq!(
            repeated.last_change_password_time,
            upgraded.last_change_password_time
        );
    }
    let before = f.user().await;
    let (secret, metadata) = keycloak_argon_json("id", "1.3", KEYCLOAK_ARGON_VECTORS[1].2);
    for (field, value) in [
        ("memory", json!(["4294967295"])),
        ("version", json!(["2.0"])),
        ("hashLength", json!(["64"])),
        ("parallelism", json!(["1", "2"])),
    ] {
        let mut bad = metadata.clone();
        bad["additionalParameters"][field] = value;
        set_keycloak_raw_argon(&f, "s2", &secret, &bad).await;
        sqlx::raw_sql(&format!(
            "UPDATE {}.people SET fullname='No partial write' WHERE source_id='s1'",
            f.schema
        ))
        .execute(&f.source)
        .await
        .unwrap();
        assert_eq!(
            f.request("POST", &format!("/api/syncers/{id}/run"), None)
                .await
                .status_code,
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        let stable = f.user().await;
        assert_eq!(stable.password_hash, before.password_hash);
        assert_eq!(stable.display_name, before.display_name);
    }
    sqlx::raw_sql(&format!("DELETE FROM {}.credential WHERE user_id='s2'; UPDATE {}.people SET fullname='Source Alice',enabled=false WHERE source_id='s1'",f.schema,f.schema)).execute(&f.source).await.unwrap();
    assert_eq!(f.run(&id).await["status"], "ok");
    assert_ne!(
        keycloak_login(&f, &app, "alice", "KeycloakArgonPassword!")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let foreign: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE owner=$1 AND name='alice'")
            .bind(&f.foreign)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(foreign, "foreign-hash");
    keycloak_cleanup(f, &app).await;
}

#[derive(Clone)]
struct PagedDirectoryState {
    ad: bool,
    uac: String,
    dn_suffix: String,
    username: String,
    mode: String,
    ids: Vec<usize>,
    display: String,
}
async fn paged_directory() -> (
    String,
    Arc<Mutex<PagedDirectoryState>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ldap://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(PagedDirectoryState {
        ad: false,
        uac: "512".into(),
        dn_suffix: "ou=initial,dc=test".into(),
        username: "ad-alice".into(),
        mode: "normal".into(),
        ids: vec![0, 1, 2],
        display: "Paged source".into(),
    }));
    let shared = state.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let shared = shared.clone();
            tokio::spawn(async move {
                let mut page = 0;
                while let Some(message) = packet(&mut socket).await {
                    let (_, id, rest) = item(&message);
                    let (tag, body, controls) = item(rest);
                    match tag {
                        0x60 => {
                            let (_, _, rest) = item(body);
                            let (_, dn, rest) = item(rest);
                            let (_, password, _) = item(rest);
                            let rc = if dn == b"cn=sync,dc=test" && password == b"directory-secret"
                            {
                                0
                            } else {
                                49
                            };
                            let mut done = tlv(10, &[rc]);
                            done.extend(tlv(4, b""));
                            done.extend(tlv(4, b""));
                            ldap_reply(&mut socket, id, 0x61, &done).await;
                        }
                        0x63 => {
                            let (tag, control, _) = item(controls);
                            assert_eq!(tag, 0xa0);
                            let (_, control, _) = item(control);
                            let (_, oid, rest) = item(control);
                            assert_eq!(oid, b"1.2.840.113556.1.4.319");
                            let (tag, value, _) = item(rest);
                            assert_eq!(tag, 4, "paging request must be non-critical and ignorable");
                            let (_, value, _) = item(value);
                            let (_, size, rest) = item(value);
                            assert_eq!(size, &[1, 244]);
                            let (_, cookie, _) = item(rest);
                            assert_eq!(
                                cookie,
                                if page == 0 {
                                    b"".as_slice()
                                } else {
                                    b"page\0\xfftwo".as_slice()
                                }
                            );
                            let state = shared.lock().unwrap().clone();
                            let start = if state.mode == "empty-middle" && page >= 2 {
                                (page - 1) * 2
                            } else {
                                page * 2
                            };
                            let mut ids = if state.mode.starts_with("unpaged") {
                                state.ids.clone()
                            } else {
                                state
                                    .ids
                                    .iter()
                                    .skip(start)
                                    .take(2)
                                    .copied()
                                    .collect::<Vec<_>>()
                            };
                            if state.mode == "empty-loop"
                                || state.mode == "empty-middle" && page == 1
                            {
                                ids.clear();
                            }
                            if matches!(state.mode.as_str(), "duplicate" | "loop") && page == 1 {
                                ids = vec![0];
                            }
                            for n in &ids {
                                let dn = if state.ad {
                                    format!("cn=user-{n},{}", state.dn_suffix)
                                } else {
                                    format!("uid={n},dc=test")
                                };
                                let mut entry = tlv(4, dn.as_bytes());
                                let mut attributes = Vec::new();
                                for (name, value) in [
                                    ("uid", format!("paged-{n}")),
                                    ("cn", format!("{} {n}", state.display)),
                                    ("mail", format!("paged{n}@example.test")),
                                ] {
                                    let mut attr = tlv(4, name.as_bytes());
                                    attr.extend(tlv(0x31, &tlv(4, value.as_bytes())));
                                    attributes.extend(tlv(0x30, &attr));
                                }
                                if state.ad {
                                    let mut guid = if *n == 2 {
                                        b"abcdefghijklmnop".to_vec()
                                    } else {
                                        vec![
                                            0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88,
                                            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                        ]
                                    };
                                    if *n == 1 {
                                        guid[15] = 0xfe;
                                    }
                                    if *n == 1 && state.mode == "bad-ad-guid" {
                                        guid.pop();
                                    }
                                    let values = vec![
                                        ("OBJECTguid", guid),
                                        (
                                            "SAMACCOUNTNAME",
                                            if *n == 0 {
                                                state.username.clone()
                                            } else {
                                                format!("ad-user-{n}")
                                            }
                                            .into_bytes(),
                                        ),
                                        ("givenName", b"Directory".to_vec()),
                                        ("sn", b"Person".to_vec()),
                                        (
                                            "userPrincipalName",
                                            format!("ad{n}@directory.test").into_bytes(),
                                        ),
                                        ("telephoneNumber", b"123456789".to_vec()),
                                        ("title", b"Engineer".to_vec()),
                                        ("department", b"R&D".to_vec()),
                                        ("company", b"Directory Company".to_vec()),
                                        ("streetAddress", b"1 Main Street".to_vec()),
                                        ("l", b"Shanghai".to_vec()),
                                        ("st", b"Shanghai".to_vec()),
                                        ("postalCode", b"200000".to_vec()),
                                        ("co", b"China".to_vec()),
                                        ("whenCreated", b"20231010120000.0Z".to_vec()),
                                        (
                                            "userAccountControl",
                                            if *n == 1 && state.mode == "bad-ad-uac" {
                                                b"invalid".to_vec()
                                            } else {
                                                state.uac.as_bytes().to_vec()
                                            },
                                        ),
                                    ];
                                    // Remove generic mail so AD's UPN fallback is exercised.
                                    attributes.clear();
                                    for (name, value) in values {
                                        if *n == 3
                                            && state.mode == "missing-ad-guid"
                                            && name == "OBJECTguid"
                                        {
                                            continue;
                                        }
                                        let mut attr = tlv(4, name.as_bytes());
                                        attr.extend(tlv(0x31, &tlv(4, &value)));
                                        attributes.extend(tlv(0x30, &attr));
                                    }
                                }
                                entry.extend(tlv(0x30, &attributes));
                                ldap_reply(&mut socket, id, 0x64, &entry).await;
                            }
                            let oversized = vec![b'x'; 4097];
                            let next = if page == 1 && state.mode == "oversized-cookie" {
                                oversized.as_slice()
                            } else if start + ids.len() < state.ids.len()
                                || state.mode == "empty-loop"
                                || (page == 1 && state.mode == "empty-middle")
                            {
                                b"page\0\xfftwo".as_slice()
                            } else {
                                b"".as_slice()
                            };
                            let rc = if state.mode == "unpaged-truncated"
                                || page == 1 && state.mode == "truncated"
                            {
                                4
                            } else if page == 1 && state.mode == "error" {
                                80
                            } else {
                                0
                            };
                            ldap_paged_done(
                                &mut socket,
                                id,
                                rc,
                                next,
                                page == 1 && state.mode == "malformed",
                                page == 1 && state.mode == "missing"
                                    || state.mode.starts_with("unpaged"),
                            )
                            .await;
                            page += 1;
                        }
                        0x42 => break,
                        _ => panic!("unexpected paged LDAP operation {tag}"),
                    }
                }
            });
        }
    });
    (endpoint, state, server)
}
async fn paged_ldap_syncer(f: &Fixture, endpoint: &str) -> String {
    sqlx::query(
        "UPDATE users SET ldap='uid=0,dc=test' WHERE (owner=$1 OR owner=$2) AND name='alice'",
    )
    .bind(&f.owner)
    .bind(&f.foreign)
    .execute(&f.pool)
    .await
    .unwrap();
    let mapping = json!([{"name":"dn","type":"String","casdoorName":"Id","isKey":true},{"name":"uid","type":"String","casdoorName":"Name"},{"name":"cn","type":"String","casdoorName":"DisplayName"},{"name":"mail","type":"String","casdoorName":"Email"}]);
    f.json("POST","/api/syncers",Some(json!({"owner":f.owner,"name":"paged-directory","organization":f.owner,"type":"LDAP","host":endpoint,"port":389,"user":"cn=sync,dc=test","password":"directory-secret","database":"dc=test","table":"(objectClass=person)","tableColumns":mapping,"isReadOnly":true}))).await["id"].as_str().unwrap().into()
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL main and source fixture databases"]
async fn ldap_complete_paged_snapshot_imports_all_users_and_only_then_reconciles_source_deletions()
{
    let f = Fixture::new().await;
    let before = f.user().await;
    let (endpoint, state, server) = paged_directory().await;
    let id = paged_ldap_syncer(&f, &endpoint).await;
    assert_eq!(f.run(&id).await["recordsSynced"], 3);
    let imported = f.user().await;
    assert_eq!(imported.id, before.id);
    assert_eq!(imported.password_hash, before.password_hash);
    assert_eq!(imported.display_name, "Paged source 0");
    // A server may ignore a non-critical paging request and return a
    // complete unpaged result larger than the requested 500 entries.
    let prefix = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type,ldap) SELECT $1||n::text,$2,'paged-'||n::text,'Preexisting '||n::text,$3,'argon2','uid='||n::text||',dc=test' FROM generate_series(1,500) n WHERE NOT EXISTS(SELECT 1 FROM users WHERE owner=$2 AND name='paged-'||n::text)")
        .bind(prefix).bind(&f.owner).bind(&before.password_hash).execute(&f.pool).await.unwrap();
    {
        let mut state = state.lock().unwrap();
        state.mode = "unpaged".into();
        state.ids = (0..501).collect();
    }
    assert_eq!(
        f.run(&id).await["recordsSynced"],
        501,
        "successful unpaged fallback may exceed the requested page size"
    );
    {
        let mut state = state.lock().unwrap();
        state.mode = "unpaged-truncated".into();
        state.display = "No partial fallback".into();
    }
    assert_eq!(
        f.request("POST", &format!("/api/syncers/{id}/run"), None)
            .await
            .status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert_eq!(f.user().await.display_name, "Paged source 0");
    {
        let mut state = state.lock().unwrap();
        state.mode = "normal".into();
        state.ids = vec![0, 1, 2];
        state.display = "Paged source".into();
    }
    assert_eq!(f.run(&id).await["recordsForbidden"], 498);
    // RFC 2696 cookies are opaque cursor handles: two non-final
    // responses may legally reuse the same bytes while the cursor advances.
    state.lock().unwrap().ids = vec![0, 1, 2, 3, 4];
    assert_eq!(
        f.run(&id).await["recordsSynced"],
        5,
        "three pages with a repeated opaque cookie must complete"
    );
    assert_eq!(f.user().await.id, before.id);
    state.lock().unwrap().ids = vec![0, 1, 2];
    assert_eq!(f.run(&id).await["recordsForbidden"], 2);
    state.lock().unwrap().mode = "empty-middle".into();
    assert_eq!(
        f.run(&id).await["recordsSynced"],
        3,
        "a legal empty intermediate page must not truncate the traversal"
    );
    state.lock().unwrap().mode = "normal".into();
    let removed: String = sqlx::query_scalar(
        "SELECT user_id FROM syncer_user_links WHERE syncer_id=$1 AND source_key='uid=1,dc=test'",
    )
    .bind(&id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    {
        let mut state = state.lock().unwrap();
        state.ids = vec![0, 2];
        state.display = "Updated source".into();
    }
    let run = f.run(&id).await;
    assert_eq!(run["recordsSynced"], 2);
    assert_eq!(run["recordsForbidden"], 1);
    assert_eq!(f.user().await.display_name, "Updated source 0");
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT is_forbidden FROM users WHERE id=$1")
            .bind(removed)
            .fetch_one(&f.pool)
            .await
            .unwrap()
    );
    state.lock().unwrap().ids.clear();
    assert_eq!(f.run(&id).await["recordsForbidden"], 2);
    let foreign: (String, bool) = sqlx::query_as(
        "SELECT password_hash,is_forbidden FROM users WHERE owner=$1 AND name='alice'",
    )
    .bind(&f.foreign)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(foreign, ("foreign-hash".into(), false));
    server.abort();
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires migrated PostgreSQL main and source fixture databases"]
async fn ldap_later_page_errors_truncation_bad_cookies_or_controls_never_partially_write_or_forbid()
{
    let f = Fixture::new().await;
    let (endpoint, state, server) = paged_directory().await;
    let id = paged_ldap_syncer(&f, &endpoint).await;
    f.run(&id).await;
    let before = f.user().await;
    for mode in [
        "error",
        "truncated",
        "malformed",
        "missing",
        "loop",
        "empty-loop",
        "duplicate",
        "oversized-cookie",
    ] {
        {
            let mut state = state.lock().unwrap();
            state.mode = mode.into();
            state.display = "Must not partially write".into();
        }
        assert_eq!(
            f.request("POST", &format!("/api/syncers/{id}/run"), None)
                .await
                .status_code,
            Some(StatusCode::INTERNAL_SERVER_ERROR),
            "accepted {mode}"
        );
        let after = f.user().await;
        assert_eq!(
            after.display_name, before.display_name,
            "partial profile on {mode}"
        );
        assert_eq!(after.password_hash, before.password_hash);
        assert!(!after.is_forbidden);
        let active:i64=sqlx::query_scalar("SELECT count(*) FROM users u JOIN syncer_user_links l ON l.user_id=u.id WHERE l.syncer_id=$1 AND NOT u.is_forbidden").bind(&id).fetch_one(&f.pool).await.unwrap();
        assert_eq!(active, 3, "false deletion on {mode}");
    }
    {
        let mut state = state.lock().unwrap();
        state.mode = "normal".into();
        state.display = "Recovered".into();
    }
    assert_eq!(f.run(&id).await["status"], "ok");
    assert_eq!(f.user().await.display_name, "Recovered 0");
    server.abort();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL main and source fixture databases"]
async fn active_directory_guid_identity_profile_defaults_and_uac_survive_dn_and_username_changes() {
    let f = Fixture::new().await;
    let before = f.user().await;
    let (endpoint, state, server) = paged_directory().await;
    state.lock().unwrap().ad = true;
    let guid = "00112233-4455-6677-8899-aabbccddeeff";
    sqlx::query("UPDATE users SET external_id=$1,ldap='directory-provider-reference',properties='{\"keep\":\"existing\"}' WHERE id=$2").bind(guid).bind(&f.user).execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE users SET external_id=$1 WHERE owner=$2 AND name='alice'")
        .bind(guid)
        .bind(&f.foreign)
        .execute(&f.pool)
        .await
        .unwrap();
    let body = json!({"owner":f.owner,"name":"active-directory","organization":f.owner,"type":"Active Directory","host":endpoint,"port":389,"user":"cn=sync,dc=test","password":"directory-secret","database":"dc=test","isReadOnly":true});
    let id = f.json("POST", "/api/syncers", Some(body)).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(f.run(&id).await["recordsSynced"], 3);
    let first = f.user().await;
    assert_eq!(first.id, before.id);
    assert_eq!(first.external_id.as_deref(), Some(guid));
    assert_eq!(first.ldap.as_deref(), Some("directory-provider-reference"));
    assert_eq!(first.password_hash, before.password_hash);
    assert_eq!(first.name, "ad-alice");
    assert_eq!(first.display_name, "Directory Person");
    assert_eq!(first.email.as_deref(), Some("ad0@directory.test"));
    assert_eq!(first.phone.as_deref(), Some("123456789"));
    assert_eq!(first.title.as_deref(), Some("Engineer"));
    assert_eq!(first.affiliation.as_deref(), Some("R&D"));
    assert_eq!(first.location.as_deref(), Some("Shanghai, Shanghai, China"));
    assert_eq!(
        first.address,
        Some(json!(["1 Main Street, Shanghai, Shanghai, 200000, China"]))
    );
    assert_eq!(
        first.properties.as_ref().unwrap()["company"],
        "Directory Company"
    );
    assert_eq!(
        first.properties.as_ref().unwrap()["userPrincipalName"],
        "ad0@directory.test"
    );
    assert_eq!(first.properties.as_ref().unwrap()["keep"], "existing");
    assert_eq!(first.created_at.to_rfc3339(), "2023-10-10T12:00:00+00:00");
    let ascii:i64=sqlx::query_scalar("SELECT count(*) FROM users WHERE owner=$1 AND external_id='64636261-6665-6867-696a-6b6c6d6e6f70'").bind(&f.owner).fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        ascii, 1,
        "GUID bytes that happen to be UTF8 still need AD byte ordering"
    );
    {
        let mut state = state.lock().unwrap();
        state.dn_suffix = "ou=moved,dc=test".into();
        state.username = "renamed-ad-alice".into();
    }
    f.run(&id).await;
    let renamed = f.user().await;
    assert_eq!(renamed.id, first.id);
    assert_eq!(renamed.name, "renamed-ad-alice");
    assert_eq!(renamed.password_hash, first.password_hash);
    assert_eq!(renamed.ldap, first.ldap);
    let links: i64 =
        sqlx::query_scalar("SELECT count(*) FROM syncer_user_links WHERE syncer_id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(links, 3);
    {
        let mut state = state.lock().unwrap();
        state.mode = "missing-ad-guid".into();
        state.ids = vec![0, 1, 2, 3];
    }
    assert_eq!(f.run(&id).await["recordsSynced"], 4);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM users WHERE owner=$1 AND external_id='ad-user-3'"
        )
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        1,
        "absent GUID uses upstream's explicit sAMAccountName fallback"
    );
    {
        let mut state = state.lock().unwrap();
        state.mode = "normal".into();
        state.ids = vec![0, 1, 2];
    }
    assert_eq!(f.run(&id).await["recordsForbidden"], 1);
    for (uac, disabled) in [
        ("512", false),
        ("514", true),
        ("66048", false),
        ("66050", true),
    ] {
        state.lock().unwrap().uac = uac.into();
        f.run(&id).await;
        assert_eq!(
            f.user().await.is_forbidden,
            disabled,
            "wrong ACCOUNTDISABLE bit for {uac}"
        );
    }
    state.lock().unwrap().uac = "512".into();
    f.run(&id).await;
    let stable = f.user().await;
    for mode in [
        "bad-ad-guid",
        "bad-ad-uac",
        "error",
        "truncated",
        "malformed",
        "missing",
    ] {
        {
            let mut state = state.lock().unwrap();
            state.mode = mode.into();
            state.username = "must-not-partially-rename".into();
        }
        assert_eq!(
            f.request("POST", &format!("/api/syncers/{id}/run"), None)
                .await
                .status_code,
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        let current = f.user().await;
        assert_eq!(current.name, stable.name);
        assert_eq!(current.password_hash, stable.password_hash);
        assert!(!current.is_forbidden);
    }
    let foreign: (String, bool) = sqlx::query_as(
        "SELECT password_hash,is_forbidden FROM users WHERE owner=$1 AND external_id=$2",
    )
    .bind(&f.foreign)
    .bind(guid)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(foreign, ("foreign-hash".into(), false));
    {
        let mut state = state.lock().unwrap();
        state.mode = "normal".into();
        state.username = "renamed-ad-alice".into();
    }
    f.json("PUT",&format!("/api/syncers/{id}"),Some(json!({"tableColumns":[{"name":"sn+givenName","type":"String","casdoorName":"DisplayName"}]}))).await;
    f.run(&id).await;
    assert_eq!(f.user().await.display_name, "Person Directory");
    let rejected = f
        .request(
            "PUT",
            &format!("/api/syncers/{id}"),
            Some(
                json!({"tableColumns":[{"name":"title","type":"String","casdoorName":"IsAdmin"}]}),
            ),
        )
        .await;
    assert_ne!(rejected.status_code, Some(StatusCode::OK));
    server.abort();
    f.cleanup().await;
}
