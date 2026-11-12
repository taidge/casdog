//! Real cloud-directory wire protocols and normal authorized Syncer APIs.
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    models::{User, UserResponse},
    services::{AuthService, PasswordService, UserService, syncer_executor::SyncerExecutor},
};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
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
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};

struct State {
    mode: AtomicU8,
    generation: AtomicU8,
    hits: AtomicUsize,
    token_hits: AtomicUsize,
    assertions: Mutex<Vec<Value>>,
    public_key: String,
    entered: Notify,
    release: Notify,
}
struct Wire {
    origin: String,
    secret: String,
    state: Arc<State>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Wire {
    async fn new() -> Self {
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let secret=json!({"type":"service_account","client_email":"directory@fixture.test","private_key_id":"fixture-key","private_key":pem,"token_uri":format!("{origin}/google/token")}).to_string();
        let state = Arc::new(State {
            mode: AtomicU8::new(0),
            generation: AtomicU8::new(0),
            hits: AtomicUsize::new(0),
            token_hits: AtomicUsize::new(0),
            assertions: Mutex::new(vec![]),
            public_key: RsaPublicKey::from(&key)
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let shared = state.clone();
        let base = origin.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let s = shared.clone();
                let origin = base.clone();
                tokio::spawn(async move {
                    let mut raw = vec![];
                    let mut buf = [0; 4096];
                    let end = loop {
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        raw.extend_from_slice(&buf[..n]);
                        if let Some(i) = raw.windows(4).position(|x| x == b"\r\n\r\n") {
                            break i + 4;
                        }
                        assert!(raw.len() < 131072);
                    };
                    let head = String::from_utf8(raw[..end].to_vec()).unwrap();
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.split_once(':')
                                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while raw.len() < end + length {
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        raw.extend_from_slice(&buf[..n]);
                    }
                    let first = head.lines().next().unwrap();
                    let mut parts = first.split_whitespace();
                    let method = parts.next().unwrap();
                    let target = parts.next().unwrap();
                    let url = reqwest::Url::parse(&format!("{origin}{target}")).unwrap();
                    let query: std::collections::HashMap<String, String> =
                        url.query_pairs().into_owned().collect();
                    let path = url.path();
                    let second = query.contains_key("pageToken") || query.contains_key("cursor");
                    let mode = s.mode.load(Ordering::SeqCst);
                    let generation = s.generation.load(Ordering::SeqCst);
                    s.hits.fetch_add(1, Ordering::SeqCst);
                    let mut status = 200;
                    let body = if path.ends_with("/token") {
                        assert_eq!(method, "POST");
                        s.token_hits.fetch_add(1, Ordering::SeqCst);
                        let form: std::collections::HashMap<String, String> =
                            reqwest::Url::parse(&format!(
                                "http://fixture/?{}",
                                std::str::from_utf8(&raw[end..end + length]).unwrap()
                            ))
                            .unwrap()
                            .query_pairs()
                            .into_owned()
                            .collect();
                        if path == "/azure/token" {
                            assert_eq!(form["client_id"], "azure-client");
                            assert_eq!(form["client_secret"], "azure-fixture-secret");
                            assert_eq!(form["scope"], "https://graph.microsoft.com/.default");
                            assert_eq!(form["grant_type"], "client_credentials");
                        } else {
                            assert_eq!(
                                form["grant_type"],
                                "urn:ietf:params:oauth:grant-type:jwt-bearer"
                            );
                            let mut validation =
                                jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
                            validation.set_audience(&[format!("{origin}/google/token")]);
                            validation.set_issuer(&["directory@fixture.test"]);
                            let claims = jsonwebtoken::decode::<Value>(
                                &form["assertion"],
                                &jsonwebtoken::DecodingKey::from_rsa_pem(s.public_key.as_bytes())
                                    .unwrap(),
                                &validation,
                            )
                            .unwrap()
                            .claims;
                            assert_eq!(claims["sub"], "administrator@fixture.test");
                            assert_eq!(
                                claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
                                3600
                            );
                            assert_eq!(
                                claims["scope"],
                                "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly"
                            );
                            s.assertions.lock().unwrap().push(claims);
                        }
                        if mode == 5 {
                            status = 401;
                            json!({"error":"invalid_client"})
                        } else {
                            json!({"access_token":"fixture-access","token_type":"Bearer","expires_in":3600})
                        }
                    } else {
                        assert!(head.lines().any(|h| {
                            h.eq_ignore_ascii_case("authorization: Bearer fixture-access")
                        }));
                        if mode == 8 && !second && path.ends_with("/users") {
                            s.entered.notify_one();
                            s.release.notified().await;
                        }
                        if mode == 1 && second {
                            status = 503;
                            json!({"error":"page unavailable"})
                        } else if path == "/graph/v1.0/users" {
                            assert_eq!(
                                query.get("$top").map(String::as_str).unwrap_or("999"),
                                "999"
                            );
                            let id = if second && mode != 3 { "u2" } else { "u1" };
                            let name = if generation > 0 && id == "u1" {
                                "renamed@fixture.test"
                            } else if id == "u1" {
                                "alice@fixture.test"
                            } else {
                                "bob@fixture.test"
                            };
                            let mut user = json!({"id":id,"userPrincipalName":name,"displayName":if generation>0{"Changed"}else{"Directory Alice"},"givenName":"Directory","surname":"Alice","mail":null,"mobilePhone":"123456","jobTitle":"Engineer","officeLocation":"Remote","preferredLanguage":"en","accountEnabled":generation==0});
                            if mode == 2 && second {
                                user.as_object_mut().unwrap().remove("accountEnabled");
                            }
                            if second {
                                json!({"value":[user]})
                            } else {
                                json!({"value":[user],"@odata.nextLink":if mode==4 {"http://127.0.0.1:1/steal".to_string()}else{format!("{origin}/graph/v1.0/users?cursor=opaque")}})
                            }
                        } else if path.ends_with("/users") {
                            assert_eq!(query["maxResults"], "500");
                            assert_eq!(query["customer"], "my_customer");
                            let id = if second { "u2" } else { "u1" };
                            let name = if generation > 0 && !second {
                                "renamed@fixture.test"
                            } else if second {
                                "bob@fixture.test"
                            } else {
                                "alice@fixture.test"
                            };
                            let user = json!({"id":id,"primaryEmail":name,"name":{"fullName":if generation>0{"Changed"}else{"Directory Alice"},"givenName":"Directory","familyName":"Alice"},"suspended":generation>0,"isAdmin":true,"creationTime":"2021-01-02T03:04:05Z","thumbnailPhotoUrl":"https://images.example.test/avatar"});
                            if second {
                                json!({"kind":"admin#directory#users","users":[user]})
                            } else {
                                json!({"kind":"admin#directory#users","users":[user],"nextPageToken":"users-two"})
                            }
                        } else if path.ends_with("/groups") {
                            assert_eq!(query["maxResults"], "200");
                            if second {
                                json!({"kind":"admin#directory#groups","groups":[{"id":"g2","email":"other@fixture.test","name":"Other"}]})
                            } else {
                                json!({"kind":"admin#directory#groups","groups":[{"id":"g1","email":if generation>0{"renamed-group@fixture.test"}else{"team@fixture.test"},"name":if generation>0{"Renamed Team"}else{"Team"}}],"nextPageToken":"groups-two"})
                            }
                        } else if path.ends_with("/members") {
                            assert_eq!(query["maxResults"], "200");
                            if mode == 6 {
                                status = 503;
                                json!({"error":"members unavailable"})
                            } else if path.contains("/g2/") || generation == 2 {
                                json!({"kind":"admin#directory#members","members":[]})
                            } else if second {
                                json!({"kind":"admin#directory#members","members":[{"id":"u2","type":"USER"},{"id":"nested","type":"GROUP"},{"id":"outside","type":"USER"}]})
                            } else {
                                json!({"kind":"admin#directory#members","members":[{"id":"u1","type":"USER"}],"nextPageToken":"members-two"})
                            }
                        } else {
                            status = 404;
                            json!({"error":"unknown route"})
                        }
                    };
                    let data = body.to_string();
                    let response = format!(
                        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{data}",
                        data.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        Self {
            origin,
            secret,
            state,
            task,
        }
    }
}

struct Fixture {
    pool: PgPool,
    service: Service,
    owner: String,
    foreign: String,
    auth: String,
    global: String,
    admin_id: String,
    global_id: String,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let owner = format!("cloud-{}", uuid::Uuid::new_v4().simple());
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
        let admin_id = uuid::Uuid::new_v4().to_string();
        let global_id = uuid::Uuid::new_v4().to_string();
        let mut tokens = vec![];
        for (id, org) in [(&admin_id, owner.as_str()), (&global_id, "built-in")] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,'Cloud test administrator','fixture',true)").bind(id).bind(org).bind(format!("cloud-admin-{}",uuid::Uuid::new_v4().simple())).execute(&pool).await.unwrap();
            let user: User = sqlx::query_as("SELECT * FROM users WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
            tokens.push(format!(
                "Bearer {}",
                AuthService::new(UserService::new(diesel.clone()))
                    .generate_token(&UserResponse::from(user))
                    .unwrap()
            ));
        }
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        Self {
            pool,
            service,
            owner,
            foreign,
            auth: tokens.remove(0),
            global: tokens.remove(0),
            admin_id,
            global_id,
        }
    }
    async fn request(
        &self,
        global: bool,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Response {
        let url = format!("http://localhost{path}");
        let request = match method {
            "GET" => TestClient::get(url),
            "POST" => TestClient::post(url),
            "PUT" => TestClient::put(url),
            "DELETE" => TestClient::delete(url),
            _ => unreachable!(),
        }
        .add_header(
            "Authorization",
            if global { &self.global } else { &self.auth },
            true,
        );
        if let Some(body) = body {
            request.json(&body).send(&self.service).await
        } else {
            request.send(&self.service).await
        }
    }
    async fn json(&self, global: bool, method: &str, path: &str, body: Option<Value>) -> Value {
        let mut res = self.request(global, method, path, body).await;
        let code = res.status_code;
        let body = res.take_string().await.unwrap();
        assert_eq!(code, Some(StatusCode::OK), "{body}");
        serde_json::from_str(&body).unwrap()
    }
    fn body(&self, wire: &Wire, kind: &str, name: &str) -> Value {
        let google = kind == "Google Workspace";
        json!({"owner":self.owner,"name":name,"organization":self.owner,"type":kind,"port":443,"host":if google{"administrator@fixture.test"}else{"fixture-tenant"},"user":if google{"directory@fixture.test"}else{"azure-client"},"password":if google{wire.secret.clone()}else{"azure-fixture-secret".into()},"database":if google{json!({"api_base":format!("{}/admin/directory/v1",wire.origin)}).to_string()}else{json!({"token_endpoint":format!("{}/azure/token",wire.origin),"api_base":format!("{}/graph/v1.0",wire.origin)}).to_string()},"isReadOnly":true,"isEnabled":true,"syncInterval":60})
    }
    async fn create(&self, wire: &Wire, kind: &str, name: &str) -> String {
        self.json(
            false,
            "POST",
            "/api/syncers",
            Some(self.body(wire, kind, name)),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .into()
    }
    async fn approve(&self, id: &str) {
        assert_eq!(
            self.json(
                true,
                "POST",
                &format!("/api/syncers/{id}/network-approval"),
                Some(json!({"allow_private":true}))
            )
            .await["allow_private"],
            true
        );
    }
    async fn run(&self, id: &str) -> Value {
        self.json(false, "POST", &format!("/api/syncers/{id}/run"), None)
            .await
    }
    async fn user(&self, id: &str) -> User {
        sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND external_id=$2")
            .bind(&self.owner)
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn cleanup(self) {
        sqlx::query("DELETE FROM syncers WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM groups WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE owner=$1 OR owner=$2 OR id=$3 OR id=$4")
            .bind(&self.owner)
            .bind(&self.foreign)
            .bind(&self.admin_id)
            .bind(&self.global_id)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE name=$1 OR name=$2")
            .bind(&self.owner)
            .bind(&self.foreign)
            .execute(&self.pool)
            .await
            .unwrap();
        self.pool.close().await;
    }
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn azure_native_and_legacy_crud_real_token_pagination_rename_preserves_credentials_and_tenant()
 {
    let f = Fixture::new().await;
    let w = Wire::new().await;
    let hash = PasswordService::hash_password("CloudPassword42!", "argon2", None).unwrap();
    let local = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type,external_id,mfa_enabled,totp_secret,provider_ids,properties) VALUES($1,$2,'old-local','Old',$3,'argon2','u1',true,'unchanged-secret','{\"google\":\"binding\"}','{\"manual\":\"preserve\"}')").bind(&local).bind(&f.owner).bind(&hash).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,external_id) VALUES($1,$2,'foreign','Foreign','foreign','u1')").bind(uuid::Uuid::new_v4().to_string()).bind(&f.foreign).execute(&f.pool).await.unwrap();
    let id = f.create(&w, "Azure AD", "azure").await;
    let masked = f
        .json(false, "GET", &format!("/api/syncers/{id}"), None)
        .await;
    assert_eq!(masked["password"], "***");
    assert!(!masked.to_string().contains("azure-fixture-secret"));
    let legacy = f
        .json(
            false,
            "GET",
            &format!("/api/get-syncer?id={}/azure", f.owner),
            None,
        )
        .await;
    assert_eq!(legacy["data"]["password"], "***");
    f.json(
        false,
        "POST",
        &format!("/api/update-syncer?id={}/azure", f.owner),
        Some(json!({"owner":f.owner,"name":"azure","password":"***","syncInterval":61})),
    )
    .await;
    f.approve(&id).await;
    assert_eq!(f.run(&id).await["recordsSynced"], 2);
    let before = f.user("u1").await;
    assert_eq!(before.id, local);
    assert_eq!(before.password_hash, hash);
    assert_eq!(before.title.as_deref(), Some("Engineer"));
    assert_eq!(before.email.as_deref(), Some("alice@fixture.test"));
    w.state.generation.store(1, Ordering::SeqCst);
    assert_eq!(f.run(&id).await["recordsSynced"], 2);
    let after = f.user("u1").await;
    assert_eq!(after.id, before.id);
    assert_ne!(after.name, before.name);
    assert!(after.is_forbidden && after.mfa_enabled);
    assert_eq!(after.password_hash, hash);
    assert_eq!(after.totp_secret, before.totp_secret);
    assert_eq!(after.provider_ids, before.provider_ids);
    assert_eq!(after.properties.unwrap()["manual"], "preserve");
    let foreign: (String, bool) = sqlx::query_as(
        "SELECT display_name,is_forbidden FROM users WHERE owner=$1 AND external_id='u1'",
    )
    .bind(&f.foreign)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(foreign, ("Foreign".into(), false));
    assert_eq!(w.state.token_hits.load(Ordering::SeqCst), 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn google_service_account_signature_groups_stable_rename_manual_membership_and_delete_lifecycle()
 {
    let f = Fixture::new().await;
    let w = Wire::new().await;
    let created = f
        .json(
            false,
            "POST",
            "/api/add-syncer",
            Some(f.body(&w, "Google Workspace", "google")),
        )
        .await;
    assert_eq!(created["data"], true);
    assert_eq!(created["data2"]["password"], "***");
    assert!(!created.to_string().contains("BEGIN PRIVATE KEY"));
    let id = created["data2"]["id"].as_str().unwrap().to_owned();
    let masked = f
        .json(false, "GET", &format!("/api/syncers/{id}"), None)
        .await;
    assert_eq!(masked["password"], "***");
    f.json(
        false,
        "PUT",
        &format!("/api/syncers/{id}"),
        Some(json!({"password":"***"})),
    )
    .await;
    f.approve(&id).await;
    assert_eq!(f.run(&id).await["recordsSynced"], 2);
    let alice = f.user("u1").await;
    let bob = f.user("u2").await;
    assert!(!alice.is_admin);
    assert_eq!(
        alice.properties.as_ref().unwrap()["cloud_directory"]["remote_is_admin"],
        true
    );
    let group: (String, String) = sqlx::query_as(
        "SELECT group_id,group_name FROM syncer_group_links WHERE syncer_id=$1 AND source_key='g1'",
    )
    .bind(&id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(
        alice
            .groups
            .as_ref()
            .unwrap()
            .as_array()
            .unwrap()
            .contains(&json!(format!("{}/{}", f.owner, group.1)))
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_groups WHERE group_id=$1")
            .bind(&group.0)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        2
    );
    let response = f
        .request(
            false,
            "POST",
            "/api/groups/add-user",
            Some(json!({"user_id":alice.id,"group_id":group.0})),
        )
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    w.state.generation.store(1, Ordering::SeqCst);
    f.run(&id).await;
    let renamed: (String, String) =
        sqlx::query_as("SELECT id,contact_email FROM groups WHERE id=$1")
            .bind(&group.0)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        renamed,
        (group.0.clone(), "renamed-group@fixture.test".into())
    );
    assert_eq!(f.user("u1").await.id, alice.id);
    assert_eq!(f.user("u1").await.password_hash, alice.password_hash);
    w.state.generation.store(2, Ordering::SeqCst);
    f.run(&id).await;
    let pairs: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM user_groups WHERE group_id=$1")
            .bind(&group.0)
            .fetch_all(&f.pool)
            .await
            .unwrap();
    assert_eq!(pairs, vec![alice.id.clone()]);
    assert!(
        !f.user("u2")
            .await
            .groups
            .unwrap_or(json!([]))
            .as_array()
            .unwrap()
            .contains(&json!(format!("{}/{}", f.owner, group.1)))
    );
    assert!(
        f.user("u1")
            .await
            .groups
            .unwrap()
            .as_array()
            .unwrap()
            .contains(&json!(format!("{}/{}", f.owner, group.1)))
    );
    w.state.generation.store(0, Ordering::SeqCst);
    f.run(&id).await;
    assert_eq!(f.user("u2").await.id, bob.id);
    let deleted = f
        .request(false, "DELETE", &format!("/api/syncers/{id}"), None)
        .await;
    assert_eq!(deleted.status_code, Some(StatusCode::NO_CONTENT));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_groups WHERE group_id=$1")
            .bind(&group.0)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1)")
            .bind(&group.0)
            .fetch_one(&f.pool)
            .await
            .unwrap()
    );
    assert_eq!(w.state.assertions.lock().unwrap().len(), 4);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn cloud_failed_second_page_bad_identity_or_group_query_never_imports_partial_or_forbids() {
    for kind in ["Azure AD", "Google Workspace"] {
        let f = Fixture::new().await;
        let w = Wire::new().await;
        let id = f.create(&w, kind, "atomic").await;
        f.approve(&id).await;
        f.run(&id).await;
        let before = f.user("u1").await;
        w.state.generation.store(1, Ordering::SeqCst);
        let modes = if kind == "Azure AD" {
            vec![1, 2, 3, 4, 5]
        } else {
            vec![1, 5, 6]
        };
        for mode in modes {
            w.state.mode.store(mode, Ordering::SeqCst);
            let response = f
                .request(false, "POST", &format!("/api/syncers/{id}/run"), None)
                .await;
            assert_ne!(response.status_code, Some(StatusCode::OK), "mode {mode}");
            let after = f.user("u1").await;
            assert_eq!(after.id, before.id);
            assert_eq!(after.name, before.name);
            assert_eq!(after.display_name, before.display_name);
            assert!(!after.is_forbidden);
            assert_eq!(after.password_hash, before.password_hash);
            assert_eq!(after.groups, before.groups);
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM syncer_user_links WHERE syncer_id=$1"
                )
                .bind(&id)
                .fetch_one(&f.pool)
                .await
                .unwrap(),
                2
            );
        }
        f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn cloud_private_approval_is_explicit_config_bound_tenant_safe_and_pool_one_does_not_deadlock()
 {
    let f = Fixture::new().await;
    let w = Wire::new().await;
    let id = f.create(&w, "Azure AD", "approval").await;
    let denied = f
        .request(
            false,
            "POST",
            &format!("/api/syncers/{id}/network-approval"),
            Some(json!({"allow_private":true})),
        )
        .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    assert_ne!(
        f.request(false, "POST", &format!("/api/syncers/{id}/run"), None)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(w.state.hits.load(Ordering::SeqCst), 0);
    let mut foreign = f.body(&w, "Azure AD", "foreign");
    foreign["organization"] = json!(f.foreign);
    assert_ne!(
        f.request(false, "POST", "/api/syncers", Some(foreign))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let mut writable = f.body(&w, "Azure AD", "writable");
    writable["isReadOnly"] = json!(false);
    assert_eq!(
        f.request(false, "POST", "/api/syncers", Some(writable))
            .await
            .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    for (field, value) in [
        ("password", json!("{\"type\":\"service_account\"}")),
        ("user", json!("another-service-account@fixture.test")),
        (
            "tableColumns",
            json!([
                {"name":"id","type":"String","casdoorName":"Id","isKey":true},
                {"name":"userName","type":"String","casdoorName":"Name"},
                {"name":"properties","type":"String","casdoorName":"IsAdmin"}
            ]),
        ),
    ] {
        let mut invalid = f.body(&w, "Google Workspace", "invalid-google");
        invalid[field] = value;
        assert_eq!(
            f.request(false, "POST", "/api/syncers", Some(invalid))
                .await
                .status_code,
            Some(StatusCode::BAD_REQUEST),
            "invalid field {field}"
        );
    }
    assert_eq!(w.state.hits.load(Ordering::SeqCst), 0);
    f.approve(&id).await;
    f.json(
        false,
        "PUT",
        &format!("/api/syncers/{id}"),
        Some(json!({"user":"changed-client"})),
    )
    .await;
    let status = f
        .json(
            true,
            "GET",
            &format!("/api/syncers/{id}/network-approval"),
            None,
        )
        .await;
    assert_eq!(status["stale"], true);
    assert_eq!(status["allow_private"], false);
    assert_ne!(
        f.request(false, "POST", &format!("/api/syncers/{id}/run"), None)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    f.json(
        false,
        "PUT",
        &format!("/api/syncers/{id}"),
        Some(json!({"user":"azure-client"})),
    )
    .await;
    f.approve(&id).await;
    let one = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        SyncerExecutor::execute_syncer(&one, &id),
    )
    .await
    .expect("pool max1 must not deadlock")
    .unwrap();
    assert_eq!(result.records_synced, 2);
    one.close().await;
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated CASDOG_TEST_DATABASE_URL"]
async fn cloud_network_revocation_and_cross_pool_lease_abort_before_any_local_commit() {
    let f = Fixture::new().await;
    let w = Wire::new().await;
    let id = f.create(&w, "Azure AD", "revocation").await;
    f.approve(&id).await;
    w.state.mode.store(8, Ordering::SeqCst);
    let pool = f.pool.clone();
    let run_id = id.clone();
    let run = tokio::spawn(async move { SyncerExecutor::execute_syncer(&pool, &run_id).await });
    tokio::time::timeout(Duration::from_secs(10), w.state.entered.notified())
        .await
        .unwrap();
    let other = PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    assert!(SyncerExecutor::execute_syncer(&other, &id).await.is_err());
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        f.request(
            true,
            "DELETE",
            &format!("/api/syncers/{id}/network-approval"),
            None,
        ),
    )
    .await
    .expect("revocation must not block behind running Syncer row lock");
    assert_eq!(response.status_code, Some(StatusCode::OK));
    tokio::time::timeout(Duration::from_secs(3), f.approve(&id))
        .await
        .expect("same-config reapproval must not block on the running source transaction");
    w.state.release.notify_one();
    assert!(run.await.unwrap().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM syncer_user_links WHERE syncer_id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(w.state.hits.load(Ordering::SeqCst), 2);
    w.state.mode.store(0, Ordering::SeqCst);
    f.run(&id).await;
    assert_eq!(f.user("u1").await.external_id.as_deref(), Some("u1"));
    other.close().await;
    f.cleanup().await;
}
