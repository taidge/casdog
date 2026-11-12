//! Local HTTP SCIM service + real PostgreSQL, through normal Syncer CRUD/run.
use casdog::{config::AppConfig, diesel_pool::create_diesel_pool, models::User};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[derive(Default)]
struct SourceState {
    users: Vec<Value>,
    mode: String,
    requests: Vec<(String, String, String)>,
    expected: String,
    secret: String,
}
struct Source {
    host: String,
    state: Arc<Mutex<SourceState>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Source {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn person(id: &str, name: &str) -> Value {
    json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":id,"externalId":format!("employee-{id}"),"userName":name,"name":{"givenName":"Ada","familyName":"Lovelace","formatted":"Ada Formatted"},"emails":[{"value":"secondary@example.test"},{"value":"primary@example.test","primary":true}],"phoneNumbers":[{"value":"123"},{"value":"456","primary":true}],"active":true,"title":"Engineer","preferredLanguage":"zh-CN","addresses":[{"primary":true,"streetAddress":"Main St","locality":"City","region":"State","postalCode":"12345","country":"CN"}]})
}
impl Source {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = format!("http://{}/scim/v2", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(SourceState {
            users: vec![person("stable-a", "alice"), person("stable-b", "bob")],
            expected: "Bearer scim-secret".into(),
            secret: "scim-secret".into(),
            ..Default::default()
        }));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let shared = shared.clone();
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = socket.read(&mut buf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        data.extend_from_slice(&buf[..n]);
                        if data.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&data);
                    let mut line = head.lines().next().unwrap().split_whitespace();
                    let method = line.next().unwrap().to_owned();
                    let path = line.next().unwrap().to_owned();
                    let header = |name: &str| {
                        head.lines()
                            .find_map(|l| {
                                l.split_once(':')
                                    .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                                    .map(|(_, v)| v.trim().to_owned())
                            })
                            .unwrap_or_default()
                    };
                    let auth = header("authorization");
                    let accept = header("accept");
                    let url = reqwest::Url::parse(&format!("http://fixture{path}")).unwrap();
                    let start = url
                        .query_pairs()
                        .find(|(k, _)| k == "startIndex")
                        .unwrap()
                        .1
                        .parse::<usize>()
                        .unwrap();
                    let count = url
                        .query_pairs()
                        .find(|(k, _)| k == "count")
                        .unwrap()
                        .1
                        .to_string();
                    let (status, body, redirect) = {
                        let mut state = shared.lock().unwrap();
                        state.requests.push((method.clone(), auth.clone(), path));
                        assert_eq!(method, "GET");
                        assert_eq!(url.path(), "/scim/v2/Users");
                        assert_eq!(accept, "application/scim+json");
                        assert_eq!(count, "100");
                        if auth != state.expected {
                            (401, json!({"detail":state.secret}).to_string(), false)
                        } else if state.mode == "redirect" {
                            (302, String::new(), true)
                        } else if state.mode == "http" && start > 1 {
                            (503, json!({"detail":state.secret}).to_string(), false)
                        } else {
                            let resource = state
                                .users
                                .get(start - 1)
                                .cloned()
                                .into_iter()
                                .collect::<Vec<_>>();
                            let mut body = json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":state.users.len(),"startIndex":start,"itemsPerPage":resource.len(),"Resources":resource});
                            if start > 1 {
                                match state.mode.as_str() {
                                    "drift" => body["totalResults"] = json!(state.users.len() + 1),
                                    "backwards" => body["startIndex"] = json!(1),
                                    "truncated" => {
                                        body["Resources"] = json!([]);
                                        body["itemsPerPage"] = json!(0);
                                    }
                                    "duplicate" => {
                                        body["Resources"] = json!([state.users[0].clone()])
                                    }
                                    "missing-total" => {
                                        body.as_object_mut().unwrap().remove("totalResults");
                                    }
                                    "malformed" => body["Resources"][0]["active"] = json!("false"),
                                    _ => {}
                                }
                            }
                            (200, body.to_string(), false)
                        }
                    };
                    let location = if redirect {
                        "Location: http://127.0.0.1:1/stolen\r\n"
                    } else {
                        ""
                    };
                    let response = format!(
                        "HTTP/1.1 {status} Result\r\n{location}Content-Type: application/scim+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        Self { host, state, task }
    }
}
struct Fixture {
    pool: PgPool,
    app: Service,
    owner: String,
    foreign: String,
    admin: String,
    foreign_admin: String,
    source: Source,
}
impl Fixture {
    async fn new() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            AppConfig::load().unwrap();
        });
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&url)
            .await
            .unwrap();
        let owner = format!("scim-{}", uuid::Uuid::new_v4());
        let foreign = format!("scim-other-{}", uuid::Uuid::new_v4());
        let admin = uuid::Uuid::new_v4().to_string();
        let foreign_admin = uuid::Uuid::new_v4().to_string();
        for (org, id) in [(&owner, &admin), (&foreign, &foreign_admin)] {
            sqlx::query(
                "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(org)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,'admin','Admin','unused',true)").bind(id).bind(org).execute(&pool).await.unwrap();
        }
        let diesel = create_diesel_pool(&url).await.unwrap();
        let app = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        Self {
            pool,
            app,
            owner,
            foreign,
            admin,
            foreign_admin,
            source: Source::new().await,
        }
    }
    fn token(&self, foreign: bool) -> String {
        let now = chrono::Utc::now();
        let c = AppConfig::get();
        jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({"sub":if foreign{&self.foreign_admin}else{&self.admin},"owner":if foreign{&self.foreign}else{&self.owner},"name":"admin","is_admin":true,"iat":now.timestamp(),"exp":now.timestamp()+3600,"issued_at_ms":now.timestamp_millis(),"iss":c.jwt.issuer}),&jsonwebtoken::EncodingKey::from_secret(c.jwt.secret.as_bytes())).unwrap()
    }
    fn body(&self, name: &str, user: &str, password: &str) -> Value {
        json!({"owner":self.owner,"organization":self.owner,"name":name,"type":"SCIM","host":self.source.host,"port":443,"user":user,"password":password,"isReadOnly":true,"isEnabled":true,"syncInterval":60})
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        foreign: bool,
    ) -> Response {
        let request = match method {
            "GET" => TestClient::get(format!("http://localhost{path}")),
            "PUT" => TestClient::put(format!("http://localhost{path}")),
            _ => TestClient::post(format!("http://localhost{path}")),
        }
        .add_header(
            "Authorization",
            format!("Bearer {}", self.token(foreign)),
            true,
        );
        if let Some(body) = body {
            request.json(&body).send(&self.app).await
        } else {
            request.send(&self.app).await
        }
    }
    async fn json(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let mut response = self.request(method, path, body, false).await;
        let status = response.status_code;
        let body = response.take_string().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
        serde_json::from_str(&body).unwrap()
    }
    async fn create(&self) -> String {
        self.json(
            "POST",
            "/api/syncers",
            Some(self.body("directory", "", "scim-secret")),
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
    async fn account(&self, name: &str) -> User {
        sqlx::query_as("SELECT * FROM users WHERE owner=$1 AND name=$2")
            .bind(&self.owner)
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn cleanup(&self) {
        for sql in [
            "DELETE FROM syncer_operations WHERE organization=$1 OR organization=$2",
            "DELETE FROM syncers WHERE owner=$1 OR owner=$2",
            "DELETE FROM users WHERE owner=$1 OR owner=$2",
            "DELETE FROM organizations WHERE name=$1 OR name=$2",
        ] {
            sqlx::query(sql)
                .bind(&self.owner)
                .bind(&self.foreign)
                .execute(&self.pool)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires migrations001-042 and CASDOG_TEST_DATABASE_URL"]
async fn scim_normal_api_imports_all_pages_profiles_and_stable_rename_without_writeback() {
    let f = Fixture::new().await;
    {
        let mut state = f.source.state.lock().unwrap();
        state.users[1]["active"] = json!(false);
    }
    let id = f.create().await;
    f.run(&id).await;
    let alice = f.account("alice").await;
    let bob = f.account("bob").await;
    assert!(!alice.is_forbidden);
    assert!(bob.is_forbidden);
    assert_eq!(alice.display_name, "Ada Formatted");
    assert_eq!(alice.email.as_deref(), Some("primary@example.test"));
    assert_eq!(alice.phone.as_deref(), Some("456"));
    assert_eq!(alice.first_name.as_deref(), Some("Ada"));
    assert_eq!(alice.last_name.as_deref(), Some("Lovelace"));
    assert_eq!(alice.title.as_deref(), Some("Engineer"));
    assert_eq!(alice.language.as_deref(), Some("zh-CN"));
    assert_eq!(alice.location.as_deref(), Some("City"));
    assert_eq!(alice.region.as_deref(), Some("State"));
    assert_eq!(
        alice.address,
        Some(json!(["Main St", "City", "State", "12345", "CN"]))
    );
    // An omitted administrative status is not an instruction to re-enable a
    // previously disabled account; an explicit active=true below is required.
    f.source.state.lock().unwrap().users[1]
        .as_object_mut()
        .unwrap()
        .remove("active");
    f.run(&id).await;
    assert!(f.account("bob").await.is_forbidden);
    let response = f
        .json("GET", &format!("/api/users/{}", alice.id), None)
        .await;
    assert_eq!(response["title"], "Engineer");
    assert_eq!(response["language"], "zh-CN");
    assert_eq!(response["location"], "City");
    assert_eq!(response["region"], "State");
    assert_eq!(
        response["address"],
        json!(["Main St", "City", "State", "12345", "CN"])
    );
    {
        let mut state = f.source.state.lock().unwrap();
        assert_eq!(state.requests.len(), 4);
        state.users[0]["userName"] = json!("alice-renamed");
        state.users[0]["displayName"] = json!("Updated Alice");
        state.users[0]["addresses"] = json!([]);
        state.users[1]["active"] = json!(true);
    }
    f.run(&id).await;
    let renamed = f.account("alice-renamed").await;
    assert_eq!(renamed.id, alice.id);
    assert_eq!(renamed.address, Some(json!([])));
    assert_eq!(f.account("bob").await.id, bob.id);
    assert!(!f.account("bob").await.is_forbidden);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM syncer_user_links WHERE syncer_id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM syncer_operations WHERE syncer_id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    assert!(
        f.source
            .state
            .lock()
            .unwrap()
            .requests
            .iter()
            .all(|(method, _, _)| method == "GET")
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrations001-042 and CASDOG_TEST_DATABASE_URL"]
async fn incomplete_scim_snapshots_never_partially_update_or_disable_missing_users_and_recover() {
    let f = Fixture::new().await;
    let id = f.create().await;
    f.run(&id).await;
    let alice = f.account("alice").await;
    let bob = f.account("bob").await;
    {
        let mut state = f.source.state.lock().unwrap();
        state.users = vec![person("stable-a", "alice"), person("stable-c", "carol")];
        state.users[0]["displayName"] = json!("Must Roll Back");
        state.users[0]["active"] = json!(false);
    }
    for mode in [
        "http",
        "drift",
        "backwards",
        "truncated",
        "duplicate",
        "missing-total",
        "malformed",
        "redirect",
    ] {
        f.source.state.lock().unwrap().mode = mode.into();
        let mut response = f
            .request("POST", &format!("/api/syncers/{id}/run"), None, false)
            .await;
        assert_ne!(response.status_code, Some(StatusCode::OK), "{mode}");
        let error = response.take_string().await.unwrap();
        assert!(!error.contains("scim-secret"));
        let actual = f.account("alice").await;
        assert_eq!(actual.display_name, alice.display_name, "{mode}");
        assert!(!actual.is_forbidden);
        assert!(!f.account("bob").await.is_forbidden);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM users WHERE owner=$1 AND name='carol'"
            )
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            0
        );
        let stored: Option<String> =
            sqlx::query_scalar("SELECT error_text FROM syncers WHERE id=$1")
                .bind(&id)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert!(!stored.unwrap_or_default().contains("scim-secret"));
    }
    {
        let mut state = f.source.state.lock().unwrap();
        state.mode.clear();
        state.users = vec![person("stable-a", "alice")];
    }
    f.run(&id).await;
    assert!(f.account("bob").await.is_forbidden);
    f.source
        .state
        .lock()
        .unwrap()
        .users
        .push(person("stable-b", "bob"));
    f.run(&id).await;
    assert_eq!(f.account("bob").await.id, bob.id);
    assert!(!f.account("bob").await.is_forbidden);
    f.source.state.lock().unwrap().users.clear();
    f.run(&id).await;
    assert!(f.account("alice").await.is_forbidden);
    assert!(f.account("bob").await.is_forbidden);
    {
        let mut state = f.source.state.lock().unwrap();
        state.users = vec![person("stable-a", "alice"), person("stable-b", "bob")];
    }
    f.run(&id).await;
    assert_eq!(f.account("alice").await.id, alice.id);
    assert_eq!(f.account("bob").await.id, bob.id);
    assert!(!f.account("alice").await.is_forbidden);
    assert!(!f.account("bob").await.is_forbidden);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrations001-042 and CASDOG_TEST_DATABASE_URL"]
async fn scim_auth_modes_mask_long_bearer_tokens_and_preserve_redacted_updates() {
    use base64::Engine;
    let f = Fixture::new().await;
    let long = format!("jwt.{}.signature", "x".repeat(2048));
    for (name, user, password, expected) in [
        (
            "password-token",
            "",
            long.as_str(),
            format!("Bearer {long}"),
        ),
        ("user-token", long.as_str(), "", format!("Bearer {long}")),
        (
            "basic",
            "scim-reader",
            long.as_str(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("scim-reader:{long}"))
            ),
        ),
    ] {
        {
            let mut state = f.source.state.lock().unwrap();
            state.expected = expected;
            state.secret = long.clone();
            state.requests.clear();
        }
        let created = f
            .json("POST", "/api/syncers", Some(f.body(name, user, password)))
            .await;
        let id = created["id"].as_str().unwrap();
        assert!(!created.to_string().contains(&long));
        assert_eq!(
            created["user"],
            if name == "user-token" { "***" } else { user }
        );
        assert_eq!(
            created["password"],
            if password.is_empty() { "" } else { "***" }
        );
        let fetched = f.json("GET", &format!("/api/syncers/{id}"), None).await;
        assert!(!fetched.to_string().contains(&long));
        let updated = f
            .json(
                "PUT",
                &format!("/api/syncers/{id}"),
                Some(json!({"user":fetched["user"],"password":"***","isReadOnly":true})),
            )
            .await;
        assert!(!updated.to_string().contains(&long));
        let stored: (String, String) =
            sqlx::query_as("SELECT \"user\",password FROM syncers WHERE id=$1")
                .bind(id)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(stored, (user.into(), password.into()));
        // Keep one authoritative syncer per identity namespace in this fixture.
        f.run(id).await;
        assert!(
            f.source
                .state
                .lock()
                .unwrap()
                .requests
                .iter()
                .all(|(method, auth, _)| method == "GET" && !auth.is_empty())
        );
        sqlx::query("DELETE FROM syncers WHERE id=$1")
            .bind(id)
            .execute(&f.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE owner=$1 AND name<>'admin'")
            .bind(&f.owner)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrations001-042 and CASDOG_TEST_DATABASE_URL"]
async fn scim_rejects_cross_tenant_and_non_readonly_or_unsafe_configuration_via_normal_api() {
    let f = Fixture::new().await;
    let id = f.create().await;
    for path in [
        format!("/api/syncers/{id}/run"),
        format!("/api/run-syncer?id={}/directory", f.owner),
    ] {
        assert_eq!(
            f.request("POST", &path, None, true).await.status_code,
            Some(StatusCode::FORBIDDEN)
        );
    }
    assert_eq!(
        f.request("GET", &format!("/api/syncers/{id}"), None, true)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    for (field, value) in [
        ("isReadOnly", json!(false)),
        ("host", json!("http://example.com/scim")),
        ("host", json!("https://reader:secret@example.com/scim")),
        ("host", json!("https://example.com/scim?token=secret")),
        ("password", json!("***")),
        ("password", json!("x".repeat(16385))),
    ] {
        let mut body = f.body(
            &format!("invalid-{}", uuid::Uuid::new_v4()),
            "",
            "scim-secret",
        );
        body[field] = value;
        let res = f.request("POST", "/api/syncers", Some(body), false).await;
        assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST), "{field}");
    }
    let mut body = f.body("unstable-key", "", "scim-secret");
    body["tableColumns"] =
        json!([{"name":"userName","type":"String","casdoorName":"Name","isKey":true}]);
    assert_eq!(
        f.request("POST", "/api/syncers", Some(body), false)
            .await
            .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    let mut body = f.body("password-map", "", "scim-secret");
    body["tableColumns"] = json!([{"name":"id","type":"String","casdoorName":"Id","isKey":true},{"name":"userName","type":"String","casdoorName":"Name"},{"name":"password","type":"String","casdoorName":"Password"}]);
    assert_eq!(
        f.request("POST", "/api/syncers", Some(body), false)
            .await
            .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM syncers WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    assert!(f.source.state.lock().unwrap().requests.is_empty());
    f.cleanup().await;
}
