use casdog::{
    config::AppConfig,
    diesel_pool::{DieselPool, create_diesel_pool},
    hoops::authz::Principal,
    models::{Application, User, UserResponse},
    services::{
        AuthService, UserService, auth_service::Claims, protocol_gap_service as service,
        social_state_service::proof_hash,
    },
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct Fixture {
    pool: PgPool,
    other: PgPool,
    diesel: DieselPool,
    owner: String,
    app: Application,
    principal: Principal,
    claims: Claims,
    bearer: String,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url =
            std::env::var("CASDOG_TEST_DATABASE_URL").expect("CASDOG_TEST_DATABASE_URL required");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let other = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let owner = format!("device-{}", uuid::Uuid::new_v4().simple());
        let user = uuid::Uuid::new_v4().to_string();
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,password_hash,display_name,is_admin) VALUES($1,$2,'alice','unused','Alice',true)").bind(&user).bind(&owner).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,grant_types) VALUES($1,$2,'portal','Portal',$2,$1,'client-secret','https://example.test/callback',$3)")
            .bind(&id).bind(&owner).bind(json!([service::DEVICE_GRANT,"refresh_token"])).execute(&pool).await.unwrap();
        let app: Application = sqlx::query_as("SELECT * FROM applications WHERE id=$1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let account: User = sqlx::query_as("SELECT * FROM users WHERE id=$1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap();
        let auth = AuthService::new(UserService::new(diesel.clone()));
        let claims = auth.claims_for_user(&UserResponse::from(account));
        let bearer = auth.generate_token_from_claims(&claims).unwrap();
        let principal = Principal {
            application_identity: false,
            id: user,
            owner: owner.clone(),
            name: "alice".into(),
            admin: true,
        };
        Self {
            pool,
            other,
            diesel,
            owner,
            app,
            principal,
            claims,
            bearer,
        }
    }
    async fn begin(&self) -> Value {
        service::begin_device(&self.pool, &self.app, "profile", "http://localhost:8000")
            .await
            .unwrap()
    }
    async fn approve(&self, proof: &Value) {
        service::authorize_device(
            &self.pool,
            &self.principal,
            proof["user_code"].as_str().unwrap(),
            true,
            &self.claims,
            &self.bearer,
        )
        .await
        .unwrap();
    }
    async fn cleanup(self) {
        sqlx::query("DELETE FROM device_authorizations WHERE organization=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM tokens WHERE organization=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM revoked_session_tokens WHERE token_hash=$1")
            .bind(casdog::hoops::auth::session_fingerprint(&self.bearer))
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM user_session_epochs WHERE user_id=$1")
            .bind(&self.principal.id)
            .execute(&self.pool)
            .await
            .unwrap();
        for table in [
            "resources",
            "providers",
            "casdoor_objects",
            "applications",
            "users",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1"))
                .bind(&self.owner)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM organizations WHERE name=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
    }
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn device_pending_poll_throttle_cancel_and_expiry_are_durable() {
    let f = Fixture::new().await;
    let proof = f.begin().await;
    let device = proof["device_code"].as_str().unwrap();
    assert_eq!(
        service::poll_device(&f.other, &f.diesel, &f.app, device)
            .await
            .unwrap()["error"],
        "authorization_pending"
    );
    assert_eq!(
        service::poll_device(&f.pool, &f.diesel, &f.app, device)
            .await
            .unwrap()["error"],
        "slow_down"
    );
    let saved: (String,String,i32)=sqlx::query_as("SELECT device_hash,cancel_hash,poll_interval FROM device_authorizations WHERE user_code=$1").bind(proof["user_code"].as_str().unwrap()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(saved.0, proof_hash(device));
    assert_ne!(saved.1, proof["cancel_token"].as_str().unwrap());
    assert_eq!(saved.2, 10);
    assert!(
        service::cancel_device(&f.pool, proof["user_code"].as_str().unwrap(), "wrong")
            .await
            .is_err()
    );
    service::cancel_device(
        &f.other,
        proof["user_code"].as_str().unwrap(),
        proof["cancel_token"].as_str().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        service::poll_device(&f.pool, &f.diesel, &f.app, device)
            .await
            .unwrap()["error"],
        "access_denied"
    );
    let denied = f.begin().await;
    service::authorize_device(
        &f.pool,
        &f.principal,
        denied["user_code"].as_str().unwrap(),
        false,
        &f.claims,
        &f.bearer,
    )
    .await
    .unwrap();
    assert_eq!(
        service::poll_device(
            &f.other,
            &f.diesel,
            &f.app,
            denied["device_code"].as_str().unwrap()
        )
        .await
        .unwrap()["error"],
        "access_denied"
    );
    let expired = f.begin().await;
    sqlx::query("UPDATE device_authorizations SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE device_hash=$1").bind(proof_hash(expired["device_code"].as_str().unwrap())).execute(&f.pool).await.unwrap();
    assert_eq!(
        service::poll_device(
            &f.pool,
            &f.diesel,
            &f.app,
            expired["device_code"].as_str().unwrap()
        )
        .await
        .unwrap()["error"],
        "expired_token"
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn device_cross_instance_grant_and_browser_completion_are_consumed_once() {
    let f = Fixture::new().await;
    let proof = f.begin().await;
    f.approve(&proof).await;
    let code = proof["device_code"].as_str().unwrap();
    let (a, b) = tokio::join!(
        service::poll_device(&f.pool, &f.diesel, &f.app, code),
        service::poll_device(&f.other, &f.diesel, &f.app, code)
    );
    let replies = [a.unwrap(), b.unwrap()];
    let tokens: Vec<_> = replies
        .iter()
        .filter(|v| v.get("access_token").is_some())
        .collect();
    assert_eq!(tokens.len(), 1);
    assert_eq!(
        replies
            .iter()
            .filter(|v| v["error"] == "invalid_grant")
            .count(),
        1
    );
    let jwt = tokens[0]["access_token"].as_str().unwrap();
    let auth = AuthService::new(UserService::new(f.diesel.clone()));
    assert_eq!(auth.verify_token(jwt).unwrap().sub, f.principal.id);
    let completed = service::complete_device(&f.other, code).await.unwrap();
    assert_eq!(completed["token"], jwt);
    assert_eq!(completed["user"]["owner"], f.owner);
    assert!(service::complete_device(&f.pool, code).await.is_err());
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn device_approval_enforces_tenant_client_and_enabled_grant() {
    let f = Fixture::new().await;
    let proof = f.begin().await;
    let foreign = Principal {
        application_identity: false,
        owner: "another-tenant".into(),
        ..f.principal.clone()
    };
    assert!(
        service::verify_device(&f.pool, &foreign, proof["user_code"].as_str().unwrap())
            .await
            .is_err()
    );
    let mut app = f.app.clone();
    app.id = uuid::Uuid::new_v4().to_string();
    assert!(
        service::poll_device(
            &f.pool,
            &f.diesel,
            &app,
            proof["device_code"].as_str().unwrap()
        )
        .await
        .is_err()
    );
    app = f.app.clone();
    app.grant_types = Some(json!(["authorization_code"]));
    assert!(
        service::begin_device(&f.pool, &app, "profile", "http://localhost")
            .await
            .is_err()
    );
    f.approve(&proof).await;
    sqlx::query("UPDATE applications SET grant_types='[]'::jsonb WHERE id=$1")
        .bind(&f.app.id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        service::poll_device(
            &f.other,
            &f.diesel,
            &f.app,
            proof["device_code"].as_str().unwrap()
        )
        .await
        .is_err()
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn device_approval_rechecks_selective_revocation_global_logout_and_password_changes() {
    let f = Fixture::new().await;
    let proof = f.begin().await;
    f.approve(&proof).await;
    sqlx::query("INSERT INTO revoked_session_tokens(token_hash,user_id,expires_at) VALUES($1,$2,clock_timestamp()+INTERVAL '1 hour')").bind(casdog::hoops::auth::session_fingerprint(&f.bearer)).bind(&f.principal.id).execute(&f.pool).await.unwrap();
    assert!(
        service::poll_device(
            &f.other,
            &f.diesel,
            &f.app,
            proof["device_code"].as_str().unwrap()
        )
        .await
        .is_err()
    );
    let other = f.begin().await;
    assert!(
        service::authorize_device(
            &f.pool,
            &f.principal,
            other["user_code"].as_str().unwrap(),
            true,
            &f.claims,
            &f.bearer
        )
        .await
        .is_err()
    );
    sqlx::query("DELETE FROM revoked_session_tokens WHERE token_hash=$1")
        .bind(casdog::hoops::auth::session_fingerprint(&f.bearer))
        .execute(&f.pool)
        .await
        .unwrap();
    let proof = f.begin().await;
    f.approve(&proof).await;
    sqlx::query(
        "INSERT INTO user_session_epochs(user_id,invalid_before) VALUES($1,clock_timestamp())",
    )
    .bind(&f.principal.id)
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(
        service::poll_device(
            &f.other,
            &f.diesel,
            &f.app,
            proof["device_code"].as_str().unwrap()
        )
        .await
        .is_err()
    );
    sqlx::query("DELETE FROM user_session_epochs WHERE user_id=$1")
        .bind(&f.principal.id)
        .execute(&f.pool)
        .await
        .unwrap();
    let proof = f.begin().await;
    f.approve(&proof).await;
    sqlx::query("UPDATE users SET last_change_password_time=to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') WHERE id=$1").bind(&f.principal.id).execute(&f.pool).await.unwrap();
    assert!(
        service::poll_device(
            &f.other,
            &f.diesel,
            &f.app,
            proof["device_code"].as_str().unwrap()
        )
        .await
        .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn transcript_reads_real_storage_bounds_preview_and_rejects_tenant_or_path_escape() {
    use md5::{Digest, Md5};
    let f = Fixture::new().await;
    let path = service::local_storage_root(&f.principal, &f.owner, None, true)
        .await
        .unwrap();
    tokio::fs::create_dir_all(&path).await.unwrap();
    let bytes = vec![b'x'; 2 * 1024 * 1024 + 100];
    tokio::fs::write(path.join("raw.jsonl"), &bytes)
        .await
        .unwrap();
    sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,bucket) VALUES($1,$2,'storage','Storage','Storage','Local',$3)").bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(path.to_str().unwrap()).execute(&f.pool).await.unwrap();
    let entry = json!({"owner":f.owner,"name":"anchor","type":"session","provider":"log","message":json!({"sessionId":"session-one","entryId":"entry-one","kind":"task"}).to_string()});
    sqlx::query(
        "INSERT INTO casdoor_objects(kind,owner,name,document) VALUES('entry',$1,'anchor',$2)",
    )
    .bind(&f.owner)
    .bind(entry)
    .execute(&f.pool)
    .await
    .unwrap();
    let parent = format!(
        "openclaw/{}",
        hex::encode(Md5::digest(format!("{}|log|session-one", f.owner)))
    );
    sqlx::query("INSERT INTO resources(id,owner,name,user_id,provider,tag,parent,file_name,file_type,file_size,url) VALUES($1,$2,'raw.jsonl','alice','storage','openclawTranscript',$3,'session.jsonl','application/jsonl',$4,'')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(parent).bind(bytes.len() as i64).execute(&f.pool).await.unwrap();
    let result = service::transcript(&f.pool, &f.principal, &f.owner, "anchor")
        .await
        .unwrap();
    assert_eq!(result["fileSize"], bytes.len());
    assert_eq!(result["loadedSize"], 2 * 1024 * 1024);
    assert_eq!(result["truncated"], true);
    let foreign = Principal {
        application_identity: false,
        owner: "foreign".into(),
        ..f.principal.clone()
    };
    assert!(
        service::transcript(&f.pool, &foreign, &f.owner, "anchor")
            .await
            .is_err()
    );
    sqlx::query("UPDATE resources SET name='../outside.jsonl' WHERE owner=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        service::transcript(&f.pool, &f.principal, &f.owner, "anchor")
            .await
            .is_err()
    );
    tokio::fs::remove_file(path.join("raw.jsonl"))
        .await
        .unwrap();
    tokio::fs::remove_dir(path).await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn mcp_sync_negotiates_http_session_sse_pagination_and_preserves_denials() {
    let f = Fixture::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::<(String, Value)>::new()));
    let captured = requests.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let captured = captured.clone();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let (offset, length) = loop {
                    let count = socket.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        let len = header
                            .lines()
                            .find_map(|line| {
                                let (k, v) = line.split_once(':')?;
                                k.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (end + 4, len);
                    }
                };
                while bytes.len() < offset + length {
                    let count = socket.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                }
                let header = String::from_utf8_lossy(&bytes[..offset]).to_lowercase();
                let body: Value = serde_json::from_slice(&bytes[offset..offset + length]).unwrap();
                captured.lock().unwrap().push((header, body.clone()));
                let (status,kind,extra,body)=match body["method"].as_str().unwrap() {
                    "initialize" => ("200 OK","application/json","Mcp-Session-Id: test-session\r\n",json!({"jsonrpc":"2.0","id":body["id"],"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}}}}).to_string()),
                    "notifications/initialized" => ("202 Accepted","application/json","",String::new()),
                    _ => {let second=body["params"]["cursor"]=="next";let result=if second {json!({"tools":[{"name":"write","inputSchema":{"type":"object"}}]})} else {json!({"tools":[{"name":"read","inputSchema":{"type":"object"}}],"nextCursor":"next"})};("200 OK","text/event-stream","",format!("data: {}\n\n",json!({"jsonrpc":"2.0","id":body["id"],"result":result}))) }
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });
    let document = json!({"owner":f.owner,"name":"mcp","url":url,"token":"mcp-secret","tools":[{"name":"read","isAllowed":false}]});
    sqlx::query(
        "INSERT INTO casdoor_objects(kind,owner,name,document) VALUES('server',$1,'mcp',$2)",
    )
    .bind(&f.owner)
    .bind(document)
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(
        service::sync_mcp(&f.pool, &f.principal, &f.owner, "mcp", false)
            .await
            .is_err()
    );
    assert!(requests.lock().unwrap().is_empty());
    let global = Principal {
        application_identity: false,
        owner: "built-in".into(),
        ..f.principal.clone()
    };
    service::sync_mcp(&f.pool, &global, &f.owner, "mcp", false)
        .await
        .unwrap();
    let saved: Value = sqlx::query_scalar(
        "SELECT document FROM casdoor_objects WHERE kind='server' AND owner=$1 AND name='mcp'",
    )
    .bind(&f.owner)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(saved["tools"].as_array().unwrap().len(), 2);
    assert_eq!(saved["tools"][0]["isAllowed"], false);
    assert_eq!(saved["tools"][1]["isAllowed"], true);
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        for (header, body) in requests.iter() {
            assert!(header.contains("authorization: bearer mcp-secret"));
            if body["method"] != "initialize" {
                assert!(header.contains("mcp-session-id: test-session"));
                assert!(header.contains("mcp-protocol-version: 2025-06-18"));
            }
        }
    }
    server.abort();
    let _ = server.await;
    assert!(
        service::sync_mcp(&f.pool, &global, &f.owner, "mcp", false)
            .await
            .is_err()
    );
    let unchanged: Value = sqlx::query_scalar(
        "SELECT document FROM casdoor_objects WHERE kind='server' AND owner=$1 AND name='mcp'",
    )
    .bind(&f.owner)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(unchanged, saved);
    let foreign = Principal {
        application_identity: false,
        owner: "foreign".into(),
        ..f.principal.clone()
    };
    assert!(
        service::sync_mcp(&f.pool, &foreign, &f.owner, "mcp", true)
            .await
            .is_err()
    );
    service::sync_mcp(&f.other, &f.principal, &f.owner, "mcp", true)
        .await
        .unwrap();
    let saved: Value = sqlx::query_scalar(
        "SELECT document FROM casdoor_objects WHERE kind='server' AND owner=$1 AND name='mcp'",
    )
    .bind(&f.owner)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(saved["tools"], json!([]));
    assert_eq!(saved["token"], "mcp-secret");
    f.cleanup().await;
}

#[salvo::handler]
async fn fixture_identity(depot: &mut salvo::Depot) {
    let principal = depot.obtain::<Principal>().unwrap().clone();
    depot.insert("user_id", principal.id);
    depot.insert("user_owner", principal.owner);
    depot.insert("user_name", principal.name);
    depot.insert("is_admin", principal.admin);
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn transcript_http_upload_and_preview_use_provider_entry_and_resource_apis() {
    use salvo::{
        prelude::*,
        test::{ResponseExt, TestClient},
    };
    let f = Fixture::new().await;
    let path = service::local_storage_root(&f.principal, &f.owner, None, true)
        .await
        .unwrap();
    tokio::fs::create_dir_all(&path).await.unwrap();
    let router = Router::with_path("api")
        .hoop(
            salvo::affix_state::AffixList::new()
                .inject(f.pool.clone())
                .inject(f.principal.clone()),
        )
        .hoop(fixture_identity)
        .push(Router::with_path("providers").post(casdog::handlers::provider::create_provider))
        .push(Router::with_path("add-entry").post(casdog::handlers::parity_resources::add_entry))
        .push(Router::with_path("upload-resource").post(casdog::handlers::upload::upload_resource))
        .push(
            Router::with_path("get-openclaw-session-transcript")
                .get(casdog::handlers::protocol_gaps::get_openclaw_session_transcript),
        )
        .push(Router::with_path("resources").get(casdog::handlers::resource::list_resources));
    let service = Service::new(router);
    for (name, category, kind) in [("storage", "Storage", "Local"), ("log", "Log", "OpenClaw")] {
        let mut response=TestClient::post("http://localhost/api/providers").json(&json!({"owner":f.owner,"name":name,"display_name":name,"category":category,"type":kind,"bucket":path.to_str().unwrap()})).send(&service).await;
        let status = response.status_code;
        let result = response.take_string().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{result}");
    }
    let entry = json!({"owner":f.owner,"name":"uploaded-session","type":"session","provider":"log","message":json!({"sessionId":"http-session","entryId":"root","kind":"task"}).to_string()});
    let mut response = TestClient::post("http://localhost/api/add-entry")
        .json(&entry)
        .send(&service)
        .await;
    let status = response.status_code;
    let result = response.take_string().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{result}");
    let content = "{\"type\":\"message\",\"message\":\"hello\"}\n";
    let boundary = "casdog-boundary";
    let mut body = String::new();
    for (key, value) in [
        ("owner", f.owner.clone()),
        ("tag", "openclawTranscript".into()),
        ("provider", "storage".into()),
        ("entryId", format!("{}/uploaded-session", f.owner)),
    ] {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"session.jsonl\"\r\nContent-Type: application/jsonl\r\n\r\n{content}\r\n--{boundary}--\r\n"));
    let ordinary = Service::new(
        Router::with_path("api/upload-resource")
            .hoop(
                salvo::affix_state::AffixList::new()
                    .inject(f.pool.clone())
                    .inject(Principal {
                        application_identity: false,
                        admin: false,
                        ..f.principal.clone()
                    }),
            )
            .hoop(fixture_identity)
            .post(casdog::handlers::upload::upload_resource),
    );
    let response = TestClient::post("http://localhost/api/upload-resource")
        .add_header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
            true,
        )
        .body(body.clone())
        .send(&ordinary)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let response = TestClient::post("http://localhost/api/upload-resource")
        .add_header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
            true,
        )
        .body(body.replace("\r\nstorage\r\n", "\r\nforeign/storage\r\n"))
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM resources WHERE owner=$1")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let mut response = TestClient::post("http://localhost/api/upload-resource")
        .add_header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
            true,
        )
        .body(body.clone())
        .send(&service)
        .await;
    let status = response.status_code;
    let uploaded: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{uploaded}");
    assert_eq!(uploaded["name"], "session.jsonl");
    let mut response = TestClient::get(format!(
        "http://localhost/api/get-openclaw-session-transcript?id={}/uploaded-session",
        f.owner
    ))
    .send(&service)
    .await;
    let preview: Value = response.take_json().await.unwrap();
    assert_eq!(preview["data"]["content"], content);
    assert_eq!(preview["data"]["truncated"], false);
    let mut response = TestClient::get(format!("http://localhost/api/resources?owner={}", f.owner))
        .send(&service)
        .await;
    let listed: Value = response.take_json().await.unwrap();
    assert_eq!(listed["total"], 1);
    assert_eq!(listed["data"][0]["user"], f.principal.id);
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let original: String = sqlx::query_scalar(
        "SELECT name FROM resources WHERE owner=$1 AND tag='openclawTranscript'",
    )
    .bind(&f.owner)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE providers SET bucket=$2 WHERE owner=$1 AND name='storage'")
        .bind(&f.owner)
        .bind(repo.to_str().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE resources SET name='Cargo.toml' WHERE owner=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut attack = TestClient::get(format!(
        "http://localhost/api/get-openclaw-session-transcript?id={}/uploaded-session",
        f.owner
    ))
    .send(&service)
    .await;
    assert_eq!(attack.status_code, Some(StatusCode::FORBIDDEN));
    assert!(!attack.take_string().await.unwrap().contains("[workspace]"));
    let response = TestClient::post("http://localhost/api/upload-resource")
        .add_header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
            true,
        )
        .body(body.clone())
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    sqlx::query("UPDATE providers SET bucket=$2 WHERE owner=$1 AND name='storage'")
        .bind(&f.owner)
        .bind(path.to_str().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE resources SET name=$2 WHERE owner=$1")
        .bind(&f.owner)
        .bind(original)
        .execute(&f.pool)
        .await
        .unwrap();
    let object: String = sqlx::query_scalar(
        "SELECT name FROM resources WHERE owner=$1 AND tag='openclawTranscript'",
    )
    .bind(&f.owner)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    let object_path = path.join(object);
    let directory = object_path.parent().unwrap().to_path_buf();
    assert!(
        tokio::fs::canonicalize(&object_path)
            .await
            .unwrap()
            .starts_with(tokio::fs::canonicalize(&path).await.unwrap())
    );
    tokio::fs::remove_file(object_path).await.unwrap();
    tokio::fs::remove_dir(directory).await.unwrap();
    tokio::fs::remove_dir(path.join("openclaw")).await.unwrap();
    tokio::fs::remove_dir(path).await.unwrap();
    f.cleanup().await;
}

fn file_service(pool: PgPool, principal: Principal) -> salvo::Service {
    use salvo::prelude::*;
    Service::new(
        Router::with_path("api")
            .hoop(
                salvo::affix_state::AffixList::new()
                    .inject(pool)
                    .inject(principal),
            )
            .hoop(fixture_identity)
            .push(
                Router::with_path("upload-resource")
                    .post(casdog::handlers::upload::upload_resource),
            )
            .push(
                Router::with_path("download-resource/{id}")
                    .get(casdog::handlers::upload::download_resource),
            )
            .push(
                Router::with_path("delete-resource/{id}")
                    .post(casdog::handlers::upload::delete_resource_with_file),
            ),
    )
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn ordinary_upload_download_delete_preserves_legacy_references_and_denies_other_tenants() {
    use salvo::{
        prelude::*,
        test::{ResponseExt, TestClient},
    };
    let f = Fixture::new().await;
    let path = service::local_storage_root(&f.principal, &f.owner, None, true)
        .await
        .unwrap();
    let bucket = path.join("bucket");
    tokio::fs::create_dir_all(&bucket).await.unwrap();
    let outside = path.join("outside.txt");
    tokio::fs::write(&outside, b"outside private data")
        .await
        .unwrap();
    sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,bucket) VALUES($1,$2,'storage','Storage','Storage','Local',$3)").bind(uuid::Uuid::new_v4().to_string()).bind(&f.owner).bind(bucket.to_str().unwrap()).execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE users SET is_admin=false WHERE id=$1")
        .bind(&f.principal.id)
        .execute(&f.pool)
        .await
        .unwrap();
    let principal = Principal {
        application_identity: false,
        admin: false,
        ..f.principal.clone()
    };
    let own = file_service(f.pool.clone(), principal.clone());
    let foreign = file_service(
        f.pool.clone(),
        Principal {
            application_identity: false,
            id: uuid::Uuid::new_v4().to_string(),
            owner: "foreign".into(),
            name: "alice".into(),
            admin: false,
        },
    );
    let boundary = "casdog-file-boundary";
    let content = "original file bytes";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"provider\"\r\n\r\nstorage\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\n{content}\r\n--{boundary}--\r\n"
    );
    let mut response = TestClient::post("http://localhost/api/upload-resource")
        .add_header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
            true,
        )
        .body(body.clone())
        .send(&own)
        .await;
    let status = response.status_code;
    let uploaded: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{uploaded}");
    assert_eq!(uploaded["name"], "notes.txt");
    let (id, object): (String, String) =
        sqlx::query_as("SELECT id,name FROM resources WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_ne!(object, "notes.txt");
    let object_path = bucket.join(&object);
    assert!(object_path.exists());
    let download = format!("http://localhost/api/download-resource/{id}");
    let delete = format!("http://localhost/api/delete-resource/{id}");
    let mut response = TestClient::get(&download).send(&own).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(response.take_string().await.unwrap(), content);
    assert_eq!(
        TestClient::get(&download).send(&foreign).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        TestClient::post(&delete).send(&foreign).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert!(object_path.exists());
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    sqlx::query("UPDATE providers SET bucket=$2 WHERE owner=$1 AND name='storage'")
        .bind(&f.owner)
        .bind(repo.to_str().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE resources SET name='Cargo.toml' WHERE id=$1")
        .bind(&id)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut attacked = TestClient::get(&download).send(&own).await;
    assert_eq!(attacked.status_code, Some(StatusCode::FORBIDDEN));
    assert!(
        !attacked
            .take_string()
            .await
            .unwrap()
            .contains("[workspace]")
    );
    assert_eq!(
        TestClient::post(&delete).send(&own).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    sqlx::query("UPDATE providers SET bucket=$2 WHERE owner=$1 AND name='storage'")
        .bind(&f.owner)
        .bind(bucket.to_str().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE resources SET name=$2 WHERE id=$1")
        .bind(&id)
        .bind(&object)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE resources SET provider='foreign/storage' WHERE id=$1")
        .bind(&id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        TestClient::get(&download).send(&own).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        TestClient::post(&delete).send(&own).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    sqlx::query("UPDATE resources SET provider='storage',name=file_name WHERE id=$1")
        .bind(&id)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut response = TestClient::get(&download).send(&own).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(response.take_string().await.unwrap(), content);
    sqlx::query("UPDATE resources SET url=$2 WHERE id=$1")
        .bind(&id)
        .bind(format!("file://{}", outside.display()))
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        TestClient::get(&download).send(&own).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        TestClient::post(&delete).send(&own).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        tokio::fs::read(&outside).await.unwrap(),
        b"outside private data"
    );
    sqlx::query("UPDATE resources SET url=$2 WHERE id=$1")
        .bind(&id)
        .bind(uploaded["url"].as_str().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        TestClient::post(&delete).send(&own).await.status_code,
        Some(StatusCode::OK)
    );
    assert!(!object_path.exists());
    assert_eq!(
        TestClient::post(&delete).send(&own).await.status_code,
        Some(StatusCode::NOT_FOUND)
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM resources WHERE owner=$1")
        .bind(&f.owner)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    tokio::fs::remove_file(outside).await.unwrap();
    let mut parent = object_path.parent().unwrap().to_path_buf();
    while parent != bucket {
        tokio::fs::remove_dir(&parent).await.unwrap();
        parent = parent.parent().unwrap().to_path_buf();
    }
    tokio::fs::remove_dir(&bucket).await.unwrap();
    tokio::fs::remove_dir(path).await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
async fn local_owner_namespaces_distinguish_case_and_reject_external_buckets() {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let upper = format!("Org-{suffix}");
    let lower = format!("org-{suffix}");
    let upper_principal = Principal {
        application_identity: false,
        id: "user".into(),
        owner: upper.clone(),
        name: "user".into(),
        admin: true,
    };
    let lower_principal = Principal {
        application_identity: false,
        owner: lower.clone(),
        ..upper_principal.clone()
    };
    let a = service::local_storage_root(&upper_principal, &upper, None, true)
        .await
        .unwrap();
    let b = service::local_storage_root(&lower_principal, &lower, None, true)
        .await
        .unwrap();
    assert_ne!(a, b);
    assert_eq!(a.file_name().unwrap().to_str().unwrap(), proof_hash(&upper));
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    assert!(
        service::local_storage_root(&upper_principal, &upper, repo.to_str(), false)
            .await
            .is_err()
    );
    assert!(
        service::local_storage_root(&upper_principal, &upper, b.to_str(), false)
            .await
            .is_err()
    );
    tokio::fs::remove_dir(a).await.unwrap();
    tokio::fs::remove_dir(b).await.unwrap();
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn implicit_local_upload_is_resolved_from_resource_owner_for_global_and_ordinary_actors() {
    use salvo::{
        prelude::*,
        test::{ResponseExt, TestClient},
    };
    let f = Fixture::new().await;
    let principal = Principal {
        application_identity: false,
        admin: false,
        ..f.principal.clone()
    };
    let own = file_service(f.pool.clone(), principal.clone());
    let global = file_service(
        f.pool.clone(),
        Principal {
            application_identity: false,
            owner: "built-in".into(),
            admin: true,
            ..f.principal.clone()
        },
    );
    let root = service::local_storage_root(&principal, &f.owner, None, true)
        .await
        .unwrap();
    let body = "--implicit-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"implicit.txt\"\r\nContent-Type: text/plain\r\n\r\nimplicit file\r\n--implicit-boundary--\r\n";
    let mut response = TestClient::post("http://localhost/api/upload-resource")
        .add_header(
            "Content-Type",
            "multipart/form-data; boundary=implicit-boundary",
            true,
        )
        .body(body)
        .send(&own)
        .await;
    let status = response.status_code;
    let details = response.take_string().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{details}");
    let (id, key): (String, String) =
        sqlx::query_as("SELECT id,name FROM resources WHERE owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    for actor in [&own, &global] {
        let mut response = TestClient::get(format!("http://localhost/api/download-resource/{id}"))
            .send(actor)
            .await;
        let status = response.status_code;
        let data = response.take_string().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{data}");
        assert_eq!(data, "implicit file");
    }
    assert_eq!(
        TestClient::post(format!("http://localhost/api/delete-resource/{id}"))
            .send(&own)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let file = root.join(key);
    assert!(!file.exists());
    let mut directory = file.parent().unwrap().to_path_buf();
    while directory != root {
        tokio::fs::remove_dir(&directory).await.unwrap();
        directory = directory.parent().unwrap().to_path_buf();
    }
    tokio::fs::remove_dir(root).await.unwrap();
    f.cleanup().await;
}
