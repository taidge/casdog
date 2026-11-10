use casdog::handlers::parity_resources::{
    self, marketplace, openclaw,
    service::{self, Kind, ListOptions},
};
use casdog::hoops::authz::Principal;
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};

fn admin(owner: &str) -> Principal {
    Principal {
        id: "test-admin".into(),
        owner: owner.into(),
        name: "admin".into(),
        admin: true,
    }
}
fn options(owner: &str) -> ListOptions {
    ListOptions {
        owner: Some(owner.into()),
        field: None,
        value: String::new(),
        sort: "name".into(),
        descending: false,
        limit: Some(1),
        offset: 0,
    }
}
async fn pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .connect(
            &std::env::var("CASDOG_TEST_DATABASE_URL").expect("CASDOG_TEST_DATABASE_URL required"),
        )
        .await
        .unwrap()
}

#[test]
fn resource_identity_and_masking_are_closed() {
    for (owner, name) in [("", "a"), ("a", "b/c"), ("a", "b\n")] {
        assert!(service::identity(owner, name).is_err());
    }
    assert!(service::authorize(&admin("tenant-a"), "tenant-b").is_err());
    assert!(service::authorize(&admin("built-in"), "tenant-b").is_ok());
    let value = json!({"owner":"tenant-a","name":"server","token":"secret","tools":[]});
    for kind in [Kind::Agent, Kind::Server] {
        assert_eq!(service::masked(kind, value.clone(), false)["token"], "");
    }
    assert_eq!(
        service::masked(Kind::Key, json!({"accessSecret":"secret"}), true)["accessSecret"],
        "***"
    );
}

#[test]
fn marketplace_checks_checksum_manifest_and_revocations() {
    let bundle = json!({"manifest":{"id":"test","type":"app","version":"1.0"},"files":{"application.json":{}}});
    let bytes = serde_json::to_vec(&bundle).unwrap();
    let mut index = json!({"integrations":[{"id":"test","type":"app","latest":"1.0","versions":[{"version":"1.0","sha256":hex::encode(Sha256::digest(&bytes))}]}],"revoked":[]});
    assert!(marketplace::validate_bundle(&index, "test", "", &bytes).is_ok());
    assert!(marketplace::validate_bundle(&index, "test", "", b"tampered").is_err());
    index["revoked"] = json!([{"id":"test","version":"1.0"}]);
    assert!(marketplace::validate_bundle(&index, "test", "", &bytes).is_err());
}

#[test]
fn marketplace_variables_are_validated_and_replaced_as_values() {
    let bundle = json!({"manifest":{"variables":[{"name":"appUrl","type":"url","required":true}]},"files":{"application.json":{"redirectUris":["{{ appUrl }}/callback"]}}});
    assert_eq!(
        marketplace::render(
            &bundle,
            &json!({"variables":{"appUrl":"https://app.example/"}}),
            "application.json"
        )
        .unwrap()["redirectUris"][0],
        "https://app.example/callback"
    );
    assert!(
        marketplace::render(
            &bundle,
            &json!({"variables":{"appUrl":"javascript:alert(1)"}}),
            "application.json"
        )
        .is_err()
    );
    assert!(marketplace::render(&bundle, &json!({}), "application.json").is_err());
}

#[test]
fn openclaw_graph_links_tool_results_and_excludes_other_sessions() {
    let entry = |name: &str, data: Value| json!({"owner":"tenant","name":name,"provider":"log","type":"session","message":data.to_string()});
    let task = entry(
        "task",
        json!({"sessionId":"one","entryId":"t","kind":"task","summary":"task"}),
    );
    let call = entry(
        "call",
        json!({"sessionId":"one","entryId":"a","parentId":"t","kind":"tool_call","toolCallId":"c","tool":"search"}),
    );
    let result = entry(
        "result",
        json!({"sessionId":"one","entryId":"r","parentId":"a","kind":"tool_result","toolCallId":"c","ok":false}),
    );
    let other = entry(
        "other",
        json!({"sessionId":"two","entryId":"x","kind":"final"}),
    );
    let graph = openclaw::build(&task, &[task.clone(), call, result, other]).unwrap();
    assert_eq!(graph["stats"]["totalNodes"], 4);
    assert_eq!(graph["stats"]["failedCount"], 1);
    assert!(
        graph["edges"]
            .as_array()
            .unwrap()
            .contains(&json!({"source":"tool_call:c","target":"r"}))
    );
    assert!(!graph.to_string().contains("\"id\":\"x\""));
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn resource_crud_persists_secrets_preserves_identity_and_enforces_tenants() {
    let pool = pool().await;
    let owner = format!("resource-{}", uuid::Uuid::new_v4());
    let principal = admin(&owner);
    for (kind, name, body) in [
        (
            Kind::Agent,
            "agent",
            json!({"url":"https://example.org/agent","token":"agent-secret"}),
        ),
        (
            Kind::Server,
            "server",
            json!({"url":"https://example.org/mcp","token":"server-secret","tools":[{"name":"search","inputSchema":{"type":"object"},"isAllowed":false}]}),
        ),
        (
            Kind::Entry,
            "entry",
            json!({"type":"event","message":"persist me"}),
        ),
        (
            Kind::Key,
            "key",
            json!({"type":"General","accessKey":"forged","accessSecret":"forged"}),
        ),
    ] {
        let result = service::save(&pool, &principal, kind, &owner, name, body.clone(), false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result["owner"], owner);
        assert!(
            service::save(&pool, &principal, kind, &owner, name, body, false)
                .await
                .is_err()
        );
        assert!(
            service::save(
                &pool,
                &admin("other"),
                kind,
                &owner,
                name,
                json!({"displayName":"hijack"}),
                true
            )
            .await
            .is_err()
        );
    }
    let key = service::get(&pool, Kind::Key, &owner, "key")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(key["accessKey"], "forged");
    assert_ne!(key["accessSecret"], "forged");
    let changed = service::save(
        &pool,
        &principal,
        Kind::Key,
        &owner,
        "key",
        json!({"accessSecret":"replace","displayName":"Renamed"}),
        true,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(changed["accessSecret"], key["accessSecret"]);
    for kind in [Kind::Agent, Kind::Server] {
        let name = kind.name();
        let old = service::get(&pool, kind, &owner, name)
            .await
            .unwrap()
            .unwrap();
        let changed = service::save(
            &pool,
            &principal,
            kind,
            &owner,
            name,
            json!({"token":""}),
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(old["token"], changed["token"]);
    }
    assert!(
        service::save(
            &pool,
            &principal,
            Kind::Key,
            &owner,
            "bad",
            json!({"type":"User","organization":"other","user":"victim"}),
            false
        )
        .await
        .is_err()
    );
    assert!(
        service::save(
            &pool,
            &principal,
            Kind::Key,
            &owner,
            "bad",
            json!({"type":"General","expireTime":"yesterday"}),
            false
        )
        .await
        .is_err()
    );
    service::save(
        &pool,
        &principal,
        Kind::Entry,
        &owner,
        "entry2",
        json!({"message":"other"}),
        false,
    )
    .await
    .unwrap();
    let mut filter = options(&owner);
    filter.offset = 20;
    let (data, total) = service::list(&pool, &principal, Kind::Entry, filter)
        .await
        .unwrap();
    assert!(data.is_empty());
    assert_eq!(total, 2);
    let mut filter = options(&owner);
    filter.field = Some("name".into());
    filter.value = "entry2".into();
    let (data, total) = service::list(&pool, &principal, Kind::Entry, filter)
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(data[0]["name"], "entry2");
    let mut filter = options(&owner);
    filter.sort = "token".into();
    assert!(
        service::list(&pool, &principal, Kind::Agent, filter)
            .await
            .is_err()
    );
    assert!(
        service::delete(&pool, &principal, Kind::Agent, &owner, "agent")
            .await
            .unwrap()
    );
    assert!(
        !service::delete(&pool, &principal, Kind::Agent, &owner, "agent")
            .await
            .unwrap()
    );
    sqlx::query("DELETE FROM casdoor_objects WHERE owner=$1")
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn marketplace_install_uninstall_is_atomic_and_links_real_resources() {
    let pool = pool().await;
    let owner = format!("market-{}", uuid::Uuid::new_v4());
    let principal = admin(&owner);
    let app_bundle = json!({"manifest":{"id":"sample","type":"app","version":"1","variables":[{"name":"appUrl","type":"url","required":true}]},"files":{"application.json":{"redirectUris":["{{appUrl}}/callback"]}}});
    let item = json!({"id":"sample","type":"app","name":{"en":"Sample"}});
    let request = json!({"owner":owner,"name":"sample-app","integrationId":"sample","variables":{"appUrl":"https://example.org"}});
    assert!(
        marketplace::install(&pool, &admin("other"), &request, &item, &app_bundle)
            .await
            .is_err()
    );
    marketplace::install(&pool, &principal, &request, &item, &app_bundle)
        .await
        .unwrap();
    let app: Value = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM applications a WHERE owner=$1 AND name='sample-app'",
    )
    .bind(&owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(app["organization"], owner);
    assert_eq!(app["redirect_uris"], "[\"https://example.org/callback\"]");
    let provider_bundle = json!({"manifest":{"id":"github","type":"provider","version":"1"},"files":{"provider.json":{"category":"OAuth","type":"GitHub","scopes":"user:email"}}});
    let request = json!({"owner":owner,"name":"github","clientId":"client","clientSecret":"secret","application":"sample-app"});
    marketplace::install(
        &pool,
        &principal,
        &request,
        &json!({"name":{"en":"GitHub"}}),
        &provider_bundle,
    )
    .await
    .unwrap();
    let links: Value = sqlx::query_scalar("SELECT providers FROM applications WHERE id=$1")
        .bind(app["id"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(links[0]["name"], "github");
    let bad = json!({"owner":owner,"name":"rollback","clientId":"client","clientSecret":"secret","application":"missing"});
    assert!(
        marketplace::install(&pool, &principal, &bad, &item, &provider_bundle)
            .await
            .is_err()
    );
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM providers WHERE owner=$1 AND name='rollback') OR EXISTS(SELECT 1 FROM casdoor_objects WHERE owner=$1 AND name='rollback')").bind(&owner).fetch_one(&pool).await.unwrap();
    assert!(!exists);
    assert!(
        marketplace::uninstall(&pool, &principal, &owner, "github")
            .await
            .unwrap()
    );
    let links: Value = sqlx::query_scalar("SELECT providers FROM applications WHERE id=$1")
        .bind(app["id"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(links, json!([]));
    assert!(
        marketplace::uninstall(&pool, &principal, &owner, "sample-app")
            .await
            .unwrap()
    );
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications WHERE id=$1)")
        .bind(app["id"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!exists);
    let envelope: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM casdoor_objects WHERE kind='integration' AND owner=$1 AND name='sample-app')")
        .bind(&owner).fetch_one(&pool).await.unwrap();
    assert!(!envelope);
    let reinstall = json!({"owner":owner,"name":"sample-app","integrationId":"sample","variables":{"appUrl":"https://reinstalled.example.org"}});
    marketplace::install(&pool, &principal, &reinstall, &item, &app_bundle)
        .await
        .unwrap();
    let (new_id, deleted, redirects): (String, bool, String) = sqlx::query_as(
        "SELECT id,is_deleted,redirect_uris FROM applications WHERE owner=$1 AND name='sample-app'",
    )
    .bind(&owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(new_id, app["id"].as_str().unwrap());
    assert!(!deleted);
    assert_eq!(redirects, "[\"https://reinstalled.example.org/callback\"]");
    assert!(
        marketplace::uninstall(&pool, &principal, &owner, "sample-app")
            .await
            .unwrap()
    );
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM applications WHERE owner=$1")
        .bind(&owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
    sqlx::query("DELETE FROM applications WHERE owner=$1")
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

fn signed_session(owner: &str, id: &str) -> (String, casdog::services::auth_service::Claims) {
    let config = casdog::config::AppConfig::load().unwrap();
    let now = chrono::Utc::now();
    let claims = casdog::services::auth_service::Claims {
        sub: id.into(),
        owner: owner.into(),
        name: "user".into(),
        is_admin: false,
        impersonator_user_id: None,
        impersonator_owner: None,
        impersonator_name: None,
        impersonation_session_id: None,
        impersonation_application: None,
        exp: now.timestamp() + 3600,
        iat: now.timestamp(),
        issued_at_ms: Some(now.timestamp_millis()),
        jti: Some(uuid::Uuid::new_v4().to_string()),
        iss: config.jwt.issuer,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(config.jwt.secret.as_bytes()),
    )
    .unwrap();
    (token, claims)
}
fn mcp_service(pool: &PgPool) -> Service {
    Service::new(
        Router::with_path("api")
            .hoop(casdog::hoops::JwtAuth)
            .push(parity_resources::routes()),
    )
    .hoop(salvo::affix_state::AffixList::new().inject(pool.clone()))
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn mcp_access_token_is_app_bound_read_only_short_lived_and_denies_disabled_user() {
    let pool = pool().await;
    let owner = format!("mcp-{}", uuid::Uuid::new_v4());
    let id = uuid::Uuid::new_v4().to_string();
    let app_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,$2,'user','User','unused')").bind(&id).bind(&owner).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris) VALUES($1,$2,'mcp-app','MCP',$2,$3,'secret','[]')").bind(&app_id).bind(&owner).bind(uuid::Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
    let service = mcp_service(&pool);
    let (jwt, claims) = signed_session(&owner, &id);
    let authorization = format!("Bearer {jwt}");
    let mut response = TestClient::get(format!(
        "http://localhost/api/get-mcp-access-token?owner={owner}&applicationName=mcp-app"
    ))
    .add_header("Authorization", &authorization, true)
    .send(&service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    let token = body["data"].as_str().unwrap();
    assert!(!token.contains('.'));
    let (user, org, scope, expiry): (String, String, String, i64) = sqlx::query_as(
        "SELECT user_id,organization,scope,expires_in FROM tokens WHERE access_token=$1",
    )
    .bind(token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (user, org, scope, expiry),
        (id.clone(), owner.clone(), "read".into(), 900)
    );
    let response = TestClient::get(
        "http://localhost/api/get-mcp-access-token?owner=other&applicationName=mcp-app",
    )
    .add_header("Authorization", &authorization, true)
    .send(&service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    sqlx::query("UPDATE users SET is_forbidden=true WHERE id=$1")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
    let response = TestClient::get(format!(
        "http://localhost/api/get-mcp-access-token?owner={owner}&applicationName=mcp-app"
    ))
    .add_header("Authorization", &authorization, true)
    .send(&service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    sqlx::query("UPDATE users SET is_forbidden=false WHERE id=$1")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
    casdog::services::auth_service::AuthService::logout_session(
        &pool,
        &id,
        Some((&casdog::hoops::auth::session_fingerprint(&jwt), claims.exp)),
    )
    .await
    .unwrap();
    let response = TestClient::get(format!(
        "http://localhost/api/get-mcp-access-token?owner={owner}&applicationName=mcp-app"
    ))
    .add_header("Authorization", &authorization, true)
    .send(&service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tokens WHERE user_id=$1")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::query("DELETE FROM tokens WHERE organization=$1")
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM applications WHERE id=$1")
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn mcp_access_token_rechecks_logout_epoch_after_waiting_for_account_lock() {
    let first = pool().await;
    let second = pool().await;
    let owner = format!("mcp-race-{}", uuid::Uuid::new_v4());
    let id = uuid::Uuid::new_v4().to_string();
    let app_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,$2,'user','User','unused')").bind(&id).bind(&owner).execute(&first).await.unwrap();
    sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris) VALUES($1,$2,'mcp-app','MCP',$2,$3,'secret','[]')").bind(&app_id).bind(&owner).bind(uuid::Uuid::new_v4().to_string()).execute(&first).await.unwrap();
    let (jwt, _) = signed_session(&owner, &id);
    let service = mcp_service(&second);
    let mut tx = first.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let url =
        format!("http://localhost/api/get-mcp-access-token?owner={owner}&applicationName=mcp-app");
    let request = tokio::spawn(async move {
        TestClient::get(url)
            .add_header("Authorization", format!("Bearer {jwt}"), true)
            .send(&service)
            .await
    });
    // Observe the actual row-lock wait: the signed session passed JwtAuth before
    // the epoch changes, so this exercises the handler's transaction recheck.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            sqlx::query("SELECT pg_stat_clear_snapshot()")
                .execute(&mut *tx)
                .await
                .unwrap();
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            if waiting {
                break;
            }
            assert!(
                !request.is_finished(),
                "request must wait for the account lock"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("MCP issuance did not acquire the account lock");
    sqlx::query(
        "INSERT INTO user_session_epochs(user_id,invalid_before) VALUES($1,clock_timestamp())",
    )
    .bind(&id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let response = request.await.unwrap();
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tokens WHERE user_id=$1")
        .bind(&id)
        .fetch_one(&first)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "a JWT revoked during its lock wait cannot mint a token"
    );
    sqlx::query("DELETE FROM applications WHERE id=$1")
        .bind(app_id)
        .execute(&first)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(id)
        .execute(&first)
        .await
        .unwrap();
    first.close().await;
    second.close().await;
}
