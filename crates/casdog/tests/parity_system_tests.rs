use casdog::handlers::parity_system;
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::PgPool;
#[handler]
async fn tenant(depot: &mut Depot) {
    depot.insert("user_id", "system-test-user".to_string());
    depot.insert("user_owner", "system-test-tenant".to_string());
    depot.insert("user_name", "tester".to_string());
    depot.insert("is_admin", true);
}
#[handler]
async fn global(depot: &mut Depot) {
    depot.insert("user_id", "system-test-user".to_string());
    depot.insert("user_owner", "built-in".to_string());
    depot.insert("user_name", "admin".to_string());
    depot.insert("is_admin", true);
}
fn service(pool: PgPool, is_global: bool) -> Service {
    let r = Router::with_path("api").hoop(salvo::affix_state::AffixList::new().inject(pool));
    let r = if is_global {
        r.hoop(global)
    } else {
        r.hoop(tenant)
    };
    Service::new(r.push(parity_system::routes()))
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn duplicate_session_is_exact_and_does_not_disclose_another_users_session() {
    let pool = PgPool::connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO sessions(id,owner,name,application,user_id,session_id) VALUES($1,'system-test-tenant',$1,'app','system-test-user','browser')").bind(&id).execute(&pool).await.unwrap();
    let s = service(pool.clone(), false);
    for (value, expected) in [("browser", false), ("other-browser", true)] {
        let mut r = TestClient::get(format!(
            "http://localhost/api/is-session-duplicated?sessionPkId={id}&sessionId={value}"
        ))
        .send(&s)
        .await;
        assert_eq!(r.status_code, Some(StatusCode::OK));
        let body: Value = r.take_json().await.unwrap();
        assert_eq!(body["data"], expected);
    }
    sqlx::query("UPDATE sessions SET user_id='another-user' WHERE id=$1")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        TestClient::get(format!(
            "http://localhost/api/is-session-duplicated?sessionPkId={id}&sessionId=browser"
        ))
        .send(&s)
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    sqlx::query("DELETE FROM sessions WHERE id=$1")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn global_forms_returns_persisted_schemas_only_to_global_admin() {
    let pool = PgPool::connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO forms(id,owner,name,form_items) VALUES($1,'system-test-tenant',$1,$2)",
    )
    .bind(&id)
    .bind(json!([{"name":"Email","type":"email"}]))
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        TestClient::get("http://localhost/api/get-global-forms")
            .send(&service(pool.clone(), false))
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let mut r = TestClient::get("http://localhost/api/get-global-forms")
        .send(&service(pool.clone(), true))
        .await;
    let body: Value = r.take_json().await.unwrap();
    assert!(
        body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["name"] == id && v["formItems"][0]["name"] == "Email")
    );
    sqlx::query("DELETE FROM forms WHERE id=$1")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn discovery_requires_configured_tenant_issuer_and_checks_document_issuer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let pool = PgPool::connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let server_issuer = issuer.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            socket.read(&mut request).await.unwrap();
            let body=json!({"issuer":server_issuer,"authorization_endpoint":"https://idp.example/authorize"}).to_string();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
    });
    let path = format!(
        "http://localhost/api/get-idp-discovery?issuer={}",
        urlencoding::encode(&issuer)
    );
    assert_eq!(
        TestClient::get(&path)
            .send(&service(pool.clone(), true))
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,issuer_url) VALUES($1,'system-test-tenant',$1,'Discovery','OAuth','Custom',$2)").bind(&id).bind(&issuer).execute(&pool).await.unwrap();
    assert_eq!(
        TestClient::get(&path)
            .send(&service(pool.clone(), false))
            .await
            .status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    let mut r = TestClient::get(&path)
        .send(&service(pool.clone(), true))
        .await;
    assert_eq!(r.status_code, Some(StatusCode::OK));
    let body: Value = r.take_json().await.unwrap();
    assert_eq!(body["data"]["issuer"], issuer);
    server.abort();
    sqlx::query("DELETE FROM providers WHERE id=$1")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn first_administrator_password_is_atomic_and_cannot_be_reset_through_bootstrap() {
    casdog::config::AppConfig::load().unwrap();
    let pool = PgPool::connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    // The migrated disposable database includes a seeded admin. Preserve its
    // identity and references while exercising the canonical bootstrap name.
    let backup_name = format!("bootstrap-backup-{}", uuid::Uuid::new_v4());
    let original: Option<String> = sqlx::query_scalar(
        "UPDATE users SET name=$1 WHERE owner='built-in' AND name='admin' RETURNING id",
    )
    .bind(&backup_name)
    .fetch_optional(&pool)
    .await
    .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,'built-in','admin','Bootstrap admin','')").bind(&id).execute(&pool).await.unwrap();
    let s = Service::new(
        Router::with_path("api")
            .hoop(salvo::affix_state::AffixList::new().inject(pool.clone()))
            .push(Router::with_path("get-init-admin-status").get(parity_system::init_admin_status))
            .push(
                Router::with_path("init-admin-password").post(parity_system::init_admin_password),
            ),
    );
    let mut r = TestClient::get("http://localhost/api/get-init-admin-status")
        .send(&s)
        .await;
    let b: Value = r.take_json().await.unwrap();
    assert_eq!(b["data"], true);
    let one = TestClient::post("http://localhost/api/init-admin-password")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .json(&json!({"password":"OneStrongPassword42!"}));
    let two = TestClient::post("http://localhost/api/init-admin-password")
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .json(&json!({"password":"TwoStrongPassword42!"}));
    let (a, b) = tokio::join!(one.send(&s), two.send(&s));
    assert_ne!(
        a.status_code == Some(StatusCode::OK),
        b.status_code == Some(StatusCode::OK)
    );
    let mut r = TestClient::get("http://localhost/api/get-init-admin-status")
        .send(&s)
        .await;
    let b: Value = r.take_json().await.unwrap();
    assert_eq!(b["data"], false);
    let (hash, kind): (String, String) =
        sqlx::query_as("SELECT password_hash,password_type FROM users WHERE id=$1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(kind, "argon2");
    let winner = if a.status_code == Some(StatusCode::OK) {
        "OneStrongPassword42!"
    } else {
        "TwoStrongPassword42!"
    };
    assert!(
        casdog::services::PasswordService::verify_password(winner, &hash, &kind, None).unwrap()
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    if let Some(original) = original {
        sqlx::query("UPDATE users SET name='admin' WHERE id=$1 AND name=$2")
            .bind(original)
            .bind(backup_name)
            .execute(&pool)
            .await
            .unwrap();
    }
}
