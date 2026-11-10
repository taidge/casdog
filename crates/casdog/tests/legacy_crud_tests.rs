use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

#[derive(Clone)]
struct Identity {
    owner: String,
    name: String,
    id: String,
    admin: bool,
}

#[handler]
async fn identify(depot: &mut Depot) {
    let identity = depot.obtain::<Identity>().unwrap().clone();
    depot.insert("user_owner", identity.owner);
    depot.insert("user_name", identity.name);
    depot.insert("user_id", identity.id);
    depot.insert("is_admin", identity.admin);
}

fn service(pool: &PgPool, identity: Identity) -> Service {
    Service::new(Router::with_path("api").push(casdog::handlers::casdoor_compat::routes()))
        .hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(identity),
        )
        .hoop(identify)
}

#[tokio::test]
async fn mfa_short_and_legacy_routes_require_authentication() {
    casdog::config::AppConfig::load().expect("test configuration must load");
    let service = Service::new(casdog::routes::create_router());
    for path in [
        "setup",
        "verify",
        "enable",
        "setup/initiate",
        "setup/verify",
        "setup/enable",
    ] {
        let response = TestClient::post(format!("http://localhost/api/mfa/{path}"))
            .json(&json!({}))
            .send(&service)
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "{path}"
        );
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL pointing to a migrated disposable PostgreSQL database"]
async fn legacy_crud_filters_masks_and_enforces_tenant_and_self_access() {
    let url = std::env::var("CASDOG_TEST_DATABASE_URL").expect("set CASDOG_TEST_DATABASE_URL");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let owner = format!("parity-{}", uuid::Uuid::new_v4());
    let other_owner = format!("other-{}", uuid::Uuid::new_v4());
    let alice_id = uuid::Uuid::new_v4().to_string();
    for (id, tenant, name, display) in [
        (alice_id.clone(), owner.clone(), "alice", "Match Bravo"),
        (
            uuid::Uuid::new_v4().to_string(),
            owner.clone(),
            "bob",
            "Match Charlie",
        ),
        (
            uuid::Uuid::new_v4().to_string(),
            other_owner.clone(),
            "bob",
            "Match Delta",
        ),
    ] {
        sqlx::query("INSERT INTO users (id, owner, name, display_name, password_hash, totp_secret, recovery_codes) VALUES ($1, $2, $3, $4, 'opaque-password-hash', 'private-totp-secret', '[\"private-recovery\"]')")
            .bind(id).bind(tenant).bind(name).bind(display).execute(&pool).await.unwrap();
    }
    let global = service(
        &pool,
        Identity {
            owner: "built-in".into(),
            name: "admin".into(),
            id: "user_admin".into(),
            admin: true,
        },
    );
    let mut response = TestClient::get(format!("http://localhost/api/get-users?owner={owner}&field=displayName&value=Match&sortField=displayName&sortOrder=descend&pageSize=1&p=1"))
        .send(&global).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["data2"], 2);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["name"], "bob");
    assert_eq!(body["data"][0]["password"], "***");
    for secret in ["passwordHash", "totpSecret", "recoveryCodes"] {
        assert!(body["data"][0].get(secret).is_none(), "{secret}");
    }
    let alice = service(
        &pool,
        Identity {
            owner: owner.clone(),
            name: "alice".into(),
            id: alice_id.clone(),
            admin: false,
        },
    );
    let mut response = TestClient::get("http://localhost/api/get-users")
        .send(&alice)
        .await;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["data2"], 1);
    assert_eq!(body["data"][0]["name"], "alice");
    for (id, payload) in [
        (format!("{owner}/bob"), json!({"displayName": "Hijacked"})),
        (format!("{owner}/alice"), json!({"isAdmin": true})),
        (
            format!("{other_owner}/bob"),
            json!({"displayName": "Hijacked"}),
        ),
    ] {
        let response = TestClient::post(format!("http://localhost/api/update-user?id={id}"))
            .json(&payload)
            .send(&alice)
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::FORBIDDEN),
            "{id}: {payload}"
        );
    }
    let response = TestClient::post(format!("http://localhost/api/update-user?id={owner}/alice"))
        .json(&json!({"displayName": "New Alice"}))
        .send(&alice)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let admin = service(
        &pool,
        Identity {
            owner: owner.clone(),
            name: "alice".into(),
            id: alice_id.clone(),
            admin: true,
        },
    );
    let response = TestClient::post(format!(
        "http://localhost/api/delete-user?id={other_owner}/bob"
    ))
    .json(&json!({}))
    .send(&admin)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let (display, admin, hash): (String, bool, String) =
        sqlx::query_as("SELECT display_name, is_admin, password_hash FROM users WHERE id=$1")
            .bind(alice_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(display, "New Alice");
    assert!(!admin);
    assert_eq!(hash, "opaque-password-hash");
    sqlx::query("DELETE FROM users WHERE owner IN ($1, $2)")
        .bind(owner)
        .bind(other_owner)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
