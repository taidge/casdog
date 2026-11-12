//! WebAuthn registration state regressions against a disposable migrated database.
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    hoops::auth::session_fingerprint,
    services::{auth_service::Claims, webauthn_service::WebauthnService},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use salvo::{prelude::*, test::TestClient};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use webauthn_rs::prelude::Url;

struct Fixture {
    first: PgPool,
    second: PgPool,
    owner: String,
    user: String,
    claims: Claims,
    token: String,
    webauthn: WebauthnService,
}

impl Fixture {
    async fn new() -> Self {
        static CONFIG: std::sync::Once = std::sync::Once::new();
        CONFIG.call_once(|| {
            AppConfig::load().unwrap();
        });
        let url = std::env::var("CASDOG_TEST_DATABASE_URL")
            .expect("Set disposable migrated database URL");
        let first = PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .unwrap();
        let second = PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .unwrap();
        let owner = format!("webauthn-{}", uuid::Uuid::new_v4());
        let user = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Passkey regression')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&owner)
            .execute(&first)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO users(id,owner,name,display_name,password_hash) VALUES($1,$2,'alice','Alice','unused')",
        )
        .bind(&user)
        .bind(&owner)
        .execute(&first)
        .await
        .unwrap();
        let now = chrono::Utc::now();
        let claims: Claims = serde_json::from_value(json!({
            "sub": user, "owner": owner, "name": "alice", "is_admin": false,
            "iat": now.timestamp(), "issued_at_ms": now.timestamp_millis(),
            "exp": now.timestamp()+3600, "iss": AppConfig::get().jwt.issuer,
            "jti": uuid::Uuid::new_v4().to_string()
        }))
        .unwrap();
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes()),
        )
        .unwrap();
        let webauthn = WebauthnService::new(
            "localhost",
            &Url::parse("http://localhost:18085").unwrap(),
            "Casdog",
        )
        .unwrap();
        Self {
            first,
            second,
            owner,
            user,
            claims,
            token,
            webauthn,
        }
    }

    async fn begin(&self) -> String {
        let (_, state) = self
            .webauthn
            .start_registration(self.user.as_bytes(), "alice", "Alice", None)
            .unwrap();
        WebauthnService::begin_registration_state(
            &self.first,
            &self.claims,
            &self.token,
            "http://localhost:18085",
            &state,
        )
        .await
        .unwrap()
    }

    async fn remains(&self, request_id: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM webauthn_challenges WHERE request_id=$1)")
            .bind(request_id)
            .fetch_one(&self.second)
            .await
            .unwrap()
    }

    async fn finish(&self, pool: &PgPool, request_id: &str, token: &str, origin: &str) -> bool {
        self.webauthn
            .complete_registration(
                pool,
                &self.claims,
                token,
                origin,
                request_id,
                json!({}),
                "Passkey",
            )
            .await
            .is_ok()
    }

    async fn cleanup(self) {
        sqlx::query("DELETE FROM users WHERE owner=$1")
            .bind(&self.owner)
            .execute(&self.first)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE name=$1")
            .bind(&self.owner)
            .execute(&self.first)
            .await
            .unwrap();
        self.first.close().await;
        self.second.close().await;
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-023"]
async fn registration_state_is_shared_session_bound_and_consumed_once() {
    let f = Fixture::new().await;
    let request = f.begin().await;
    let saved: Value =
        sqlx::query_scalar("SELECT to_jsonb(c) FROM webauthn_challenges c WHERE request_id=$1")
            .bind(&request)
            .fetch_one(&f.second)
            .await
            .unwrap();
    assert_eq!(saved["session_hash"], session_fingerprint(&f.token));
    assert!(!saved.to_string().contains(&f.token));
    assert!(
        !f.finish(
            &f.second,
            &request,
            "another-session",
            "http://localhost:18085"
        )
        .await
    );
    assert!(f.remains(&request).await);
    assert!(
        !f.finish(&f.second, &request, &f.token, "https://attacker.test")
            .await
    );
    assert!(f.remains(&request).await);
    // A malformed attestation consumes its own proof on another instance.
    assert!(
        !f.finish(&f.second, &request, &f.token, "http://localhost:18085")
            .await
    );
    assert!(!f.remains(&request).await);
    assert!(
        !f.finish(&f.first, &request, &f.token, "http://localhost:18085")
            .await
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-023"]
async fn concurrent_registration_completions_consume_one_proof_across_instances() {
    let f = Fixture::new().await;
    let request = f.begin().await;
    let first = f.webauthn.complete_registration(
        &f.first,
        &f.claims,
        &f.token,
        "http://localhost:18085",
        &request,
        json!({}),
        "Passkey",
    );
    let second = f.webauthn.complete_registration(
        &f.second,
        &f.claims,
        &f.token,
        "http://localhost:18085",
        &request,
        json!({}),
        "Passkey",
    );
    let (first, second) = tokio::join!(first, second);
    let errors = [
        first.unwrap_err().to_string(),
        second.unwrap_err().to_string(),
    ];
    assert_eq!(
        errors
            .iter()
            .filter(|error| error.contains("Invalid registration payload"))
            .count(),
        1
    );
    assert_eq!(
        errors
            .iter()
            .filter(|error| error.contains("Unknown or expired registration request"))
            .count(),
        1
    );
    assert!(!f.remains(&request).await);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-023"]
async fn registration_rejects_expired_revoked_and_impersonated_sessions() {
    let f = Fixture::new().await;
    let expired = f.begin().await;
    sqlx::query("UPDATE webauthn_challenges SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE request_id=$1")
        .bind(&expired)
        .execute(&f.first)
        .await
        .unwrap();
    assert!(
        !f.finish(&f.second, &expired, &f.token, "http://localhost:18085")
            .await
    );
    let active = f.begin().await;
    assert!(!f.remains(&expired).await);
    sqlx::query("INSERT INTO revoked_session_tokens(token_hash,user_id,expires_at) VALUES($1,$2,clock_timestamp()+INTERVAL '1 hour')")
        .bind(session_fingerprint(&f.token)).bind(&f.user).execute(&f.first).await.unwrap();
    assert!(
        !f.finish(&f.second, &active, &f.token, "http://localhost:18085")
            .await
    );
    sqlx::query("DELETE FROM revoked_session_tokens WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.first)
        .await
        .unwrap();
    let mut claims = f.claims.clone();
    claims.impersonator_user_id = Some(uuid::Uuid::new_v4().to_string());
    let (_, state) = f
        .webauthn
        .start_registration(f.user.as_bytes(), "alice", "Alice", None)
        .unwrap();
    assert!(
        WebauthnService::begin_registration_state(
            &f.first,
            &claims,
            &f.token,
            "http://localhost:18085",
            &state
        )
        .await
        .is_err()
    );
    claims.impersonator_user_id = None;
    claims.issued_at_ms = Some(chrono::Utc::now().timestamp_millis() - 300_001);
    assert!(
        WebauthnService::begin_registration_state(
            &f.first,
            &claims,
            &f.token,
            "http://localhost:18085",
            &state
        )
        .await
        .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-023"]
async fn unrelated_account_cannot_consume_registration_and_pending_state_is_bounded() {
    let f = Fixture::new().await;
    let other = Fixture::new().await;
    let request = f.begin().await;
    assert!(
        !other
            .finish(
                &other.second,
                &request,
                &other.token,
                "http://localhost:18085"
            )
            .await
    );
    assert!(f.remains(&request).await);
    for _ in 1..20 {
        f.begin().await;
    }
    let (_, state) = f
        .webauthn
        .start_registration(f.user.as_bytes(), "alice", "Alice", None)
        .unwrap();
    assert!(
        WebauthnService::begin_registration_state(
            &f.second,
            &f.claims,
            &f.token,
            "http://localhost:18085",
            &state
        )
        .await
        .is_err()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM webauthn_challenges WHERE user_id=$1")
            .bind(&f.user)
            .fetch_one(&f.first)
            .await
            .unwrap();
    assert_eq!(count, 20);
    other.cleanup().await;
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-023"]
async fn registration_finish_rejects_cross_origin_without_consuming_state() {
    let f = Fixture::new().await;
    let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
    let diesel = create_diesel_pool(&url).await.unwrap();
    let service = Service::new(casdog::routes::create_router()).hoop(
        salvo::affix_state::AffixList::new()
            .inject(f.first.clone())
            .inject(diesel),
    );
    let request = f.begin().await;
    let response = TestClient::post(format!(
        "http://localhost/api/webauthn/signup/finish?requestId={request}&name=Test"
    ))
    .add_header("authorization", format!("Bearer {}", f.token), true)
    .add_header("origin", "https://attacker.test", true)
    .json(&json!({}))
    .send(&service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    assert!(f.remains(&request).await);
    f.cleanup().await;
}
