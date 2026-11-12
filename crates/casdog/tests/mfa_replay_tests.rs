//! PostgreSQL-backed MFA replay and FaceID first-factor regressions (001–027).
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    handlers::{login_compat, password_mfa, social_session},
    models::User,
    services::{
        PasswordService,
        face_service::{FaceService, FaceVerifyRequest},
        mfa_service::MfaService,
        social_state_service::{self as state, NewCompletion},
    },
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

struct Fixture {
    pool: PgPool,
    other_pool: PgPool,
    service: Service,
    other: Service,
    owner: String,
    user: String,
    app: String,
    provider: String,
    secret: String,
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
                .push(
                    Router::with_path("api/auth/password/session")
                        .post(password_mfa::consume_password_session),
                )
                .push(
                    Router::with_path("api/auth/session")
                        .post(social_session::consume_social_session),
                )
                .push(
                    Router::with_path("api/faceid-signin-finish")
                        .post(login_compat::faceid_signin_finish),
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
        let owner = format!("replay-{}", uuid::Uuid::new_v4());
        let user = uuid::Uuid::new_v4().to_string();
        let app = uuid::Uuid::new_v4().to_string();
        let provider = uuid::Uuid::new_v4().to_string();
        let (secret, _) = MfaService::initiate_totp_setup("alice", "test").unwrap();
        sqlx::query(
            "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'Replay test')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        let hash = PasswordService::hash_password("ValidPassword42!", "bcrypt", None).unwrap();
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type,provider_ids,properties) VALUES($1,$2,'alice','Alice',$3,'bcrypt',$4,$5)")
            .bind(&user).bind(&owner).bind(hash).bind(json!({format!("oauth:{provider}"):"subject"}))
            .bind(json!({"faceIds":[[1.0,0.0,0.0]]})).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES($1,$2,'mock','Mock','OAuth','Mock')")
            .bind(&provider).bind(&owner).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,enable_password,providers) VALUES($1,$2,'app','App',$2,$1,'secret','',true,$3)")
            .bind(&app).bind(&owner).bind(json!([{"name":format!("{owner}/mock"),"canSignIn":true}])).execute(&pool).await.unwrap();
        Self {
            pool,
            other_pool,
            service,
            other,
            owner,
            user,
            app,
            provider,
            secret,
        }
    }
    async fn enroll(&self) {
        MfaService::save_mfa(&self.pool, &self.user, "totp", Some(&self.secret))
            .await
            .unwrap();
        MfaService::enable_mfa(&self.pool, &self.user, "totp")
            .await
            .unwrap();
        sqlx::query("UPDATE user_mfa SET recovery_codes='[\"recovery-one\",\"recovery-two\",\"recovery-three\"]' WHERE user_id=$1")
            .bind(&self.user).execute(&self.pool).await.unwrap();
    }
    async fn user(&self) -> User {
        sqlx::query_as("SELECT * FROM users WHERE id=$1")
            .bind(&self.user)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn code(&self, offset: i64) -> String {
        use totp_rs::{Algorithm, Secret, TOTP};
        let seconds: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(self.secret.clone()).to_bytes().unwrap(),
            None,
            "alice".into(),
        )
        .unwrap()
        .generate(((seconds / 30 + offset) * 30) as u64)
    }
    async fn password_proof(&self) -> String {
        let mut response = TestClient::post("http://localhost/api/login")
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .json(&json!({"owner":self.owner,"name":"alice","password":"ValidPassword42!","clientId":self.app}))
            .send(&self.service).await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let proof = proof_cookie(&response);
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(body["mfa_required"], true);
        assert_eq!(body["token"], "");
        proof
    }
    async fn completion(&self) -> String {
        state::create_completion(
            &self.pool,
            &NewCompletion {
                user_id: self.user.clone(),
                provider_id: self.provider.clone(),
                provider_name: "mock".into(),
                application_id: self.app.clone(),
                organization: self.owner.clone(),
                context: json!({"link_key":format!("oauth:{}",self.provider),"subject":"subject"}),
            },
        )
        .await
        .unwrap()
    }
    async fn factor(
        service: &Service,
        proof: &str,
        social: bool,
        method: &str,
        code: &str,
    ) -> Response {
        let (path, cookie) = if social {
            ("api/auth/session", "casdog_oauth_completion")
        } else {
            ("api/auth/password/session", "casdog_password_mfa")
        };
        TestClient::post(format!("http://localhost/{path}"))
            .add_header("Origin", "http://127.0.0.1:8000", true)
            .add_header("Cookie", format!("{cookie}={proof}"), true)
            .json(&json!({"mfaType":method,"passcode":code}))
            .send(service)
            .await
    }
    async fn face_nonce(&self) -> String {
        FaceService::new(self.pool.clone())
            .begin(&self.owner, "alice", Some(&self.app))
            .await
            .unwrap()
            .challenge
    }
    async fn face(&self, service: &Service, nonce: &str, embedding: Value) -> Response {
        TestClient::post(format!(
            "http://localhost/api/faceid-signin-finish?owner={}&name=alice",
            self.owner
        ))
        .add_header("Origin", "http://127.0.0.1:8000", true)
        .json(&json!({"challenge":nonce,"embedding":embedding}))
        .send(service)
        .await
    }
    async fn cleanup(self) {
        for (table, column) in [
            ("password_mfa_challenges", "organization"),
            ("social_oauth_completions", "organization"),
            ("tokens", "owner"),
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
fn proof_cookie(response: &Response) -> String {
    response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("casdog_password_mfa=")
        .unwrap()
        .to_owned()
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn totp_step_is_atomic_across_pools_and_transaction_rollback_preserves_proof() {
    let f = Fixture::new().await;
    let code = f.code(0).await;
    let mut a = f.pool.acquire().await.unwrap();
    let mut b = f.other_pool.acquire().await.unwrap();
    assert!(
        !MfaService::consume_totp(&mut a, &f.user, &f.secret, "invalid")
            .await
            .unwrap()
    );
    let (left, right) = tokio::join!(
        MfaService::consume_totp(&mut a, &f.user, &f.secret, &code),
        MfaService::consume_totp(&mut b, &f.user, &f.secret, &code),
    );
    assert_ne!(
        left.unwrap(),
        right.unwrap(),
        "exactly one instance consumes the authenticator step"
    );
    assert!(
        !MfaService::consume_totp(&mut b, &f.user, &f.secret, &code)
            .await
            .unwrap()
    );
    drop(a);
    drop(b);
    let future = f.code(1).await;
    let mut tx = f.pool.begin().await.unwrap();
    assert!(
        MfaService::consume_totp(&mut tx, &f.user, &f.secret, &future)
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();
    let mut conn = f.other_pool.acquire().await.unwrap();
    assert!(
        MfaService::consume_totp(&mut conn, &f.user, &f.secret, &future)
            .await
            .unwrap()
    );
    assert!(
        !MfaService::consume_totp(&mut conn, &f.user, &f.secret, &code)
            .await
            .unwrap()
    );
    drop(conn);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn enrollment_step_cannot_be_reused_by_legacy_login_and_recovery_remains_available() {
    let f = Fixture::new().await;
    MfaService::save_mfa(&f.pool, &f.user, "totp", Some(&f.secret))
        .await
        .unwrap();
    let code = f.code(0).await;
    assert!(
        MfaService::confirm_setup(&f.pool, &f.user, "totp", &code)
            .await
            .unwrap()
            .is_some()
    );
    let user = f.user().await;
    assert!(
        !MfaService::verify_login(&f.other_pool, &user, Some("app"), &code)
            .await
            .unwrap()
    );
    // Legacy inline secrets share the same replay namespace as enrolled rows.
    sqlx::query("UPDATE user_mfa SET is_enabled=false WHERE user_id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET totp_secret=$1 WHERE id=$2")
        .bind(&f.secret)
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        !MfaService::verify_login(&f.other_pool, &f.user().await, Some("app"), &code)
            .await
            .unwrap()
    );
    sqlx::query(
        "UPDATE user_mfa SET is_enabled=true,recovery_codes='[\"independent\"]' WHERE user_id=$1",
    )
    .bind(&f.user)
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(
        MfaService::verify_login(&f.other_pool, &user, Some("recovery"), "independent")
            .await
            .unwrap()
    );
    assert!(
        !MfaService::verify_login(&f.pool, &user, Some("recovery"), "independent")
            .await
            .unwrap()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn password_and_social_challenges_compete_for_the_same_totp_step() {
    let f = Fixture::new().await;
    f.enroll().await;
    let password = f.password_proof().await;
    let social = f.completion().await;
    let code = f.code(0).await;
    let (mut a, mut b) = tokio::join!(
        Fixture::factor(&f.service, &password, false, "app", &code),
        Fixture::factor(&f.other, &social, true, "app", &code),
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
    let successful: Value = if a.status_code == Some(StatusCode::OK) {
        a.take_json().await.unwrap()
    } else {
        b.take_json().await.unwrap()
    };
    assert!(!successful["token"].as_str().unwrap().is_empty());
    let next = f.password_proof().await;
    assert_eq!(
        Fixture::factor(&f.other, &next, false, "app", &code)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        Fixture::factor(&f.other, &next, false, "recovery", "recovery-one")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn faceid_nonce_is_atomic_and_enrolled_mfa_uses_the_common_browser_challenge() {
    let f = Fixture::new().await;
    f.enroll().await;
    sqlx::query("UPDATE applications SET enable_password=false WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    let nonce = f.face_nonce().await;
    let (mut a, mut b) = tokio::join!(
        f.face(&f.service, &nonce, json!([1.0, 0.0, 0.0])),
        f.face(&f.other, &nonce, json!([1.0, 0.0, 0.0]))
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
    let successful = if a.status_code == Some(StatusCode::OK) {
        &mut a
    } else {
        &mut b
    };
    let proof = proof_cookie(successful);
    let receipt: Value = successful.take_json().await.unwrap();
    assert_eq!(receipt["mfa_required"], true);
    assert_eq!(receipt["token"], "");
    assert_eq!(receipt["user"], format!("{}/alice", f.owner));
    assert!(receipt["similarity"].as_f64().unwrap() > 0.99);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM password_mfa_challenges WHERE user_id=$1")
            .bind(&f.user)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        Fixture::factor(&f.other, &proof, false, "recovery", "recovery-one")
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let nonce = f.face_nonce().await;
    let mut pending = f.face(&f.service, &nonce, json!([1.0, 0.0, 0.0])).await;
    let proof = proof_cookie(&pending);
    let _: Value = pending.take_json().await.unwrap();
    FaceService::new(f.pool.clone())
        .enroll(&f.owner, "alice", vec![0.0, 1.0, 0.0])
        .await
        .unwrap();
    assert_eq!(
        Fixture::factor(&f.other, &proof, false, "recovery", "recovery-two")
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn faceid_without_mfa_preserves_receipt_and_failed_embedding_consumes_nonce() {
    let f = Fixture::new().await;
    let nonce = f.face_nonce().await;
    let mut response = f.face(&f.other, &nonce, json!([1.0, 0.0, 0.0])).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let receipt: Value = response.take_json().await.unwrap();
    assert_eq!(receipt["status"], "ok");
    assert_eq!(receipt["user"], format!("{}/alice", f.owner));
    assert!(!receipt["token"].as_str().unwrap().is_empty());
    assert_eq!(
        f.face(&f.service, &nonce, json!([1.0, 0.0, 0.0]))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let nonce = f.face_nonce().await;
    assert_eq!(
        f.face(&f.service, &nonce, json!([0.0, 1.0, 0.0]))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        f.face(&f.other, &nonce, json!([1.0, 0.0, 0.0]))
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn faceid_rechecks_tenant_application_account_and_enrollment_before_authentication() {
    let f = Fixture::new().await;
    let face = FaceService::new(f.pool.clone());
    sqlx::query("UPDATE applications SET organization='other-tenant' WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(face.begin(&f.owner, "alice", Some(&f.app)).await.is_err());
    sqlx::query("UPDATE applications SET organization=$1 WHERE id=$2")
        .bind(&f.owner)
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    let nonce = f.face_nonce().await;
    sqlx::query("UPDATE applications SET organization='other-tenant' WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.face(&f.other, &nonce, json!([1.0, 0.0, 0.0]))
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
    sqlx::query("UPDATE organizations SET disable_signin=true WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.face(&f.other, &nonce, json!([1.0, 0.0, 0.0]))
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
    assert_ne!(
        f.face(&f.other, &nonce, json!([1.0, 0.0, 0.0]))
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    sqlx::query("UPDATE users SET is_forbidden=false WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    FaceService::new(f.other_pool.clone())
        .enroll(&f.owner, "alice", vec![0.0, 1.0, 0.0])
        .await
        .unwrap();
    assert!(
        face.finish(
            &f.owner,
            "alice",
            &FaceVerifyRequest {
                challenge: nonce,
                embedding: vec![1.0, 0.0, 0.0]
            }
        )
        .await
        .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn faceid_email_only_mfa_requires_the_same_browser_bound_delivery_proof() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE users SET mfa_email_enabled=true,email='alice@example.test' WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let nonce = f.face_nonce().await;
    let mut response = f.face(&f.service, &nonce, json!([1.0, 0.0, 0.0])).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let proof = proof_cookie(&response);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["mfa_required"], true);
    assert_eq!(body["mfa_types"], json!(["email"]));
    assert_eq!(body["token"], "");
    assert_eq!(
        Fixture::factor(&f.other, &proof, false, "email", "123456")
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE password_mfa_challenges SET code_hash=$1,code_method='email',receiver='alice@example.test',sent_at=clock_timestamp() WHERE secret_hash=$2")
        .bind(state::proof_hash(&format!("{proof}:123456"))).bind(state::proof_hash(&proof)).execute(&f.pool).await.unwrap();
    let mut result = Fixture::factor(&f.other, &proof, false, "email", "123456").await;
    assert_eq!(result.status_code, Some(StatusCode::OK));
    let body: Value = result.take_json().await.unwrap();
    assert_eq!(body["user"]["id"], f.user);
    assert!(!body["token"].as_str().unwrap().is_empty());
    assert_eq!(
        Fixture::factor(&f.service, &proof, false, "email", "123456")
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
