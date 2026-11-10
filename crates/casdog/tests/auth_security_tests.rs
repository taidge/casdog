//! Security regressions for real authentication services.
//!
//! Database tests require all migrations and an explicit disposable database:
//! PowerShell: $env:CASDOG_TEST_DATABASE_URL='postgres://postgres@127.0.0.1:55489/casdog_parity'
//! cargo test -p casdog --test auth_security_tests -- --ignored
//! Cargo runs these tests from crates/casdog so config/default.toml is available.
//! Each test uses unique organization/user IDs and cleans up even after assertion panics.

use std::{future::Future, sync::Once};

use casdog::{
    config::AppConfig,
    diesel_pool::{DieselPool, create_diesel_pool},
    models::User,
    services::{
        AuthService, PasswordService, UserService,
        auth_service::{LoginRequest, SignupRequest},
        mfa_service::MfaService,
    },
};
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

#[test]
fn casdoor_login_camel_case_and_username_aliases() {
    let req: LoginRequest = serde_json::from_value(json!({
        "owner":"org", "username":"alice", "password":"secret", "type":"password",
        "responseType":"code", "clientId":"client", "redirectUri":"https://example.test/callback",
        "codeChallenge":"challenge", "codeChallengeMethod":"S256", "captchaType":"Default",
        "captchaToken":"captcha", "mfaType":"app", "passcode":"123456", "autoSignin":true
    }))
    .unwrap();
    assert_eq!(req.name, "alice");
    assert_eq!(req.login_type.as_deref(), Some("password"));
    assert_eq!(req.response_type.as_deref(), Some("code"));
    assert_eq!(req.client_id.as_deref(), Some("client"));
    assert_eq!(
        req.redirect_uri.as_deref(),
        Some("https://example.test/callback")
    );
    assert_eq!(req.code_challenge.as_deref(), Some("challenge"));
    assert_eq!(req.code_challenge_method.as_deref(), Some("S256"));
    assert_eq!(req.captcha_type.as_deref(), Some("Default"));
    assert_eq!(req.captcha_token.as_deref(), Some("captcha"));
    assert_eq!(req.mfa_type.as_deref(), Some("app"));
    assert_eq!(req.auto_signin, Some(true));
    let snake: LoginRequest = serde_json::from_value(json!({
        "owner":"org", "name":"alice", "password":"secret", "client_id":"client", "mfa_type":"app"
    }))
    .unwrap();
    assert_eq!(snake.name, req.name);
    assert_eq!(snake.client_id, req.client_id);
    assert_eq!(snake.mfa_type, req.mfa_type);
}

#[test]
fn casdoor_signup_camel_case_aliases() {
    let req: SignupRequest = serde_json::from_value(json!({
        "owner":"org", "username":"alice", "password":"secret", "displayName":"Alice",
        "invitationCode":"invite", "captchaType":"Default", "captchaToken":"captcha"
    }))
    .unwrap();
    assert_eq!(req.name, "alice");
    assert_eq!(req.display_name, "Alice");
    assert_eq!(req.invitation_code.as_deref(), Some("invite"));
    assert_eq!(req.captcha_type.as_deref(), Some("Default"));
    assert_eq!(req.captcha_token.as_deref(), Some("captcha"));
}

#[tokio::test]
async fn kerberos_http_never_trusts_forged_identity_or_ticket() {
    let service = Service::new(
        Router::with_path("api/kerberos-login").get(casdog::handlers::login_compat::kerberos_login),
    );
    for (query, header, token) in [
        ("", "", ""),
        ("?owner=admin&username=admin&name=admin", "", ""),
        ("", "admin@EXAMPLE.COM", ""),
        (
            "?name=admin",
            "admin@EXAMPLE.COM",
            "Negotiate YWRtaW5ARVhBTVBMRS5DT00=",
        ),
        ("?username=admin", "", "Negotiate invalid"),
    ] {
        let mut response = TestClient::get(format!("http://localhost/api/kerberos-login{query}"))
            .add_header("X-Remote-User", header, true)
            .add_header("Remote-User", header, true)
            .add_header("Authorization", token, true)
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(
            response.headers().get("www-authenticate").unwrap(),
            "Negotiate"
        );
        let body = response.take_string().await.unwrap();
        assert!(!body.contains("\"token\""));
    }
}

struct TestIdentity(String);

#[async_trait]
impl Handler for TestIdentity {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.insert("user_id", self.0.clone());
        depot.insert("user_name", "alice".to_string());
        ctrl.call_next(req, depot, res).await;
    }
}

#[derive(Clone)]
struct Fixture {
    pg: PgPool,
    diesel: DieselPool,
    auth: AuthService,
    owner: String,
    user_id: String,
}

impl Fixture {
    async fn new() -> Self {
        static CONFIG: Once = Once::new();
        CONFIG.call_once(|| {
            AppConfig::load().expect("run from crates/casdog with config/default.toml");
        });
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").expect(
            "set CASDOG_TEST_DATABASE_URL to an explicitly migrated disposable PostgreSQL database",
        );
        let pg = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let owner = format!("auth-test-{}", Uuid::new_v4().simple());
        let user_id = Uuid::new_v4().to_string();
        let hash = PasswordService::hash_password("old-password", "bcrypt", None).unwrap();
        sqlx::query("INSERT INTO organizations (id, owner, name, display_name) VALUES ($1, $2, $2, 'Auth regression')")
            .bind(Uuid::new_v4().to_string()).bind(&owner).execute(&pg).await.unwrap();
        sqlx::query("INSERT INTO users (id, owner, name, display_name, password_hash, password_type, password_salt) VALUES ($1, $2, 'alice', 'Alice', $3, 'bcrypt', 'legacy-salt')")
            .bind(&user_id).bind(&owner).bind(hash).execute(&pg).await.unwrap();
        let auth = AuthService::new(UserService::new(diesel.clone())).with_pg_pool(pg.clone());
        Self {
            pg,
            diesel,
            auth,
            owner,
            user_id,
        }
    }

    fn request(&self, method: Option<&str>, code: Option<&str>) -> LoginRequest {
        serde_json::from_value(json!({
            "owner":self.owner, "name":"alice", "password":"old-password", "mfaType":method, "passcode":code
        })).unwrap()
    }

    async fn user(&self) -> User {
        sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(&self.user_id)
            .fetch_one(&self.pg)
            .await
            .unwrap()
    }

    async fn failures(&self) -> i32 {
        sqlx::query_scalar("SELECT signin_wrong_times FROM users WHERE id = $1")
            .bind(&self.user_id)
            .fetch_one(&self.pg)
            .await
            .unwrap()
    }

    async fn enroll_totp(&self) -> String {
        let (secret, _) = MfaService::initiate_totp_setup("alice", "test").unwrap();
        MfaService::save_mfa(&self.pg, &self.user_id, "totp", Some(&secret))
            .await
            .unwrap();
        MfaService::enable_mfa(&self.pg, &self.user_id, "totp")
            .await
            .unwrap();
        secret
    }

    async fn cleanup(&self) {
        sqlx::query("DELETE FROM verifications WHERE owner = $1")
            .bind(&self.owner)
            .execute(&self.pg)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE owner = $1")
            .bind(&self.owner)
            .execute(&self.pg)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE name = $1")
            .bind(&self.owner)
            .execute(&self.pg)
            .await
            .unwrap();
        self.pg.close().await;
    }
}

async fn isolated<F, Fut>(body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let fixture = Fixture::new().await;
    let result = tokio::spawn(body(fixture.clone())).await;
    fixture.cleanup().await;
    result.expect("authentication regression assertion failed (fixture cleaned up)");
}

fn totp_code(secret: &str) -> String {
    use totp_rs::{Algorithm, Secret, TOTP};
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret.into()).to_bytes().unwrap(),
        None,
        "alice".into(),
    )
    .unwrap()
    .generate_current()
    .unwrap()
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL; run --ignored"]
async fn login_requires_valid_enrolled_totp_before_token_issuance() {
    isolated(|f| async move {
        let secret = f.enroll_totp().await;
        // The enrollment record must be honored even if the legacy user flag is stale.
        sqlx::query("UPDATE users SET mfa_enabled = false WHERE id = $1")
            .bind(&f.user_id)
            .execute(&f.pg)
            .await
            .unwrap();
        let challenge = f
            .auth
            .login(&f.diesel, f.request(None, None))
            .await
            .unwrap();
        assert_eq!(challenge.mfa_required, Some(true));
        assert!(challenge.token.is_empty());
        assert_eq!(challenge.expires_in, 0);
        assert!(challenge.mfa_types.unwrap().iter().any(|m| m == "app"));
        assert!(
            f.auth
                .login(&f.diesel, f.request(Some("app"), Some("not-a-code")))
                .await
                .is_err()
        );
        assert_eq!(f.failures().await, 1);
        // Asking for the challenge again must not reset the failed second-factor count.
        assert!(
            f.auth
                .login(&f.diesel, f.request(None, None))
                .await
                .unwrap()
                .token
                .is_empty()
        );
        assert_eq!(f.failures().await, 1);
        let valid = f
            .auth
            .login(&f.diesel, f.request(Some("app"), Some(&totp_code(&secret))))
            .await
            .unwrap();
        assert!(!valid.token.is_empty());
        assert_ne!(valid.mfa_required, Some(true));
        assert_eq!(f.failures().await, 0);
        assert_eq!(f.auth.verify_token(&valid.token).unwrap().sub, f.user_id);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL; run --ignored"]
async fn repeated_invalid_mfa_locks_account_without_password_reset_bypass() {
    isolated(|f| async move {
        let secret = f.enroll_totp().await;
        for failures in 1..=5 {
            assert!(
                f.auth
                    .login(&f.diesel, f.request(Some("app"), Some("invalid")))
                    .await
                    .is_err()
            );
            assert_eq!(f.failures().await, failures);
        }
        assert!(
            f.auth
                .login(&f.diesel, f.request(Some("app"), Some(&totp_code(&secret))))
                .await
                .is_err()
        );
        assert_eq!(f.failures().await, 5);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL; run --ignored"]
async fn recovery_code_can_only_be_consumed_once_concurrently() {
    isolated(|f| async move {
        f.enroll_totp().await;
        sqlx::query("UPDATE user_mfa SET recovery_codes = $1 WHERE user_id = $2")
            .bind("[\"single-use\",\"spare-code\"]")
            .bind(&f.user_id)
            .execute(&f.pg)
            .await
            .unwrap();
        let (a, b) = tokio::join!(
            MfaService::verify_recovery_code(&f.pg, &f.user_id, "single-use"),
            MfaService::verify_recovery_code(&f.pg, &f.user_id, "single-use"),
        );
        assert_ne!(
            a.unwrap(),
            b.unwrap(),
            "exactly one simultaneous attempt must consume the code"
        );
        assert!(
            !MfaService::verify_recovery_code(&f.pg, &f.user_id, "single-use")
                .await
                .unwrap()
        );
        assert!(
            MfaService::verify_recovery_code(&f.pg, &f.user_id, "spare-code")
                .await
                .unwrap()
        );
        sqlx::query(
            "UPDATE user_mfa SET is_enabled = false, recovery_codes = $1 WHERE user_id = $2",
        )
        .bind("[\"disabled-code\"]")
        .bind(&f.user_id)
        .execute(&f.pg)
        .await
        .unwrap();
        assert!(
            !MfaService::verify_recovery_code(&f.pg, &f.user_id, "disabled-code")
                .await
                .unwrap()
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL; run --ignored"]
async fn imported_bcrypt_password_change_updates_algorithm_metadata() {
    isolated(|f| async move {
        assert!(
            f.auth
                .check_password(&f.user_id, "old-password")
                .await
                .unwrap()
        );
        assert!(!f.auth.check_password(&f.user_id, "wrong").await.unwrap());
        assert!(
            f.auth
                .set_password(&f.user_id, "wrong", "new-password")
                .await
                .is_err()
        );
        assert_eq!(f.user().await.password_type.as_deref(), Some("bcrypt"));
        sqlx::query("UPDATE users SET need_update_password = true WHERE id = $1")
            .bind(&f.user_id)
            .execute(&f.pg)
            .await
            .unwrap();
        f.auth
            .set_password(&f.user_id, "old-password", "new-password")
            .await
            .unwrap();
        let user = f.user().await;
        assert!(user.password_hash.starts_with("$argon2"));
        assert_eq!(user.password_type.as_deref(), Some("argon2"));
        assert!(user.password_salt.is_none());
        assert!(user.last_change_password_time.is_some());
        assert!(!user.need_update_password);
        assert!(
            f.auth
                .check_password(&f.user_id, "new-password")
                .await
                .unwrap()
        );
        assert!(
            !f.auth
                .check_password(&f.user_id, "old-password")
                .await
                .unwrap()
        );
        let mut login = f.request(None, None);
        login.password = "new-password".into();
        assert!(
            !f.auth
                .login(&f.diesel, login)
                .await
                .unwrap()
                .token
                .is_empty()
        );
    })
    .await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL; run --ignored"]
async fn email_mfa_codes_are_bound_to_account_expiry_and_single_use() {
    isolated(|f| async move {
        use casdog::handlers::password_mfa;
        use casdog::services::social_state_service::proof_hash;
        sqlx::query("UPDATE users SET mfa_enabled=true,mfa_email_enabled=true,mfa_phone_enabled=true,email='alice@example.test',phone='+15555550123' WHERE id=$1")
            .bind(&f.user_id).execute(&f.pg).await.unwrap();
        for (code,user_id,minutes) in [("123456",f.user_id.as_str(),0),("234567","another-user",0),("345678",f.user_id.as_str(),10)] {
            sqlx::query("INSERT INTO verifications(id,owner,name,type,user_id,provider,receiver,code,created_at) VALUES($1,$2,'test','email',$3,'test','alice@example.test',$4,NOW()-($5*INTERVAL '1 minute'))")
                .bind(Uuid::new_v4().to_string()).bind(&f.owner).bind(user_id).bind(code).bind(minutes as f64).execute(&f.pg).await.unwrap();
        }
        // Legacy generic verification rows cannot bypass a password-bound ceremony.
        assert!(f.auth.login(&f.diesel,f.request(Some("email"),Some("123456"))).await.is_err());
        assert!(f.auth.login(&f.diesel,f.request(Some("sms"),Some("123456"))).await.is_err());
        let service=Service::new(Router::new()
            .push(Router::with_path("api/login").post(password_mfa::login))
            .push(Router::with_path("api/auth/password/session").post(password_mfa::consume_password_session)))
            .hoop(salvo::affix_state::AffixList::new().inject(f.pg.clone()).inject(f.diesel.clone()));
        let mut begin=TestClient::post("http://localhost/api/login").add_header("Origin","http://127.0.0.1:8000",true)
            .json(&json!({"owner":f.owner,"name":"alice","password":"old-password"})).send(&service).await;
        assert_eq!(begin.status_code,Some(StatusCode::OK));
        let proof=begin.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().strip_prefix("casdog_password_mfa=").unwrap().to_owned();
        let body:serde_json::Value=begin.take_json().await.unwrap();assert_eq!(body["token"],"");assert_eq!(body["mfa_required"],true);
        async fn verify(service:&Service,proof:&str,code:&str)->Response {
            TestClient::post("http://localhost/api/auth/password/session").add_header("Origin","http://127.0.0.1:8000",true)
                .add_header("Cookie",format!("casdog_password_mfa={proof}"),true).json(&json!({"mfaType":"email","passcode":code})).send(service).await
        }
        for code in ["123456","234567"] {assert_eq!(verify(&service,&proof,code).await.status_code,Some(StatusCode::UNAUTHORIZED));}
        sqlx::query("UPDATE password_mfa_challenges SET code_hash=$1,code_method='email',receiver='alice@example.test',sent_at=clock_timestamp()-INTERVAL '10 minutes' WHERE secret_hash=$2")
            .bind(proof_hash(&format!("{proof}:345678"))).bind(proof_hash(&proof)).execute(&f.pg).await.unwrap();
        assert_eq!(verify(&service,&proof,"345678").await.status_code,Some(StatusCode::UNAUTHORIZED));
        sqlx::query("UPDATE password_mfa_challenges SET code_hash=$1,sent_at=clock_timestamp() WHERE secret_hash=$2")
            .bind(proof_hash(&format!("{proof}:456789"))).bind(proof_hash(&proof)).execute(&f.pg).await.unwrap();
        let (a,b)=tokio::join!(verify(&service,&proof,"456789"),verify(&service,&proof,"456789"));
        assert_eq!([a.status_code,b.status_code].iter().filter(|s|**s==Some(StatusCode::OK)).count(),1);
        assert_eq!([a.status_code,b.status_code].iter().filter(|s|**s==Some(StatusCode::UNAUTHORIZED)).count(),1);
        assert_eq!(verify(&service,&proof,"456789").await.status_code,Some(StatusCode::UNAUTHORIZED));
    }).await;
}

#[tokio::test]
#[ignore = "requires migrated PostgreSQL and CASDOG_TEST_DATABASE_URL; run --ignored"]
async fn mfa_http_enrollment_requires_proof_and_json_delete_removes_challenge() {
    isolated(|f| async move {
        use casdog::handlers::mfa;
        let service = Service::new(
            Router::with_path("api/mfa")
                .hoop(TestIdentity(f.user_id.clone()))
                .push(Router::with_path("setup").post(mfa::initiate_mfa_setup))
                .push(Router::with_path("verify").post(mfa::verify_mfa_setup))
                .push(Router::with_path("enable").post(mfa::enable_mfa))
                .push(Router::with_path("delete").post(mfa::delete_mfa)),
        )
        .hoop(salvo::affix_state::AffixList::new().inject(f.pg.clone()));
        let mut setup = TestClient::post("http://localhost/api/mfa/setup")
            .send(&service)
            .await;
        assert_eq!(setup.status_code, Some(StatusCode::OK));
        let setup: serde_json::Value = setup.take_json().await.unwrap();
        let secret = setup["secret"].as_str().unwrap().to_string();
        assert!(setup["qr_url"].as_str().unwrap().starts_with("otpauth://"));
        assert!(!MfaService::is_mfa_enabled(&f.pg, &f.user_id).await.unwrap());
        let enable = TestClient::post("http://localhost/api/mfa/enable")
            .send(&service)
            .await;
        assert_eq!(enable.status_code, Some(StatusCode::BAD_REQUEST));
        let mut wrong = TestClient::post("http://localhost/api/mfa/verify")
            .json(&json!({"code":"not-a-code", "mfa_type":"totp"}))
            .send(&service)
            .await;
        assert_eq!(wrong.status_code, Some(StatusCode::OK));
        assert_eq!(
            wrong.take_json::<serde_json::Value>().await.unwrap()["success"],
            false
        );
        assert!(!MfaService::is_mfa_enabled(&f.pg, &f.user_id).await.unwrap());
        assert!(!f.user().await.mfa_enabled);
        let mut valid = TestClient::post("http://localhost/api/mfa/verify")
            .json(&json!({"code":totp_code(&secret), "mfa_type":"totp"}))
            .send(&service)
            .await;
        assert_eq!(valid.status_code, Some(StatusCode::OK));
        let verified: serde_json::Value = valid.take_json().await.unwrap();
        assert_eq!(verified["success"], true);
        assert!(!verified["recovery_codes"].as_array().unwrap().is_empty());
        assert!(MfaService::is_mfa_enabled(&f.pg, &f.user_id).await.unwrap());
        assert!(f.user().await.mfa_enabled);
        assert_eq!(
            TestClient::post("http://localhost/api/mfa/enable")
                .send(&service)
                .await
                .status_code,
            Some(StatusCode::OK)
        );
        let repeated = TestClient::post("http://localhost/api/mfa/setup")
            .send(&service)
            .await;
        assert_eq!(repeated.status_code, Some(StatusCode::CONFLICT));
        assert_eq!(
            MfaService::get_user_mfa(&f.pg, &f.user_id, "totp")
                .await
                .unwrap()
                .unwrap()
                .secret
                .as_deref(),
            Some(secret.as_str())
        );
        assert!(
            f.auth
                .login(&f.diesel, f.request(None, None))
                .await
                .unwrap()
                .token
                .is_empty()
        );
        let deleted = TestClient::post("http://localhost/api/mfa/delete")
            .json(&json!({"mfa_type":"totp"}))
            .send(&service)
            .await;
        assert_eq!(deleted.status_code, Some(StatusCode::OK));
        assert!(!MfaService::is_mfa_enabled(&f.pg, &f.user_id).await.unwrap());
        assert!(!f.user().await.mfa_enabled);
        let login = f
            .auth
            .login(&f.diesel, f.request(None, None))
            .await
            .unwrap();
        assert!(!login.token.is_empty());
        assert_ne!(login.mfa_required, Some(true));
    })
    .await;
}

#[test]
fn casdoor_authform_username_and_name_have_distinct_meanings() {
    let upstream = json!({
        "organization":"org", "username":"alice-login", "name":"Alice Display",
        "password":"secret", "clientId":"client", "captchaType":"Default",
        "captchaToken":"captcha", "mfaType":"app", "invitationCode":"invite"
    });
    let login: LoginRequest = serde_json::from_value(upstream.clone()).unwrap();
    assert_eq!(login.owner, "org");
    assert_eq!(login.name, "alice-login");
    assert_eq!(login.client_id.as_deref(), Some("client"));
    assert_eq!(login.mfa_type.as_deref(), Some("app"));
    let signup: SignupRequest = serde_json::from_value(upstream).unwrap();
    assert_eq!(signup.owner, "org");
    assert_eq!(signup.name, "alice-login");
    assert_eq!(signup.display_name, "Alice Display");
    assert_eq!(signup.invitation_code.as_deref(), Some("invite"));
}

#[test]
fn native_auth_request_identity_and_display_name_remain_supported() {
    let native =
        json!({"owner":"org", "name":"alice", "display_name":"Alice", "password":"secret"});
    let login: LoginRequest = serde_json::from_value(native.clone()).unwrap();
    let signup: SignupRequest = serde_json::from_value(native).unwrap();
    assert_eq!(login.owner, "org");
    assert_eq!(login.name, "alice");
    assert_eq!(signup.name, "alice");
    assert_eq!(signup.display_name, "Alice");
    // Explicit native display_name is retained when a client sends both naming schemes.
    let mixed: SignupRequest = serde_json::from_value(json!({
        "owner":"org", "organization":"other-org", "username":"login-id", "name":"Upstream display",
        "displayName":"Explicit display", "password":"secret"
    }))
    .unwrap();
    assert_eq!(mixed.owner, "org");
    assert_eq!(mixed.name, "login-id");
    assert_eq!(mixed.display_name, "Explicit display");
}

#[test]
fn auth_request_required_and_typed_fields_are_still_validated() {
    for invalid in [
        json!({"name":"alice", "password":"secret"}),
        json!({"owner":"org", "password":"secret"}),
        json!({"owner":"org", "name":"alice"}),
        json!({"organization":"org", "username":42, "name":"Display", "password":"secret"}),
    ] {
        assert!(serde_json::from_value::<LoginRequest>(invalid.clone()).is_err());
        assert!(serde_json::from_value::<SignupRequest>(invalid).is_err());
    }
    assert!(
        serde_json::from_value::<SignupRequest>(json!({
            "owner":"org", "name":"alice", "password":"secret"
        }))
        .is_err(),
        "native signup still requires an explicit display name"
    );
    assert!(
        serde_json::from_value::<SignupRequest>(json!({
            "organization":"org", "username":"alice", "password":"secret"
        }))
        .is_err(),
        "Casdoor signup still requires its name/display field"
    );
}
