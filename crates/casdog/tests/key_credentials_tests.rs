use base64::{Engine, engine::general_purpose::STANDARD};
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    hoops::{AutoSigninFilter, JwtAuth, OptionalJwtAuth, authz::Principal},
    models::{User, UserResponse},
    services::{
        AuthService, UserService,
        key_credentials_service::{self as credentials, CredentialIdentity, CredentialSource},
    },
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

#[handler]
async fn reached() -> &'static str {
    "reached"
}
#[test]
fn api_credential_sources_are_exclusive_complete_and_never_ambiguous() {
    for query in [
        "accessKey=a",
        "accessSecret=b",
        "accessKey=&accessSecret=b",
        "clientId=a",
        "accessToken=",
        "accessKey=a&accessSecret=b&clientId=c&clientSecret=d",
        "accessKey=a&accessKey=b&accessSecret=c",
    ] {
        assert!(
            credentials::source(
                &TestClient::get(format!("http://localhost/api/products?{query}")).build()
            )
            .is_err(),
            "{query}"
        );
    }
    assert!(
        matches!(credentials::source(&TestClient::get("http://localhost/api/products?accessKey=a&accessSecret=b").build()).unwrap(),Some(CredentialSource::AccessKey(a,b)) if a=="a" && b=="b")
    );
    let request = TestClient::get("http://localhost/api/products")
        .add_header(
            "Authorization",
            format!("Basic {}", STANDARD.encode("key:secret:with:colons")),
            true,
        )
        .build();
    assert!(
        matches!(credentials::source(&request).unwrap(),Some(CredentialSource::Basic(a,b)) if a=="key" && b=="secret:with:colons")
    );
    for header in ["Basic !!!", "Basic eA==", "Bearer ", "Negotiate x"] {
        assert!(
            credentials::source(
                &TestClient::get("http://localhost/api/products")
                    .add_header("Authorization", header, true)
                    .build()
            )
            .is_err()
        );
    }
    assert!(
        credentials::source(
            &TestClient::get("http://localhost/api/products?accessKey=a&accessSecret=b")
                .add_header("Authorization", "Bearer good-looking-token", true)
                .build()
        )
        .is_err()
    );
}
#[tokio::test]
async fn required_and_optional_hoops_fail_closed_for_explicit_invalid_credentials() {
    for service in [
        Service::new(
            Router::with_path("api/products")
                .hoop(OptionalJwtAuth)
                .get(reached),
        ),
        Service::new(
            Router::with_path("api/products")
                .hoop(AutoSigninFilter)
                .get(reached),
        ),
    ] {
        assert_eq!(
            TestClient::get("http://localhost/api/products")
                .send(&service)
                .await
                .status_code,
            Some(StatusCode::OK)
        );
        for query in [
            "accessKey=invalid&accessSecret=bad",
            "accessKey=partial",
            "accessToken=invalid",
        ] {
            assert_eq!(
                TestClient::get(format!("http://localhost/api/products?{query}"))
                    .send(&service)
                    .await
                    .status_code,
                Some(StatusCode::UNAUTHORIZED)
            );
        }
    }
    let required = Service::new(Router::with_path("api/products").hoop(JwtAuth).get(reached));
    assert_eq!(
        TestClient::get("http://localhost/api/products")
            .send(&required)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    // Kind, rather than a user ID naming convention, separates interactive
    // users from applications. Optional machine-message/payment routes remain
    // available for their own handler-level authorization.
    for (identity, interactive) in [
        (
            CredentialIdentity::Application {
                principal: Principal {
                    application_identity: true,
                    id: "short-legacy-id".into(),
                    owner: "tenant".into(),
                    name: "service".into(),
                    admin: true,
                },
                application_id: "legacy".into(),
                trusted_static: true,
            },
            StatusCode::FORBIDDEN,
        ),
        (
            CredentialIdentity::User(Principal {
                application_identity: false,
                id: "app:legacy".into(),
                owner: "tenant".into(),
                name: "real-user".into(),
                admin: false,
            }),
            StatusCode::OK,
        ),
    ] {
        let optional = Service::new(
            Router::with_path("api")
                .hoop(salvo::affix_state::AffixList::new().inject(identity.clone()))
                .hoop(OptionalJwtAuth)
                .push(Router::with_path("verify-code").get(reached))
                .push(Router::with_path("send-verification-code").get(reached))
                .push(Router::with_path("send-email").get(reached))
                .push(Router::with_path("notify-payment").get(reached)),
        );
        for path in ["verify-code", "send-verification-code"] {
            assert_eq!(
                TestClient::get(format!("http://localhost/api/{path}"))
                    .send(&optional)
                    .await
                    .status_code,
                Some(interactive)
            );
        }
        for path in ["send-email", "notify-payment"] {
            assert_eq!(
                TestClient::get(format!("http://localhost/api/{path}"))
                    .send(&optional)
                    .await
                    .status_code,
                Some(StatusCode::OK)
            );
        }
        let saml = Service::new(
            Router::with_path("api/saml/redirect")
                .hoop(salvo::affix_state::AffixList::new().inject(identity))
                .hoop(AutoSigninFilter)
                .get(reached),
        );
        assert_eq!(
            TestClient::get("http://localhost/api/saml/redirect")
                .send(&saml)
                .await
                .status_code,
            Some(interactive)
        );
    }
}
struct Fixture {
    pool: PgPool,
    service: Service,
    other: Service,
    owner: String,
    foreign: String,
    admin: Principal,
    admin_token: String,
    user: String,
    foreign_user: String,
    app: String,
    product: String,
    foreign_product: String,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url =
            std::env::var("CASDOG_TEST_DATABASE_URL").expect("CASDOG_TEST_DATABASE_URL required");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let id = || uuid::Uuid::new_v4().to_string();
        let owner = format!("key-{}", uuid::Uuid::new_v4().simple());
        let foreign = format!("key-other-{}", uuid::Uuid::new_v4().simple());
        for org in [&owner, &foreign] {
            sqlx::query(
                "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
            )
            .bind(id())
            .bind(org)
            .execute(&pool)
            .await
            .unwrap();
        }
        let admin = Principal {
            application_identity: false,
            id: id(),
            owner: owner.clone(),
            name: "admin".into(),
            admin: true,
        };
        let user = id();
        let foreign_user = id();
        for (uid, org, name, is_admin) in [
            (&admin.id, &owner, "admin", true),
            (&user, &owner, "alice", false),
            (&foreign_user, &foreign, "alice", false),
        ] {
            sqlx::query("INSERT INTO users(id,owner,name,password_hash,display_name,is_admin) VALUES($1,$2,$3,'unused',$3,$4)").bind(uid).bind(org).bind(name).bind(is_admin).execute(&pool).await.unwrap();
        }
        let app = id();
        sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris) VALUES($1,$2,'portal','Portal',$2,$1,'client-secret','https://example.test/callback')").bind(&app).bind(&owner).execute(&pool).await.unwrap();
        let product = id();
        let foreign_product = id();
        for (pid, org) in [(&product, &owner), (&foreign_product, &foreign)] {
            sqlx::query(
                "INSERT INTO products(id,owner,name,display_name) VALUES($1,$2,'item','Item')",
            )
            .bind(pid)
            .bind(org)
            .execute(&pool)
            .await
            .unwrap();
        }
        let admin_user: User = sqlx::query_as("SELECT * FROM users WHERE id=$1")
            .bind(&admin.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let admin_token = AuthService::new(UserService::new(diesel.clone()))
            .generate_token(&UserResponse::from(admin_user))
            .unwrap();
        let make = || {
            Service::new(casdog::routes::create_router()).hoop(
                salvo::affix_state::AffixList::new()
                    .inject(pool.clone())
                    .inject(diesel.clone()),
            )
        };
        let service = make();
        let other = make();
        Self {
            pool,
            service,
            other,
            owner,
            foreign,
            admin,
            admin_token,
            user,
            foreign_user,
            app,
            product,
            foreign_product,
        }
    }
    async fn key(&self, name: &str, scope: &str, user: &str, app: &str) -> Value {
        let body = json!({"owner":self.owner,"name":name,"type":scope,"organization":self.owner,"user":user,"application":app,"state":"Active"});
        let mut response = TestClient::post("http://localhost/api/add-key")
            .add_header(
                "Authorization",
                format!("Bearer {}", self.admin_token),
                true,
            )
            .json(&body)
            .send(&self.service)
            .await;
        let status = response.status_code;
        let result: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{result}");
        assert_eq!(result["data"], true);
        let mut response = TestClient::get(format!(
            "http://localhost/api/get-key?id={}/{name}",
            self.owner
        ))
        .add_header(
            "Authorization",
            format!("Bearer {}", self.admin_token),
            true,
        )
        .send(&self.service)
        .await;
        let status = response.status_code;
        let result: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{result}");
        assert!(!result["data"]["accessSecret"].as_str().unwrap().is_empty());
        assert_ne!(result["data"]["accessSecret"], "***");
        result["data"].clone()
    }
    async fn update(&self, name: &str, changes: Value) {
        let mut body = changes;
        body["owner"] = json!(self.owner);
        body["name"] = json!(name);
        let mut response = TestClient::post("http://localhost/api/update-key")
            .add_header(
                "Authorization",
                format!("Bearer {}", self.admin_token),
                true,
            )
            .json(&body)
            .send(&self.service)
            .await;
        let status = response.status_code;
        let result: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{result}");
    }
    fn query(&self, path: &str, key: &Value) -> String {
        format!(
            "http://localhost{path}{}accessKey={}&accessSecret={}",
            if path.contains('?') { "&" } else { "?" },
            key["accessKey"].as_str().unwrap(),
            key["accessSecret"].as_str().unwrap()
        )
    }
    fn source(&self, key: &Value) -> CredentialSource {
        CredentialSource::AccessKey(
            key["accessKey"].as_str().unwrap().into(),
            key["accessSecret"].as_str().unwrap().into(),
        )
    }
    async fn cleanup(self) {
        sqlx::query("DELETE FROM casbin_rule WHERE v0=$1")
            .bind(format!("{}/app/{}/portal", self.owner, self.owner))
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM applications WHERE organization=$1 OR organization=$2 OR id=$3")
            .bind(&self.owner)
            .bind(&self.foreign)
            .bind(&self.app)
            .execute(&self.pool)
            .await
            .unwrap();
        for table in ["casdoor_objects", "products", "applications", "users"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1 OR owner=$2"))
                .bind(&self.owner)
                .bind(&self.foreign)
                .execute(&self.pool)
                .await
                .unwrap();
        }
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
#[ignore = "requires CASDOG_TEST_DATABASE_URL migrated through 031"]
async fn key_crud_generated_user_credentials_authenticate_real_protected_apis_and_mask_lists() {
    let f = Fixture::new().await;
    let key = f.key("alice-key", "User", "alice", "").await;
    let path = format!("/api/users/{}", f.user);
    assert_eq!(
        TestClient::get(f.query(&path, &key))
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let header = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{}:{}",
            key["accessKey"].as_str().unwrap(),
            key["accessSecret"].as_str().unwrap()
        ))
    );
    assert_eq!(
        TestClient::get(format!("http://localhost{path}"))
            .add_header("Authorization", header, true)
            .send(&f.other)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        TestClient::get(f.query(&format!("/api/users/{}", f.foreign_user), &key))
            .send(&f.other)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        TestClient::get(f.query(&format!("/api/get-key?id={}/alice-key", f.owner), &key))
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let mut response = TestClient::get(format!("http://localhost/api/get-keys?owner={}", f.owner))
        .add_header("Authorization", format!("Bearer {}", f.admin_token), true)
        .send(&f.service)
        .await;
    let listed: Value = response.take_json().await.unwrap();
    assert_eq!(listed["data"][0]["accessSecret"], "***");
    for kind in ["General", "Organization"] {
        let bound = f.key(&format!("bound-{kind}"), kind, "alice", "").await;
        assert_eq!(
            TestClient::get(f.query(&path, &bound))
                .send(&f.service)
                .await
                .status_code,
            Some(StatusCode::OK)
        );
        let unbound = f.key(&format!("unbound-{kind}"), kind, "", "").await;
        assert_eq!(
            TestClient::get(f.query(&path, &unbound))
                .send(&f.service)
                .await
                .status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL migrated through 031"]
async fn key_state_expiry_deletion_and_current_subject_org_revocation_apply_across_instances() {
    let f = Fixture::new().await;
    let key = f.key("revoke", "User", "alice", "").await;
    let endpoint = f.query(&format!("/api/users/{}", f.user), &key);
    f.update("revoke", json!({"state":"Inactive"})).await;
    assert_eq!(
        TestClient::get(&endpoint).send(&f.other).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.update(
        "revoke",
        json!({"state":"Active","expireTime":"2000-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(
        TestClient::get(&endpoint).send(&f.other).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.update("revoke", json!({"expireTime":""})).await;
    assert_eq!(
        TestClient::get(&endpoint).send(&f.other).await.status_code,
        Some(StatusCode::OK)
    );
    sqlx::query("UPDATE users SET is_forbidden=true WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        TestClient::get(&endpoint).send(&f.other).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE users SET is_forbidden=false WHERE id=$1")
        .bind(&f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE organizations SET disable_signin=true WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        TestClient::get(&endpoint).send(&f.other).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE organizations SET disable_signin=false WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut response = TestClient::post("http://localhost/api/delete-key")
        .add_header("Authorization", format!("Bearer {}", f.admin_token), true)
        .json(&json!({"owner":f.owner,"name":"revoke"}))
        .send(&f.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(response.take_json::<Value>().await.unwrap()["data"], true);
    assert_eq!(
        TestClient::get(&endpoint).send(&f.other).await.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL migrated through 031"]
async fn application_keys_static_provenance_inherits_only_tenant_admin_and_never_user_session() {
    let f = Fixture::new().await;
    credentials::mark_static_application(&f.pool, &f.app, &f.admin)
        .await
        .unwrap();
    credentials::trust_application(&f.pool, &f.app, &f.admin)
        .await
        .unwrap();
    credentials::trust_application(&f.pool, &f.app, &f.admin)
        .await
        .unwrap();
    let key = f
        .key("app-key", "Application", "", &format!("{}/portal", f.owner))
        .await;
    let identity = credentials::authenticate(&f.pool, &f.source(&key))
        .await
        .unwrap();
    assert!(matches!(
        identity,
        CredentialIdentity::Application {
            trusted_static: true,
            ..
        }
    ));
    assert!(identity.principal().is_application());
    assert!(identity.principal().admin);
    assert!(!identity.principal().global_admin());
    for path in [
        format!("/api/products/{}", f.product),
        format!("/api/users/{}", f.user),
    ] {
        assert_eq!(
            TestClient::get(f.query(&path, &key))
                .send(&f.other)
                .await
                .status_code,
            Some(StatusCode::OK)
        );
    }
    assert_eq!(
        TestClient::get(f.query(&format!("/api/users/{}", f.foreign_user), &key))
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    for path in [
        "/api/get-account",
        "/api/get-mcp-access-token",
        "/api/get-global-users",
    ] {
        assert_eq!(
            TestClient::get(f.query(path, &key))
                .send(&f.service)
                .await
                .status_code,
            Some(StatusCode::FORBIDDEN),
            "{path}"
        );
    }
    assert_eq!(
        TestClient::post(f.query("/api/mfa/setup", &key))
            .json(&json!({}))
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        TestClient::get(f.query(&format!("/api/saml/redirect/{}/portal", f.owner), &key))
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        TestClient::post(f.query("/api/verify-code", &key))
            .json(&json!({"code":"123456"}))
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        TestClient::post(f.query("/api/set-password", &key))
            .json(&json!({}))
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert!(
        credentials::trust_application(&f.pool, &f.app, identity.principal())
            .await
            .is_err()
    );
    let client = CredentialSource::Client(f.app.clone(), "client-secret".into());
    assert!(
        credentials::authenticate(&f.pool, &client)
            .await
            .unwrap()
            .principal()
            .admin
    );
    sqlx::query("UPDATE applications SET organization=$2,owner=$3 WHERE id=$1")
        .bind(&f.app)
        .bind(&f.foreign)
        .bind(format!("managed-{}", f.owner))
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        credentials::authenticate(&f.pool, &f.source(&key))
            .await
            .is_err()
    );
    assert!(
        !credentials::authenticate(&f.pool, &client)
            .await
            .unwrap()
            .principal()
            .admin
    );
    assert!(
        credentials::trust_application(&f.pool, &f.app, &f.admin)
            .await
            .is_err()
    );
    sqlx::query("UPDATE users SET is_admin=true WHERE id=$1")
        .bind(&f.foreign_user)
        .execute(&f.pool)
        .await
        .unwrap();
    let new_admin = Principal {
        application_identity: false,
        id: f.foreign_user.clone(),
        owner: f.foreign.clone(),
        name: "alice".into(),
        admin: true,
    };
    credentials::trust_application(&f.pool, &f.app, &new_admin)
        .await
        .unwrap();
    let rebound = credentials::authenticate(&f.pool, &client).await.unwrap();
    assert!(rebound.principal().admin);
    assert_eq!(rebound.principal().owner, f.foreign);
    assert_eq!(
        TestClient::get(format!(
            "http://localhost/api/applications/{}?clientId={}&clientSecret=client-secret",
            f.app, f.app
        ))
        .send(&f.service)
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    // A global service identity requires a separate explicit review by the
    // real seeded built-in administrator; it still cannot mint a user session.
    sqlx::query("UPDATE applications SET organization='built-in' WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        !credentials::authenticate(&f.pool, &client)
            .await
            .unwrap()
            .principal()
            .global_admin()
    );
    let root = Principal {
        application_identity: false,
        id: "user_admin".into(),
        owner: "built-in".into(),
        name: "admin".into(),
        admin: true,
    };
    credentials::trust_application(&f.pool, &f.app, &root)
        .await
        .unwrap();
    assert!(
        credentials::authenticate(&f.pool, &client)
            .await
            .unwrap()
            .principal()
            .global_admin()
    );
    assert_eq!(
        TestClient::get(format!(
            "http://localhost/api/get-global-users?clientId={}&clientSecret=client-secret",
            f.app
        ))
        .send(&f.service)
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        TestClient::get(format!(
            "http://localhost/api/get-account?clientId={}&clientSecret=client-secret",
            f.app
        ))
        .send(&f.service)
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL migrated through 031"]
async fn unverified_and_dynamic_applications_require_current_scoped_policy_and_cannot_upgrade_or_read_credentials()
 {
    let f = Fixture::new().await;
    let key = f.key("app-key", "Application", "", "portal").await;
    let identity = credentials::authenticate(&f.pool, &f.source(&key))
        .await
        .unwrap();
    assert!(!identity.principal().admin);
    let path = format!("/api/products/{}", f.product);
    assert_eq!(
        TestClient::get(f.query(&path, &key))
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let subject = format!("{}/app/{}/portal", f.owner, f.owner);
    for (path, method) in [
        (path.as_str(), "GET"),
        ("/api/products", "GET"),
        (&format!("/api/products/{}", f.foreign_product), "GET"),
        (&format!("/api/users/{}", f.user), "PUT"),
        (&format!("/api/users/{}", f.user), "GET"),
        (&format!("/api/applications/{}", f.app), "GET"),
    ] {
        sqlx::query("INSERT INTO casbin_rule(ptype,v0,v1,v2) VALUES('p',$1,$2,$3)")
            .bind(&subject)
            .bind(path)
            .bind(method)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    assert_eq!(
        TestClient::get(f.query(&path, &key))
            .send(&f.other)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let mut response = TestClient::get(f.query("/api/products", &key))
        .send(&f.other)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let result: Value = response.take_json().await.unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(result["data"][0]["owner"], f.owner);
    assert_eq!(
        TestClient::get(f.query(&format!("/api/products/{}", f.foreign_product), &key))
            .send(&f.other)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    for path in [
        format!("/api/users/{}", f.user),
        format!("/api/applications/{}", f.app),
    ] {
        assert_eq!(
            TestClient::get(f.query(&path, &key))
                .send(&f.service)
                .await
                .status_code,
            Some(StatusCode::FORBIDDEN)
        );
    }
    for body in [
        json!({"is_admin":true}),
        json!({"access_key":"steal","access_secret":"secret"}),
        json!({"password":"takeover"}),
        json!({"provider_ids":{"oauth:fake":"attacker"}}),
    ] {
        assert_eq!(
            TestClient::put(f.query(&format!("/api/users/{}", f.user), &key))
                .json(&body)
                .send(&f.service)
                .await
                .status_code,
            Some(StatusCode::FORBIDDEN)
        );
    }
    assert_eq!(
        TestClient::put(f.query(&format!("/api/users/{}", f.user), &key))
            .json(&json!({"display_name":"Service-updated profile"}))
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    // Historical provenance stays unverified until an explicit real-admin audit.
    sqlx::query("INSERT INTO application_credential_origins(application_id,origin,application_owner,organization) VALUES($1,'unverified',$2,$2)")
        .bind(&f.app).bind(&f.owner).execute(&f.pool).await.unwrap();
    credentials::mark_static_application(&f.pool, &f.app, &f.admin)
        .await
        .unwrap();
    assert!(
        !credentials::authenticate(&f.pool, &f.source(&key))
            .await
            .unwrap()
            .principal()
            .admin
    );
    let forged_admin = Principal {
        application_identity: false,
        id: f.user.clone(),
        owner: f.owner.clone(),
        name: "alice".into(),
        admin: true,
    };
    assert!(
        credentials::trust_application(&f.pool, &f.app, &forged_admin)
            .await
            .is_err()
    );
    credentials::trust_application(&f.pool, &f.app, &f.admin)
        .await
        .unwrap();
    assert!(
        credentials::authenticate(&f.pool, &f.source(&key))
            .await
            .unwrap()
            .principal()
            .admin
    );
    credentials::mark_dynamic_application(&f.pool, &f.app)
        .await
        .unwrap();
    assert!(
        credentials::trust_application(&f.pool, &f.app, &f.admin)
            .await
            .is_err()
    );
    credentials::mark_static_application(&f.pool, &f.app, &f.admin)
        .await
        .unwrap();
    assert!(
        !credentials::authenticate(&f.pool, &f.source(&key))
            .await
            .unwrap()
            .principal()
            .admin
    );
    sqlx::query("DELETE FROM casbin_rule WHERE v0=$1 AND v1=$2")
        .bind(&subject)
        .bind(&path)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        TestClient::get(f.query(&path, &key))
            .send(&f.other)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL migrated through 031"]
async fn legacy_user_keys_client_basic_and_bad_explicit_sources_never_fall_back() {
    let f = Fixture::new().await;
    let access = format!("legacy-{}", uuid::Uuid::new_v4().simple());
    sqlx::query("UPDATE users SET access_key=$2,access_secret='legacy-secret' WHERE id=$1")
        .bind(&f.user)
        .bind(&access)
        .execute(&f.pool)
        .await
        .unwrap();
    let identity = credentials::authenticate(
        &f.pool,
        &CredentialSource::AccessKey(access.clone(), "legacy-secret".into()),
    )
    .await
    .unwrap();
    assert_eq!(identity.principal().id, f.user);
    assert!(
        credentials::authenticate(
            &f.pool,
            &CredentialSource::AccessKey(access.clone(), "bad-secret".into())
        )
        .await
        .is_err()
    );
    let legacy_id = format!(
        "app:legacy-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    sqlx::query("UPDATE users SET id=$2 WHERE id=$1")
        .bind(&f.user)
        .bind(&legacy_id)
        .execute(&f.pool)
        .await
        .unwrap();
    let real_user = credentials::authenticate(
        &f.pool,
        &CredentialSource::AccessKey(access.clone(), "legacy-secret".into()),
    )
    .await
    .unwrap();
    assert!(!real_user.principal().is_application());
    assert_eq!(
        TestClient::get(format!(
            "http://localhost/api/users/{legacy_id}?accessKey={access}&accessSecret=legacy-secret"
        ))
        .send(&f.service)
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    let bound = f.key("legacy-user-key", "User", "alice", "").await;
    assert_eq!(
        TestClient::get(f.query(&format!("/api/users/{legacy_id}"), &bound))
            .send(&f.other)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let path = format!(
        "http://localhost/api/users/{}?accessKey=bad&accessSecret=bad",
        f.user
    );
    assert_eq!(
        TestClient::get(path)
            .add_header("Authorization", format!("Bearer {}", f.admin_token), true)
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        TestClient::get(format!("http://localhost/api/products/{}", f.product))
            .add_header(
                "Authorization",
                format!("Basic {}", STANDARD.encode(format!("{}:wrong", f.app))),
                true
            )
            .send(&f.service)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    let app_identity = credentials::authenticate(
        &f.pool,
        &CredentialSource::Basic(f.app.clone(), "client-secret".into()),
    )
    .await
    .unwrap();
    assert!(app_identity.principal().is_application());
    assert!(!app_identity.principal().admin);
    f.cleanup().await;
}
