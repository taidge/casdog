//! Real database authorization regressions. Run ignored tests with an explicitly
//! configured disposable CASDOG_TEST_DATABASE_URL after applying migrations.
use casdog::{config::AppConfig, diesel_pool::create_diesel_pool};
use jsonwebtoken::{EncodingKey, Header, encode};
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

#[tokio::test]
async fn credentials_presence_never_bypasses_authorization() {
    let service = Service::new(
        Router::with_path("api/get-global-users")
            .hoop(casdog::hoops::AuthzFilter)
            .get(reached),
    );
    for credentials in [
        "",
        "?clientId=fake&clientSecret=fake",
        "?accessKey=fake&accessSecret=fake",
    ] {
        let response = TestClient::get(format!(
            "http://localhost/api/get-global-users{credentials}"
        ))
        .add_header("Authorization", "Basic ZmFrZTpmYWtl", true)
        .send(&service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    }
}

#[test]
fn self_profile_allowlist_rejects_privileges_credentials_and_identity() {
    assert!(
        casdog::hoops::authz::validate_profile(
            &json!({"display_name":"Alice", "avatar":"https://example.test/avatar"})
        )
        .is_ok()
    );
    for field in [
        "owner",
        "name",
        "is_admin",
        "isAdmin",
        "password",
        "password_hash",
        "email",
        "phone",
        "roles",
        "properties",
        "totp_secret",
    ] {
        assert!(
            casdog::hoops::authz::validate_profile(&json!({field:true})).is_err(),
            "{field}"
        );
    }
}

struct Fixture {
    pool: PgPool,
    service: Service,
    tenant: String,
    other: String,
    admin_id: String,
    user_id: String,
    other_user: String,
    group: String,
    other_group: String,
    app: String,
    other_app: String,
    provider: String,
    other_provider: String,
}
impl Fixture {
    async fn new() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            AppConfig::load().unwrap();
        });
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").expect("set CASDOG_TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        let id = || uuid::Uuid::new_v4().to_string();
        let tenant = format!("authz-{}", id());
        let other = format!("authz-other-{}", id());
        let admin_id = id();
        let user_id = id();
        let other_user = id();
        let group = id();
        let other_group = id();
        let app = id();
        let other_app = id();
        let provider = id();
        let other_provider = id();
        for (owner, user, name, admin) in [
            (&tenant, &admin_id, "admin", true),
            (&tenant, &user_id, "alice", false),
            (&other, &other_user, "other", true),
        ] {
            sqlx::query("INSERT INTO users (id,owner,name,display_name,password_hash,is_admin) VALUES ($1,$2,$3,$3,'unused-test-hash',$4)")
                .bind(user).bind(owner).bind(name).bind(admin).execute(&pool).await.unwrap();
        }
        for (owner, group) in [(&tenant, &group), (&other, &other_group)] {
            sqlx::query(
                "INSERT INTO groups(id,owner,name,display_name) VALUES ($1,$2,'group','Group')",
            )
            .bind(group)
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        }
        for (owner, provider) in [(&tenant, &provider), (&other, &other_provider)] {
            sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES ($1,$2,'mail','Mail','Email','SMTP')")
                .bind(provider).bind(owner).execute(&pool).await.unwrap();
        }
        for (owner, app, provider) in [
            (&tenant, &app, &provider),
            (&other, &other_app, &other_provider),
        ] {
            sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,providers) VALUES ($1,$2,'same-name','App',$2,$1,'test-client-secret','https://example.test/callback',$3)")
                .bind(app).bind(owner).bind(json!([{"name":provider,"canSignIn":true}])).execute(&pool).await.unwrap();
        }
        Self {
            pool,
            service,
            tenant,
            other,
            admin_id,
            user_id,
            other_user,
            group,
            other_group,
            app,
            other_app,
            provider,
            other_provider,
        }
    }
    fn token(&self, admin: bool) -> String {
        let now = chrono::Utc::now();
        encode(&Header::default(), &json!({"sub":if admin {&self.admin_id} else {&self.user_id}, "owner":self.tenant,
            "name":if admin {"admin"} else {"alice"},"is_admin":admin,"exp":now.timestamp()+3600,"iat":now.timestamp(),
            "issued_at_ms":now.timestamp_millis(),"iss":AppConfig::get().jwt.issuer}),
            &EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
    }
    async fn cleanup(&self) {
        for table in ["user_groups", "revoked_session_tokens"] {
            let sql = if table == "user_groups" {
                "DELETE FROM user_groups WHERE user_id IN ($1,$2,$3)"
            } else {
                "DELETE FROM revoked_session_tokens WHERE user_id IN ($1,$2,$3)"
            };
            let _ = sqlx::query(sql)
                .bind(&self.admin_id)
                .bind(&self.user_id)
                .bind(&self.other_user)
                .execute(&self.pool)
                .await;
        }
        for table in [
            "records",
            "orders",
            "groups",
            "applications",
            "providers",
            "sessions",
            "users",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1 OR owner=$2"))
                .bind(&self.tenant)
                .bind(&self.other)
                .execute(&self.pool)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrated disposable PostgreSQL"]
async fn rest_and_scim_enforce_actual_owner_lists_self_fields_and_foreign_keys() {
    let f = Fixture::new().await;
    let bearer = format!("Bearer {}", f.token(true));
    let user_bearer = format!("Bearer {}", f.token(false));
    let mut res = TestClient::get("http://localhost/api/groups")
        .add_header("Authorization", &bearer, true)
        .send(&f.service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let value: Value = res.take_json().await.unwrap();
    assert_eq!(value["total"], 1);
    assert_eq!(value["data"][0]["owner"], f.tenant);
    for url in [
        format!("http://localhost/api/groups/{}", f.other_group),
        format!("http://localhost/api/groups?owner={}", f.other),
        "http://localhost/api/get-global-users".into(),
        "http://localhost/api/get-system-info".into(),
        "http://localhost/api/get-dashboard".into(),
        "http://localhost/api/policies".into(),
    ] {
        let res = TestClient::get(url)
            .add_header("Authorization", &bearer, true)
            .send(&f.service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    }
    let res = TestClient::put(format!("http://localhost/api/groups/{}", f.group))
        .add_header("Authorization", &bearer, true)
        .json(&json!({"display_name":"Updated"}))
        .send(&f.service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    for body in [
        json!({"owner":f.other,"name":"forged","display_name":"forged"}),
        json!({"owner":f.tenant,"name":"forged-parent","display_name":"forged","parent_id":f.other_group}),
    ] {
        let res = TestClient::post("http://localhost/api/groups")
            .add_header("Authorization", &bearer, true)
            .json(&body)
            .send(&f.service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    }
    let res = TestClient::post("http://localhost/api/groups/add-user")
        .add_header("Authorization", &bearer, true)
        .json(&json!({"user_id":f.other_user,"group_id":f.group}))
        .send(&f.service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let res = TestClient::post("http://localhost/api/groups/add-user")
        .add_header("Authorization", &bearer, true)
        .json(&json!({"user_id":f.user_id,"group_id":f.group}))
        .send(&f.service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let res = TestClient::post("http://localhost/api/remove-user-from-group")
        .add_header("Authorization", &bearer, true)
        .json(&json!({"owner":f.tenant,"user_id":f.other_user,"group_id":f.group}))
        .send(&f.service)
        .await;
    assert!(matches!(
        res.status_code,
        Some(StatusCode::FORBIDDEN | StatusCode::NOT_FOUND)
    ));
    let res = TestClient::put(format!("http://localhost/api/users/{}", f.user_id))
        .add_header("Authorization", &user_bearer, true)
        .json(&json!({"display_name":"My profile"}))
        .send(&f.service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let res = TestClient::put(format!("http://localhost/api/users/{}", f.user_id))
        .add_header("Authorization", &user_bearer, true)
        .json(&json!({"is_admin":true}))
        .send(&f.service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let res = TestClient::put(format!("http://localhost/api/applications/{}", f.app))
        .add_header("Authorization", &bearer, true)
        .json(&json!({"organization":f.other}))
        .send(&f.service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let res=TestClient::post("http://localhost/api/tokens").add_header("Authorization",&bearer,true)
        .json(&json!({"owner":f.tenant,"name":"forged-user","organization":f.tenant,"application":f.app,"user":f.other_user})).send(&f.service).await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    let bad_order = uuid::Uuid::new_v4().to_string();
    sqlx::query(r#"INSERT INTO orders(id,owner,name,display_name,"user") VALUES($1,$2,'bad-order','Bad',$3)"#)
        .bind(&bad_order).bind(&f.tenant).bind(&f.other_user).execute(&f.pool).await.unwrap();
    for path in [
        format!("orders/{bad_order}/pay"),
        format!("orders/{bad_order}/cancel"),
        format!("pay-order?id={bad_order}"),
    ] {
        let res = TestClient::post(format!("http://localhost/api/{path}"))
            .add_header("Authorization", &bearer, true)
            .send(&f.service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    }
    for (authorization, total) in [(&bearer, 2), (&user_bearer, 1)] {
        let mut res = TestClient::get("http://localhost/api/scim/v2/Users")
            .add_header("Authorization", authorization, true)
            .send(&f.service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        let value: Value = res.take_json().await.unwrap();
        assert_eq!(value["totalResults"], total);
        assert!(!value.to_string().contains(&f.other_user));
    }
    let res = TestClient::get(format!(
        "http://localhost/api/scim/v2/Users/{}",
        f.other_user
    ))
    .add_header("Authorization", &bearer, true)
    .send(&f.service)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::NOT_FOUND));
    let mut res = TestClient::get("http://localhost/api/users")
        .add_header("Authorization", &user_bearer, true)
        .send(&f.service)
        .await;
    let body: Value = res.take_json().await.unwrap();
    assert_eq!(body["total"], 1);
    assert_eq!(body["data"][0]["id"], f.user_id);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrated disposable PostgreSQL"]
async fn mcp_scopes_exact_applications_masks_secrets_and_rejects_nonadmins() {
    let f = Fixture::new().await;
    let bearer = format!("Bearer {}", f.token(true));
    for (tool, args) in [
        ("get_applications", json!({"owner":f.other})),
        ("get_application", json!({"id":f.other_app})),
        (
            "update_application",
            json!({"id":f.other_app,"application":{"displayName":"hijacked"}}),
        ),
        (
            "delete_application",
            json!({"application":{"id":f.other_app}}),
        ),
        (
            "add_application",
            json!({"application":{"owner":f.tenant,"name":"forged","organization":f.other}}),
        ),
    ] {
        let res = TestClient::post("http://localhost/api/mcp")
            .add_header("Authorization", &bearer, true)
            .json(&json!({"id":1,"method":"tools/call","params":{"name":tool,"arguments":args}}))
            .send(&f.service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN), "{tool}");
    }
    let mut res=TestClient::post("http://localhost/api/mcp").add_header("Authorization",&bearer,true).json(&json!({"id":2,"method":"tools/call","params":{"name":"get_application","arguments":{"id":f.app}}})).send(&f.service).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let body: Value = res.take_json().await.unwrap();
    assert!(!body.to_string().contains("test-client-secret"));
    assert!(body.to_string().contains("***"));
    let res=TestClient::post("http://localhost/api/mcp").add_header("Authorization",&bearer,true).json(&json!({"id":3,"method":"tools/call","params":{"name":"update_application","arguments":{"id":"same-name","application":{"displayName":"Own updated"}}}})).send(&f.service).await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    let other_name: String =
        sqlx::query_scalar("SELECT display_name FROM applications WHERE id=$1")
            .bind(&f.other_app)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(other_name, "App");
    let own_name: String = sqlx::query_scalar("SELECT display_name FROM applications WHERE id=$1")
        .bind(&f.app)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(own_name, "Own updated");
    let mut res=TestClient::post("http://localhost/api/mcp").add_header("Authorization",format!("Bearer {}",f.token(false)),true).json(&json!({"id":4,"method":"tools/call","params":{"name":"get_application","arguments":{"id":f.app}}})).send(&f.service).await;
    let body: Value = res.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], -32001);
    sqlx::query("UPDATE users SET is_forbidden=true WHERE id=$1")
        .bind(&f.admin_id)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut res=TestClient::post("http://localhost/api/mcp").add_header("Authorization",&bearer,true).json(&json!({"id":5,"method":"tools/call","params":{"name":"get_application","arguments":{"id":f.app}}})).send(&f.service).await;
    let body: Value = res.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], -32001);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrated disposable PostgreSQL"]
async fn messaging_validates_real_credentials_and_provider_tenant_before_delivery() {
    let f = Fixture::new().await;
    let bearer = format!("Bearer {}", f.token(true));
    sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&f.tenant)
        .execute(&f.pool)
        .await
        .unwrap();
    casdog::services::key_credentials_service::mark_static_application(
        &f.pool,
        &f.app,
        &casdog::hoops::authz::Principal {
            id: f.admin_id.clone(),
            owner: f.tenant.clone(),
            name: "admin".into(),
            admin: true,
            application_identity: false,
        },
    )
    .await
    .unwrap();
    // Empty receiver lists guarantee this regression never sends external messages.
    for (authorization, provider, status) in [
        (
            bearer.clone(),
            f.other_provider.clone(),
            StatusCode::FORBIDDEN,
        ),
        (
            format!("Bearer {}", f.token(false)),
            f.provider.clone(),
            StatusCode::FORBIDDEN,
        ),
        (bearer.clone(), f.provider.clone(), StatusCode::BAD_REQUEST),
    ] {
        let res = TestClient::post("http://localhost/api/send-email")
            .add_header("Authorization", authorization, true)
            .json(&json!({"provider":provider,"content":"test","receivers":[]}))
            .send(&f.service)
            .await;
        assert_eq!(res.status_code, Some(status));
    }
    for (secret, provider, status) in [
        ("wrong", &f.provider, StatusCode::UNAUTHORIZED),
        (
            "test-client-secret",
            &f.other_provider,
            StatusCode::FORBIDDEN,
        ),
        ("test-client-secret", &f.provider, StatusCode::BAD_REQUEST),
    ] {
        let res = TestClient::post(format!(
            "http://localhost/api/send-email?clientId={}&clientSecret={secret}",
            f.app
        ))
        .json(&json!({"provider":provider,"content":"test","receivers":[]}))
        .send(&f.service)
        .await;
        assert_eq!(res.status_code, Some(status));
    }
    sqlx::query("UPDATE applications SET providers=NULL WHERE id=$1")
        .bind(&f.app)
        .execute(&f.pool)
        .await
        .unwrap();
    let res = TestClient::post(format!(
        "http://localhost/api/send-email?clientId={}&clientSecret=test-client-secret",
        f.app
    ))
    .json(&json!({"provider":f.provider,"content":"test","receivers":[]}))
    .send(&f.service)
    .await;
    assert_eq!(res.status_code, Some(StatusCode::FORBIDDEN));
    f.cleanup().await;
    sqlx::query("DELETE FROM organizations WHERE name=$1")
        .bind(&f.tenant)
        .execute(&f.pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrated disposable PostgreSQL"]
async fn impersonation_requires_live_original_admin_credentials_and_active_session() {
    let f = Fixture::new().await;
    let session = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO sessions(id,owner,name,application,user_id,session_id) VALUES ($1,$2,'impersonated','same-name',$3,$1)")
        .bind(&session).bind(&f.tenant).bind(&f.user_id).execute(&f.pool).await.unwrap();
    let now = chrono::Utc::now();
    let claims = json!({"sub":f.user_id,"owner":f.tenant,"name":"alice","is_admin":false,
        "impersonator_user_id":f.admin_id,"impersonator_owner":f.tenant,"impersonator_name":"admin",
        "impersonation_session_id":session,"impersonation_application":"same-name",
        "exp":now.timestamp()+3600,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"iss":AppConfig::get().jwt.issuer});
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes()),
    )
    .unwrap();
    assert!(
        casdog::hoops::auth::validate_session_claims(&f.pool, &token)
            .await
            .is_ok()
    );
    sqlx::query("UPDATE users SET is_forbidden=true WHERE id=$1")
        .bind(&f.admin_id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        casdog::hoops::auth::validate_session_claims(&f.pool, &token)
            .await
            .is_err()
    );
    sqlx::query("UPDATE users SET is_forbidden=false,last_change_password_time=$2 WHERE id=$1")
        .bind(&f.admin_id)
        .bind((now + chrono::Duration::seconds(1)).to_rfc3339())
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        casdog::hoops::auth::validate_session_claims(&f.pool, &token)
            .await
            .is_err()
    );
    sqlx::query("UPDATE users SET last_change_password_time=NULL WHERE id=$1")
        .bind(&f.admin_id)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM sessions WHERE id=$1")
        .bind(&session)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        casdog::hoops::auth::validate_session_claims(&f.pool, &token)
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrated disposable PostgreSQL"]
async fn application_login_permissions_use_tenant_scoped_normalized_role_membership() {
    use casdog::services::CheckService;
    let f = Fixture::new().await;
    assert!(
        CheckService::check_login_permission(&f.pool, &f.user_id, &f.app)
            .await
            .is_ok()
    );
    assert!(
        CheckService::check_login_permission(&f.pool, &f.user_id, &f.other_app)
            .await
            .is_err()
    );
    let role = uuid::Uuid::new_v4().to_string();
    let foreign_role = uuid::Uuid::new_v4().to_string();
    let allow = uuid::Uuid::new_v4().to_string();
    let deny = uuid::Uuid::new_v4().to_string();
    for (id, owner) in [(&role, &f.tenant), (&foreign_role, &f.other)] {
        sqlx::query(
            "INSERT INTO roles(id,owner,name,display_name) VALUES($1,$2,'login-role','Login role')",
        )
        .bind(id)
        .bind(owner)
        .execute(&f.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO user_roles(id,user_id,role_id) VALUES($1,$2,$3)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&f.user_id)
            .bind(id)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO permissions(id,owner,name,display_name,resource_type,resources,actions,effect) VALUES($1,$2,'app-allow','Allow','Application',$3,'Read','Allow')")
        .bind(&allow).bind(&f.tenant).bind(json!([f.app]).to_string()).execute(&f.pool).await.unwrap();
    assert!(
        CheckService::check_login_permission(&f.pool, &f.user_id, &f.app)
            .await
            .is_err()
    );
    // A preexisting poisoned join to another tenant's role must never grant access.
    sqlx::query("INSERT INTO role_permissions(id,role_id,permission_id) VALUES($1,$2,$3)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&foreign_role)
        .bind(&allow)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        CheckService::check_login_permission(&f.pool, &f.user_id, &f.app)
            .await
            .is_err()
    );
    sqlx::query("INSERT INTO role_permissions(id,role_id,permission_id) VALUES($1,$2,$3)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&role)
        .bind(&allow)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        CheckService::check_login_permission(&f.pool, &f.user_id, &f.app)
            .await
            .is_ok()
    );
    sqlx::query("UPDATE roles SET is_enabled=false WHERE id=$1")
        .bind(&role)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        CheckService::check_login_permission(&f.pool, &f.user_id, &f.app)
            .await
            .is_err()
    );
    sqlx::query("UPDATE roles SET is_enabled=true WHERE id=$1")
        .bind(&role)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO permissions(id,owner,name,display_name,resource_type,resources,actions,effect) VALUES($1,$2,'app-deny','Deny','Application','*','Read','Deny')")
        .bind(&deny).bind(&f.tenant).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO role_permissions(id,role_id,permission_id) VALUES($1,$2,$3)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&role)
        .bind(&deny)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        CheckService::check_login_permission(&f.pool, &f.user_id, &f.app)
            .await
            .is_err()
    );
    sqlx::query("UPDATE permissions SET is_enabled=false WHERE id=$1")
        .bind(&deny)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        CheckService::check_login_permission(&f.pool, &f.user_id, &f.app)
            .await
            .is_ok()
    );
    sqlx::query("DELETE FROM permissions WHERE id=$1 OR id=$2")
        .bind(&allow)
        .bind(&deny)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM roles WHERE id=$1 OR id=$2")
        .bind(&role)
        .bind(&foreign_role)
        .execute(&f.pool)
        .await
        .unwrap();
    f.cleanup().await;
}
