use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    services::runtime_settings_service::{RuntimeSettings, RuntimeSettingsService},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

#[test]
fn settings_accept_defaults_but_reject_invalid_limits_unknown_fields_and_lossy_types() {
    assert_eq!(
        RuntimeSettings::parse(&json!({})).unwrap(),
        RuntimeSettings::default()
    );
    for value in [
        json!({"recordRetentionDays":-1}),
        json!({"dbMaxOpenConns":2,"dbMaxIdleConns":3}),
        json!({"recordRetentionDays":"30"}),
        json!({"dbConnMaxLifetime":0.5}),
        json!({"recordRetentionDays":365001}),
        json!({"unknown":1}),
    ] {
        assert!(RuntimeSettings::parse(&value).is_err(), "{value}");
    }
}

struct Fixture {
    pool: PgPool,
    service: Service,
    admin: String,
    tenant_admin: String,
    member: String,
    a: String,
    b: String,
    old_settings: Value,
    builtin_days: i32,
}
fn token(id: &str, owner: &str, name: &str, admin: bool) -> String {
    let now = chrono::Utc::now();
    encode(&Header::default(),&json!({"sub":id,"owner":owner,"name":name,"is_admin":admin,"exp":now.timestamp()+3600,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"iss":AppConfig::get().jwt.issuer}),&EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
}
impl Fixture {
    async fn new() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            AppConfig::load().unwrap();
        });
        let url =
            std::env::var("CASDOG_TEST_DATABASE_URL").expect("Use a migrated disposable database");
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
        let a = format!("retention-{}", uuid::Uuid::new_v4());
        let b = format!("retention-{}", uuid::Uuid::new_v4());
        for name in [&a, &b] {
            sqlx::query(
                "INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,$2)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(name)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO organizations(id,owner,name,display_name) SELECT $1,'admin','built-in','Built-in' WHERE NOT EXISTS(SELECT 1 FROM organizations WHERE name='built-in')").bind(uuid::Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
        let builtin_days = sqlx::query_scalar(
            "SELECT record_retention_days FROM organizations WHERE name='built-in'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let admin = uuid::Uuid::new_v4().to_string();
        let tenant_admin = uuid::Uuid::new_v4().to_string();
        let member = uuid::Uuid::new_v4().to_string();
        for (id, owner, name, is_admin) in [
            (&admin, "built-in", admin.as_str(), true),
            (&tenant_admin, a.as_str(), "admin", true),
            (&member, a.as_str(), "member", false),
        ] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,$3,'unused',$4)").bind(id).bind(owner).bind(name).bind(is_admin).execute(&pool).await.unwrap();
        }
        let old_settings =
            sqlx::query_scalar("SELECT data FROM operation_settings WHERE singleton")
                .fetch_one(&pool)
                .await
                .unwrap();
        Self {
            pool,
            service,
            admin,
            tenant_admin,
            member,
            a,
            b,
            old_settings,
            builtin_days,
        }
    }
    fn administrator(&self) -> String {
        token(&self.admin, "built-in", &self.admin, true)
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        token: &str,
    ) -> (StatusCode, Value) {
        let builder = match method {
            "GET" => TestClient::get(format!("http://localhost{path}")),
            "PUT" => TestClient::put(format!("http://localhost{path}")),
            _ => TestClient::post(format!("http://localhost{path}")),
        }
        .add_header("Authorization", format!("Bearer {token}"), true);
        let mut response = if let Some(body) = body {
            builder.json(&body).send(&self.service).await
        } else {
            builder.send(&self.service).await
        };
        (
            response.status_code.unwrap_or(StatusCode::OK),
            response.take_json().await.unwrap(),
        )
    }
    async fn settings(&self, days: i64) {
        let response = self
            .request(
                "POST",
                "/api/update-setting",
                Some(json!({"recordRetentionDays":days})),
                &self.administrator(),
            )
            .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    }
    async fn record(&self, owner: &str, days: i64) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO records(id,owner,name,created_at) VALUES($1,$2,$1,clock_timestamp()-make_interval(days=>$3))").bind(&id).bind(owner).bind(days as i32).execute(&self.pool).await.unwrap();
        id
    }
    async fn exists(&self, id: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=$1)")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn cleanup(&self) {
        sqlx::query("UPDATE operation_settings SET data=$1 WHERE singleton")
            .bind(&self.old_settings)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE organizations SET record_retention_days=$1 WHERE name='built-in'")
            .bind(self.builtin_days)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query(
            "DELETE FROM records WHERE owner=$1 OR owner=$2 OR name LIKE 'retention-orphan-%'",
        )
        .bind(&self.a)
        .bind(&self.b)
        .execute(&self.pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM users WHERE id IN ($1,$2,$3)")
            .bind(&self.admin)
            .bind(&self.tenant_admin)
            .bind(&self.member)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE name=$1 OR name=$2")
            .bind(&self.a)
            .bind(&self.b)
            .execute(&self.pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrations 001-039"]
async fn settings_api_validates_real_global_admin_and_reports_retention_separately_from_unapplied_pool_settings()
 {
    let f = Fixture::new().await;
    for token in [
        token(&f.tenant_admin, &f.a, "admin", true),
        token(&f.member, &f.a, "member", false),
    ] {
        assert_eq!(
            f.request("GET", "/api/get-setting", None, &token).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            f.request(
                "POST",
                "/api/update-setting",
                Some(json!({"recordRetentionDays":1})),
                &token
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let response=f.request("POST","/api/update-setting",Some(json!({"dbMaxOpenConns":8,"dbMaxIdleConns":2,"dbConnMaxLifetime":60,"recordRetentionDays":7})),&f.administrator()).await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["recordRetentionApplied"], true);
    assert_eq!(response.1["poolSettingsApplied"], false);
    assert_eq!(response.1["applied"], false);
    let data = f
        .request("GET", "/api/get-setting", None, &f.administrator())
        .await
        .1;
    assert_eq!(data["data"]["recordRetentionDays"], 7);
    assert_eq!(data["data"]["runtime"]["recordRetentionApplied"], true);
    let before: Value = sqlx::query_scalar("SELECT data FROM operation_settings WHERE singleton")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.request(
            "POST",
            "/api/update-setting",
            Some(json!({"recordRetentionDays":-2})),
            &f.administrator()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let after: Value = sqlx::query_scalar("SELECT data FROM operation_settings WHERE singleton")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    let fake = casdog::hoops::authz::Principal {
        id: f.member.clone(),
        owner: "built-in".into(),
        name: "member".into(),
        admin: true,
        application_identity: false,
    };
    assert!(
        RuntimeSettingsService::update(&f.pool, &fake, &json!({"recordRetentionDays":1}))
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrations 001-039"]
async fn record_retention_applies_native_and_legacy_org_overrides_global_defaults_and_builtin_orphan_policy()
 {
    let f = Fixture::new().await;
    f.settings(7).await;
    let a_id: String = sqlx::query_scalar("SELECT id FROM organizations WHERE name=$1")
        .bind(&f.a)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    let own = token(&f.tenant_admin, &f.a, "admin", true);
    let updated = f
        .request(
            "PUT",
            &format!("/api/organizations/{a_id}"),
            Some(json!({"recordRetentionDays":30})),
            &own,
        )
        .await;
    assert_eq!(updated.0, StatusCode::OK, "{}", updated.1);
    assert_eq!(updated.1["record_retention_days"], 30);
    assert_eq!(
        f.request(
            "PUT",
            &format!("/api/organizations/{a_id}"),
            Some(json!({"recordRetentionDays":-1})),
            &own
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let b_id: String = sqlx::query_scalar("SELECT id FROM organizations WHERE name=$1")
        .bind(&f.b)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.request(
            "PUT",
            &format!("/api/organizations/{b_id}"),
            Some(json!({"recordRetentionDays":1})),
            &own
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request(
            "POST",
            "/api/update-organization",
            Some(json!({"owner":"admin","name":f.a,"recordRetentionDays":-1})),
            &own
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let kept = f.record(&f.a, 10).await;
    let removed = f.record(&f.a, 40).await;
    let fallback = f.record(&f.b, 10).await;
    let recent = f.record(&f.b, 1).await;
    assert!(RuntimeSettingsService::run_once(&f.pool).await.unwrap() >= 2);
    assert!(f.exists(&kept).await);
    assert!(!f.exists(&removed).await);
    assert!(!f.exists(&fallback).await);
    assert!(f.exists(&recent).await);
    f.settings(0).await;
    let forever = f.record(&f.b, 1000).await;
    let updated = f
        .request(
            "POST",
            "/api/update-organization",
            Some(json!({"owner":"admin","name":f.a,"recordRetentionDays":1})),
            &own,
        )
        .await;
    assert_eq!(updated.0, StatusCode::OK, "{}", updated.1);
    sqlx::query("UPDATE organizations SET record_retention_days=1 WHERE name='built-in'")
        .execute(&f.pool)
        .await
        .unwrap();
    let orphan = f.record("anonymous", 10).await;
    sqlx::query("UPDATE records SET name=$2 WHERE id=$1")
        .bind(&orphan)
        .bind(format!("retention-orphan-{orphan}"))
        .execute(&f.pool)
        .await
        .unwrap();
    RuntimeSettingsService::run_once(&f.pool).await.unwrap();
    assert!(!f.exists(&kept).await);
    assert!(!f.exists(&orphan).await);
    assert!(f.exists(&forever).await);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL with migrations 001-039"]
async fn cleanup_uses_shared_policy_and_advisory_lock_and_rejects_malformed_policy_without_deleting()
 {
    let f = Fixture::new().await;
    f.settings(1).await;
    let row = f.record(&f.a, 10).await;
    let other = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut lock = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('casdog.record-retention.v1')::bigint)")
        .execute(&mut *lock)
        .await
        .unwrap();
    assert_eq!(
        RuntimeSettingsService::cleanup_batch(&other, 100)
            .await
            .unwrap(),
        0
    );
    assert!(f.exists(&row).await);
    lock.rollback().await.unwrap();
    f.settings(0).await;
    assert_eq!(
        RuntimeSettingsService::cleanup_batch(&other, 100)
            .await
            .unwrap(),
        0
    );
    assert!(f.exists(&row).await);
    sqlx::query("UPDATE operation_settings SET data=jsonb_build_object('recordRetentionDays','invalid') WHERE singleton").execute(&f.pool).await.unwrap();
    assert!(
        RuntimeSettingsService::cleanup_batch(&other, 100)
            .await
            .is_err()
    );
    assert!(f.exists(&row).await);
    f.settings(1).await;
    RuntimeSettingsService::cleanup_batch(&other, 100)
        .await
        .unwrap();
    assert!(!f.exists(&row).await);
    other.close().await;
    f.cleanup().await;
}
