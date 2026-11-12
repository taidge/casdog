//! Cloud-directory private-network approvals: normal API and live lease isolation.
use base64::Engine;
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    hoops::authz::Principal,
    models::Syncer,
    services::{SyncerService, syncer_network_service as network},
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

struct Fixture {
    pool: PgPool,
    peer: PgPool,
    service: Service,
    other: Service,
    owner: String,
    global_id: String,
    users: Vec<String>,
    global: String,
    tenant: String,
    ordinary: String,
    misleading: String,
}
fn token(id: &str, owner: &str, name: &str, admin: bool) -> String {
    let c = AppConfig::get();
    let now = chrono::Utc::now();
    jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({"sub":id,"owner":owner,"name":name,"is_admin":admin,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"exp":now.timestamp()+3600,"iss":c.jwt.issuer}),&jsonwebtoken::EncodingKey::from_secret(c.jwt.secret.as_bytes())).unwrap()
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
        let peer = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let build = |pool: PgPool| {
            Service::new(casdog::routes::create_router()).hoop(
                salvo::affix_state::AffixList::new()
                    .inject(pool)
                    .inject(diesel.clone()),
            )
        };
        let service = build(pool.clone());
        let other = build(peer.clone());
        let owner = format!("syncnet-{}", uuid::Uuid::new_v4());
        for name in ["built-in", "admin", owner.as_str()] {
            sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,'Directory network tests') ON CONFLICT(name) DO NOTHING").bind(uuid::Uuid::new_v4().to_string()).bind(name).execute(&pool).await.unwrap();
        }
        let mut users = Vec::new();
        let mut tokens = Vec::new();
        for (org, name, admin) in [
            ("built-in", owner.as_str(), true),
            (owner.as_str(), "built-in", true),
            (owner.as_str(), "ordinary", false),
            ("admin", owner.as_str(), true),
        ] {
            let id = uuid::Uuid::new_v4().to_string();
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,'Network reviewer test','unused',$4)").bind(&id).bind(org).bind(name).bind(admin).execute(&pool).await.unwrap();
            tokens.push(token(&id, org, name, admin));
            users.push(id);
        }
        Self {
            pool,
            peer,
            service,
            other,
            owner,
            global_id: users[0].clone(),
            users,
            global: tokens[0].clone(),
            tenant: tokens[1].clone(),
            ordinary: tokens[2].clone(),
            misleading: tokens[3].clone(),
        }
    }
    fn actor(&self) -> Principal {
        Principal {
            id: self.global_id.clone(),
            owner: "built-in".into(),
            name: self.owner.clone(),
            admin: true,
            application_identity: false,
        }
    }
    async fn request_on(
        service: &Service,
        method: &str,
        path: &str,
        body: Option<Value>,
        authorization: &str,
    ) -> Response {
        let request = match method {
            "GET" => TestClient::get(format!("http://localhost{path}")),
            "DELETE" => TestClient::delete(format!("http://localhost{path}")),
            "PUT" => TestClient::put(format!("http://localhost{path}")),
            _ => TestClient::post(format!("http://localhost{path}")),
        }
        .add_header("Authorization", authorization, true);
        if let Some(body) = body {
            request.json(&body).send(service).await
        } else {
            request.send(service).await
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        token: &str,
    ) -> Response {
        Self::request_on(
            &self.service,
            method,
            path,
            body,
            &format!("Bearer {token}"),
        )
        .await
    }
    async fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let mut response = self.request(method, path, body, &self.global).await;
        let status = response.status_code;
        let text = response.take_string().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{text}");
        serde_json::from_str(&text).unwrap()
    }
    async fn create(&self, name: &str, owner: Option<&str>) -> String {
        let value=self.ok("POST","/api/syncers",Some(json!({"owner":owner.unwrap_or(&self.owner),"name":name,"organization":self.owner,"type":"Azure AD","host":"tenant.example","port":443,"user":"directory-client","password":"directory-network-secret","database":json!({"token_endpoint":"http://127.0.0.1:9/token","api_base":"http://127.0.0.1:9/v1.0"}).to_string(),"is_read_only":true,"is_enabled":false,"sync_interval":60}))).await;
        assert_eq!(value["password"], "***");
        value["id"].as_str().unwrap().into()
    }
    async fn saved(&self, id: &str) -> Syncer {
        SyncerService::get_by_id_internal(&self.pool, id)
            .await
            .unwrap()
    }
    async fn grant(&self, id: &str) -> Value {
        self.ok(
            "POST",
            &format!("/api/syncers/{id}/network-approval"),
            Some(json!({"allow_private":true})),
        )
        .await
    }
    async fn cleanup(self) {
        sqlx::query("DELETE FROM syncers WHERE organization=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM applications WHERE name LIKE $1")
            .bind(format!("{}%", self.owner))
            .execute(&self.pool)
            .await
            .unwrap();
        for id in &self.users {
            sqlx::query("DELETE FROM users WHERE id=$1")
                .bind(id)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM organizations WHERE name=$1")
            .bind(&self.owner)
            .execute(&self.pool)
            .await
            .unwrap();
        self.pool.close().await;
        self.peer.close().await;
    }
}
fn no_store(response: &Response) {
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-051"]
async fn native_cloud_network_approval_requires_real_global_user_and_strict_request_body() {
    let f = Fixture::new().await;
    let id = f.create("normal", None).await;
    let path = format!("/api/syncers/{id}/network-approval");
    let mut response = f.request("GET", &path, None, &f.global).await;
    no_store(&response);
    let status: Value = response.take_json().await.unwrap();
    assert_eq!(status["allow_private"], false);
    assert_eq!(status["stale"], false);
    for token in [&f.tenant, &f.ordinary, &f.misleading] {
        for method in ["GET", "POST", "DELETE"] {
            let response = f
                .request(
                    method,
                    &path,
                    (method == "POST").then(|| json!({"allow_private":true})),
                    token,
                )
                .await;
            assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
        }
    }
    for body in [
        json!({"allow_private":false}),
        json!({"allow_private":true,"unexpected":true}),
        json!({}),
        json!({"allow_private":"true"}),
    ] {
        let response = f.request("POST", &path, Some(body), &f.global).await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        no_store(&response);
    }
    let granted = f.grant(&id).await;
    assert_eq!(granted["allow_private"], true);
    assert_eq!(granted["approved_by"], f.global_id);
    assert!(!granted.to_string().contains("directory-network-secret"));
    let response = f.request("GET", &path, None, &f.global).await;
    no_store(&response);
    // Object ownership and a tenant administrator literally named built-in do
    // not turn into global approval authority.
    let misleading_id = f.create("misleading-owner", Some("built-in")).await;
    let response = f
        .request(
            "POST",
            &format!("/api/syncers/{misleading_id}/network-approval"),
            Some(json!({"allow_private":true})),
            &f.tenant,
        )
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let app=f.ok("POST","/api/applications",Some(json!({"owner":"admin","name":format!("{}-machine",f.owner),"display_name":"Machine must not approve","organization":"built-in"}))).await;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        app["client_id"].as_str().unwrap(),
        app["client_secret"].as_str().unwrap()
    ));
    let response = Fixture::request_on(
        &f.service,
        "POST",
        &path,
        Some(json!({"allow_private":true})),
        &format!("Basic {basic}"),
    )
    .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let unknown = f
        .request(
            "GET",
            &format!("/api/syncers/{}/network-approval", uuid::Uuid::new_v4()),
            None,
            &f.global,
        )
        .await;
    assert_eq!(unknown.status_code, Some(StatusCode::NOT_FOUND));
    no_store(&unknown);
    let response = f.request("DELETE", &path, None, &f.global).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    no_store(&response);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-051"]
async fn cloud_approval_is_bound_to_secret_and_options_reapproval_rotates_generation_and_delete_cascades()
 {
    let f = Fixture::new().await;
    let id = f.create("stamp", None).await;
    let path = format!("/api/syncers/{id}/network-approval");
    let original = f.saved(&id).await;
    assert!(!network::current_access(&f.pool, &original).await.unwrap());
    f.grant(&id).await;
    assert!(network::current_access(&f.peer, &original).await.unwrap());
    let first_generation: String =
        sqlx::query_scalar("SELECT generation FROM syncer_network_approvals WHERE syncer_id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    f.grant(&id).await;
    let generation: String =
        sqlx::query_scalar("SELECT generation FROM syncer_network_approvals WHERE syncer_id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_ne!(first_generation, generation);
    for patch in [
        json!({"password":"rotated-network-secret"}),
        json!({"database":json!({"token_endpoint":"http://127.0.0.1:9/new-token","api_base":"http://127.0.0.1:9/v1.0"}).to_string()}),
        json!({"user":"rotated-client"}),
        json!({"host":"another-tenant.example"}),
    ] {
        let previous = f.saved(&id).await;
        f.ok("PUT", &format!("/api/syncers/{id}"), Some(patch))
            .await;
        let current = f.saved(&id).await;
        assert_ne!(
            network::configuration_stamp(&previous),
            network::configuration_stamp(&current)
        );
        let status = f.ok("GET", &path, None).await;
        assert_eq!(status["allow_private"], false);
        assert_eq!(status["stale"], true);
        assert!(!network::current_access(&f.pool, &current).await.unwrap());
        assert!(matches!(
            network::current_access(&f.pool, &previous).await,
            Err(casdog::error::AppError::Authorization(_))
        ));
        let grant = f.grant(&id).await;
        assert_eq!(grant["allow_private"], true);
        assert_eq!(grant["stale"], false);
        assert!(network::current_access(&f.peer, &current).await.unwrap());
    }
    let current = f.saved(&id).await;
    f.ok("DELETE", &path, None).await;
    assert!(!network::current_access(&f.peer, &current).await.unwrap());
    assert_eq!(f.ok("GET", &path, None).await["stale"], false);
    f.grant(&id).await;
    let mut deleted = f
        .request("DELETE", &format!("/api/syncers/{id}"), None, &f.global)
        .await;
    assert_eq!(deleted.status_code, Some(StatusCode::NO_CONTENT));
    assert!(deleted.take_bytes(None).await.unwrap().is_empty());
    assert_eq!(
        f.request("GET", &format!("/api/syncers/{id}"), None, &f.global)
            .await
            .status_code,
        Some(StatusCode::NOT_FOUND)
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM syncer_network_approvals WHERE syncer_id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-051"]
async fn directory_approval_rereads_actual_admin_role_and_disabled_or_deleted_account() {
    let f = Fixture::new().await;
    let id = f.create("actor", None).await;
    let actor = f.actor();
    for field in ["is_admin", "is_forbidden", "is_deleted"] {
        let value = field != "is_admin";
        sqlx::query(&format!("UPDATE users SET {field}=$2 WHERE id=$1"))
            .bind(&f.global_id)
            .bind(value)
            .execute(&f.pool)
            .await
            .unwrap();
        assert!(matches!(
            network::approve(&f.pool, &actor, &id).await,
            Err(casdog::error::AppError::Authorization(_))
        ));
        let response = f
            .request(
                "POST",
                &format!("/api/syncers/{id}/network-approval"),
                Some(json!({"allow_private":true})),
                &f.global,
            )
            .await;
        assert!(matches!(
            response.status_code,
            Some(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
        ));
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM syncer_network_approvals WHERE syncer_id=$1")
                .bind(&id)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
        sqlx::query(&format!("UPDATE users SET {field}=$2 WHERE id=$1"))
            .bind(&f.global_id)
            .bind(!value)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    assert_eq!(f.grant(&id).await["allow_private"], true);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 001-051"]
async fn network_revocation_does_not_wait_for_executor_syncer_lock_and_is_visible_in_same_pool_one_transaction()
 {
    let f = Fixture::new().await;
    let id = f.create("lease", None).await;
    let snapshot = f.saved(&id).await;
    f.grant(&id).await;
    let mut lease = f.pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *lease)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM syncers WHERE id=$1 FOR UPDATE")
        .bind(&id)
        .fetch_one(&mut *lease)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            network::current_access_conn(&mut lease, &snapshot)
        )
        .await
        .expect("conn API must not acquire the occupied pool")
        .unwrap()
    );
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        Fixture::request_on(
            &f.other,
            "DELETE",
            &format!("/api/syncers/{id}/network-approval"),
            None,
            &format!("Bearer {}", f.global),
        ),
    )
    .await
    .expect("revoke must not wait on executor's Syncer FOR UPDATE");
    assert_eq!(response.status_code, Some(StatusCode::OK));
    no_store(&response);
    assert!(
        !tokio::time::timeout(
            std::time::Duration::from_secs(3),
            network::current_access_conn(&mut lease, &snapshot)
        )
        .await
        .expect("same lease connection must see committed revocation")
        .unwrap()
    );
    lease.rollback().await.unwrap();
    assert!(!network::current_access(&f.pool, &snapshot).await.unwrap());
    f.cleanup().await;
}
