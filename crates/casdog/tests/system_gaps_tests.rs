use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use casdog::{
    handlers::system_gaps,
    hoops::authz::Principal,
    models::provider::Provider,
    services::system_gap_service::{self as operations, SystemGapConfig},
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    origin: String,
    responses: Arc<Mutex<HashMap<String, (u16, Vec<u8>)>>>,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let responses = Arc::new(Mutex::new(HashMap::<String, (u16, Vec<u8>)>::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let response_map = responses.clone();
        let request_log = requests.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let responses = response_map.clone();
                let requests = request_log.clone();
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let mut chunk = [0; 4096];
                    loop {
                        let count = stream.read(&mut chunk).await.unwrap();
                        if count == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&chunk[..count]);
                        if let Some(index) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&bytes[..index]);
                            let length = head
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|value| value.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            if bytes.len() >= index + 4 + length {
                                break;
                            }
                        }
                    }
                    let request = String::from_utf8_lossy(&bytes).into_owned();
                    let path = request.split_whitespace().nth(1).unwrap().to_string();
                    requests.lock().unwrap().push(request);
                    let (status, body) = responses.lock().unwrap().get(&path).cloned().unwrap_or((404, b"{}".to_vec()));
                    let head = format!(
                        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(head.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                });
            }
        });
        Self {
            origin,
            responses,
            requests,
            task,
        }
    }
    fn json(&self, path: &str, value: Value) {
        self.responses.lock().unwrap().insert(path.into(), (200, serde_json::to_vec(&value).unwrap()));
    }
    fn bytes(&self, path: &str, value: &[u8]) {
        self.responses.lock().unwrap().insert(path.into(), (200, value.to_vec()));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn pool() -> PgPool {
    PgPool::connect(&std::env::var("CASDOG_TEST_DATABASE_URL").expect("dedicated test database required"))
        .await
        .unwrap()
}
fn principal(owner: &str, admin: bool) -> Principal {
    Principal {
        id: uuid::Uuid::new_v4().to_string(),
        owner: owner.into(),
        name: "tester".into(),
        admin,
    }
}
async fn provider(pool: &PgPool, owner: &str, category: &str, kind: &str) -> Provider {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type) VALUES($1,$2,$1,'Fixture',$3,$4)")
        .bind(&id)
        .bind(owner)
        .bind(category)
        .bind(kind)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query_as("SELECT * FROM providers WHERE id=$1").bind(id).fetch_one(pool).await.unwrap()
}

struct Artifacts {
    root: PathBuf,
    path: PathBuf,
}
impl Artifacts {
    fn new() -> Self {
        let root = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap();
        let path = root.join(format!("system-gap-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self {
            root,
            path,
        }
    }
}
impl Drop for Artifacts {
    fn drop(&mut self) {
        if self.path.canonicalize().is_ok_and(|path| {
            path.starts_with(&self.root) && path.file_name().unwrap().to_string_lossy().starts_with("system-gap-test-")
        }) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn upgrades_require_pinned_manifest_verify_package_and_restore_failed_restart() {
    if let Ok(id) = std::env::var("CASDOG_UPGRADE_STARTUP_PROBE") {
        let pool = pool().await;
        operations::reconcile_upgrades(&pool, &SystemGapConfig::from_env()).await.unwrap();
        let status: Value = sqlx::query_scalar("SELECT status FROM system_upgrade_history WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status["state"], "installed");
        return;
    }
    let pool = pool().await;
    let fixture = Fixture::start().await;
    let artifacts = Artifacts::new();
    let destination = artifacts.path.join("installed-binary");
    std::fs::write(&destination, b"stable fixture").unwrap();
    let actor = principal("built-in", true);
    let package = b"new fixture package";
    let manifest = json!({"version":"v9.9.9","url":format!("{}/package",fixture.origin),"sha256":operations::digest(package),"size":package.len(),"target":format!("{}-{}",std::env::consts::OS,std::env::consts::ARCH)});
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    fixture.bytes("/manifest", &manifest_bytes);
    fixture.bytes("/package", package);
    let mut config = SystemGapConfig {
        manifest_url: Some(format!("{}/manifest", fixture.origin)),
        manifest_sha256: Some(operations::digest(&manifest_bytes)),
        install_path: Some(destination.clone()),
        restart_program: Some(std::env::current_exe().unwrap()),
        restart_args: vec!["--list".into()],
    };
    assert!(operations::upgrade(&pool, &config, &principal("other", true), "v9.9.9").await.is_err());
    config.manifest_sha256 = Some("0".repeat(64));
    assert!(operations::upgrade(&pool, &config, &actor, "v9.9.9").await.is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"stable fixture");
    config.manifest_sha256 = Some(operations::digest(&manifest_bytes));
    fixture.bytes("/package", b"tampered package");
    assert!(operations::upgrade(&pool, &config, &actor, "v9.9.9").await.is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"stable fixture");
    fixture.bytes("/package", package);
    assert_eq!(operations::upgrade(&pool, &config, &actor, "v9.9.9").await.unwrap()["state"], "restart_requested");
    assert_eq!(std::fs::read(&destination).unwrap(), package);
    assert!(matches!(
        operations::upgrade(&pool, &config, &actor, "v9.9.9").await,
        Err(casdog::error::AppError::Conflict(_))
    ));
    assert_eq!(std::fs::read(&destination).unwrap(), package);
    operations::reconcile_upgrades(&pool, &config).await.unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"stable fixture");
    std::fs::write(&destination, b"rollback fixture").unwrap();
    config.restart_args = vec!["--invalid-argument-for-fixture".into()];
    assert!(operations::upgrade(&pool, &config, &actor, "v9.9.9").await.is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"rollback fixture");
    let info = operations::upgrade_info(&pool, &config).await.unwrap();
    assert_eq!(info["latestVersion"], "v9.9.9");
    assert_eq!(info["status"]["state"], "failed");
    // Simulate a durable database failure after replacement/restart. The
    // operation must restore the old executable and retain a failed journal.
    config.restart_args = vec!["--list".into()];
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let function = format!("upgrade_fault_{suffix}");
    sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN IF NEW.actor_id='{}' AND NEW.status->>'state'='restart_requested' THEN RAISE EXCEPTION 'fixture final status failure'; END IF; RETURN NEW; END; $$",actor.id)).execute(&pool).await.unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {function} BEFORE UPDATE ON system_upgrade_history FOR EACH ROW EXECUTE FUNCTION {function}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = operations::upgrade(&pool, &config, &actor, "v9.9.9").await;
    sqlx::query(&format!("DROP TRIGGER {function} ON system_upgrade_history")).execute(&pool).await.unwrap();
    sqlx::query(&format!("DROP FUNCTION {function}()")).execute(&pool).await.unwrap();
    assert!(failed.is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"rollback fixture");
    let (journal_id, journal): (String, Value) = sqlx::query_as(
        "SELECT id,journal FROM system_upgrade_history WHERE actor_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .bind(&actor.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let stage = PathBuf::from(journal["stage"].as_str().unwrap());
    let backup = PathBuf::from(journal["backup"].as_str().unwrap());
    for phase in ["installing", "restarting"] {
        std::fs::write(&stage, package).unwrap();
        std::fs::rename(&destination, &backup).unwrap();
        if phase == "restarting" {
            std::fs::rename(&stage, &destination).unwrap();
        }
        sqlx::query("UPDATE system_upgrade_history SET status=jsonb_set(status,'{state}',$2::jsonb) WHERE id=$1")
            .bind(&journal_id)
            .bind(json!(phase))
            .execute(&pool)
            .await
            .unwrap();
        // The currently running test image is outside the pending installation,
        // so startup must recover it instead of trusting the replacement on disk.
        operations::reconcile_upgrades(&pool, &config).await.unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"rollback fixture");
        let status: Value = sqlx::query_scalar("SELECT status FROM system_upgrade_history WHERE id=$1")
            .bind(&journal_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status["state"], "failed");
        assert!(status["error"].as_str().unwrap().contains("Startup restored"));
    }
    assert_eq!(operations::upgrade(&pool, &config, &actor, "v9.9.9").await.unwrap()["state"], "restart_requested");
    assert_eq!(std::fs::read(&destination).unwrap(), package);
    assert!(!std::fs::metadata(&destination).unwrap().permissions().readonly());
    // Launch a real copy of this executable from the prepared installation.
    // Its actual image hash and compiled version must confirm the handover.
    let new_image = artifacts.path.join(if cfg!(windows) {
        "startup-image.exe"
    } else {
        "startup-image"
    });
    std::fs::copy(std::env::current_exe().unwrap(), &new_image).unwrap();
    let startup_id = uuid::Uuid::new_v4().to_string();
    let new_stage = artifacts.path.join(format!(".casdog-upgrade-{startup_id}.new"));
    let old_image = artifacts.path.join(format!(".casdog-upgrade-{startup_id}.backup"));
    std::fs::write(&old_image, b"previous startup image").unwrap();
    let mut startup_journal = journal.clone();
    startup_journal["destination"] = json!(new_image);
    startup_journal["stage"] = json!(new_stage);
    startup_journal["backup"] = json!(old_image);
    startup_journal["previous_sha256"] = json!(operations::digest(b"previous startup image"));
    startup_journal["package_sha256"] = json!(operations::digest(&std::fs::read(&new_image).unwrap()));
    sqlx::query("INSERT INTO system_upgrade_history(id,actor_id,version,status,journal) VALUES($1,$2,$3,$4,$5)")
        .bind(&startup_id)
        .bind(&actor.id)
        .bind(env!("CARGO_PKG_VERSION"))
        .bind(json!({"state":"restart_requested","version":env!("CARGO_PKG_VERSION")}))
        .bind(startup_journal)
        .execute(&pool)
        .await
        .unwrap();
    let mut command = tokio::process::Command::new(&new_image);
    command
        .args([
            "--exact",
            "upgrades_require_pinned_manifest_verify_package_and_restore_failed_restart",
            "--include-ignored",
            "--nocapture",
        ])
        .env("CASDOG_UPGRADE_STARTUP_PROBE", &startup_id)
        .env("CASDOG_UPGRADE_INSTALL_PATH", &new_image)
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let child = tokio::time::timeout(std::time::Duration::from_secs(20), command.output()).await.unwrap().unwrap();
    assert!(
        child.status.success(),
        "startup child failed: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let status: Value = sqlx::query_scalar("SELECT status FROM system_upgrade_history WHERE id=$1")
        .bind(&startup_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status["state"], "installed");
    assert_eq!(std::fs::read(&old_image).unwrap(), b"previous startup image");
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('casdog-system-upgrade',0))")
        .execute(&mut *lock)
        .await
        .unwrap();
    assert!(matches!(
        operations::upgrade(&pool, &config, &actor, "v9.9.9").await,
        Err(casdog::error::AppError::Conflict(_))
    ));
    lock.rollback().await.unwrap();
    sqlx::query("DELETE FROM system_upgrade_history WHERE actor_id=$1").bind(actor.id).execute(&pool).await.unwrap();
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn security_scan_probes_fingerprints_persists_metadata_and_blocks_tenant_private_urls() {
    let pool = pool().await;
    let fixture = Fixture::start().await;
    let owner = format!("scan-{}", uuid::Uuid::new_v4());
    fixture.json("/catalog",json!({"fingerprintList":[{"name":"fixture","product":"Fixture product","vendor":"Test","severity":"low","httpInfo":{"method":"GET","path":"/target","matchers":[{"pos":"body","value":"FixtureProduct"}]},"versionInfo":{"path":"/target","regex":"version ([0-9.]+)"}}],"cveList":[{"name":"fixture","code":"CVE-FIXTURE","rule":""}]}));
    fixture.bytes("/target", b"FixtureProduct version 1.2.3");
    let provider = provider(&pool, &owner, "Scan", "Security Scan").await;
    sqlx::query("UPDATE providers SET sub_type='Url',endpoint=$1,content=$2 WHERE id=$3")
        .bind(format!("{}/catalog", fixture.origin))
        .bind(format!("{}/target", fixture.origin))
        .bind(&provider.id)
        .execute(&pool)
        .await
        .unwrap();
    let provider: Provider =
        sqlx::query_as("SELECT * FROM providers WHERE id=$1").bind(&provider.id).fetch_one(&pool).await.unwrap();
    let global = principal("built-in", true);
    let result = operations::security_scan(&pool, &global, &provider, "").await.unwrap();
    assert_eq!(result[0]["product"], "Fixture product");
    assert_eq!(result[0]["version"], "1.2.3");
    assert_eq!(result[0]["cves"][0]["code"], "CVE-FIXTURE");
    let stored: String = sqlx::query_scalar("SELECT metadata FROM providers WHERE id=$1")
        .bind(&provider.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), result);
    assert!(operations::security_scan(&pool, &principal(&owner, true), &provider, "").await.is_err());
    assert!(operations::provider(&pool, &principal("another-tenant", true), &owner, &provider.name).await.is_err());
    sqlx::query("DELETE FROM providers WHERE id=$1").bind(provider.id).execute(&pool).await.unwrap();
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn intranet_discovery_initializes_real_mcp_and_rejects_public_or_oversized_ranges() {
    let pool = pool().await;
    let fixture = Fixture::start().await;
    fixture.json("/mcp",json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"Fixture MCP","version":"1"},"capabilities":{"tools":{}}}}));
    let mut provider = provider(&pool, "built-in", "Scan", "MCP Scan").await;
    provider.sub_type = Some("Intranet Scan".into());
    provider.scopes = Some("127.0.0.1/32".into());
    provider.content = Some(fixture.origin.rsplit(':').next().unwrap().into());
    provider.endpoint = Some("/mcp".into());
    let global = principal("built-in", true);
    let result = operations::sync_intranet_servers(&pool, &global, &provider).await.unwrap();
    assert_eq!(result["scannedHosts"], 1);
    let name = result["servers"][0]["name"].as_str().unwrap().to_string();
    let stored: Value =
        sqlx::query_scalar("SELECT document FROM casdoor_objects WHERE kind='server' AND owner='built-in' AND name=$1")
            .bind(&name)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored["displayName"], "Fixture MCP");
    sqlx::query(
        "UPDATE casdoor_objects SET document=document || $2 WHERE kind='server' AND owner='built-in' AND name=$1",
    )
    .bind(&name)
    .bind(json!({"token":"preserved-secret","tools":[{"name":"preserved-tool"}]}))
    .execute(&pool)
    .await
    .unwrap();
    operations::sync_intranet_servers(&pool, &global, &provider).await.unwrap();
    let stored: Value =
        sqlx::query_scalar("SELECT document FROM casdoor_objects WHERE kind='server' AND owner='built-in' AND name=$1")
            .bind(&name)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored["token"], "preserved-secret");
    assert_eq!(stored["tools"][0]["name"], "preserved-tool");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM casdoor_objects WHERE kind='server' AND owner='built-in' AND name=$1"
        )
        .bind(&name)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let mut changed = provider.clone();
    changed.updated_at = chrono::Utc::now() + chrono::Duration::seconds(1);
    assert!(operations::sync_intranet_servers(&pool, &global, &changed).await.is_err());
    sqlx::query("DELETE FROM casdoor_objects WHERE kind='server' AND owner='built-in' AND name=$1")
        .bind(&name)
        .execute(&pool)
        .await
        .unwrap();
    assert!(fixture.requests.lock().unwrap()[0].contains("initialize"));
    assert!(operations::intranet_scan(&principal("tenant", true), &provider).await.is_err());
    for target in ["10.0.0.0/8", "8.8.8.8/32"] {
        provider.scopes = Some(target.into());
        assert!(operations::intranet_scan(&principal("built-in", true), &provider).await.is_err());
    }
    sqlx::query("DELETE FROM providers WHERE id=$1").bind(provider.id).execute(&pool).await.unwrap();
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn identity_verification_uses_configured_provider_and_updates_only_verified_subject() {
    let pool = pool().await;
    let fixture = Fixture::start().await;
    let owner = format!("idv-{}", uuid::Uuid::new_v4());
    sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,'admin',$2,'IDV Fixture')")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    let provider = provider(&pool, &owner, "ID Verification", "HTTP").await;
    sqlx::query("UPDATE providers SET endpoint=$1,client_secret='fixture-only-secret' WHERE id=$2")
        .bind(format!("{}/verify", fixture.origin))
        .bind(&provider.id)
        .execute(&pool)
        .await
        .unwrap();
    let app = uuid::Uuid::new_v4().to_string();
    let user = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris,providers) VALUES($1,$2,$1,'IDV Fixture',$2,$1,'secret','[]',$3)")
        .bind(&app).bind(&owner).bind(json!([{"name":format!("{}/{}",owner,provider.name)}])).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,id_card_type,id_card,real_name,signup_application) VALUES($1,$2,'tester','Fixture','hash','Fixture ID','fixture-id-123','Fixture Person',$3)")
        .bind(&user).bind(&owner).bind(&app).execute(&pool).await.unwrap();
    let global = principal("built-in", true);
    fixture.json("/verify", json!({"verified":false}));
    assert!(operations::verify_identification(&pool, &global, &owner, "tester", None).await.is_err());
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT is_verified FROM users WHERE id=$1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    assert!(
        operations::verify_identification(&pool, &principal("different", true), &owner, "tester", None).await.is_err()
    );
    assert!(operations::verify_identification(&pool, &global, &owner, "tester", Some("unconfigured")).await.is_err());
    fixture.json("/verify", json!({"verified":true}));
    assert_eq!(
        operations::verify_identification(&pool, &global, &owner, "tester", None).await.unwrap(),
        "Fixture Person"
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT is_verified FROM users WHERE id=$1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    let audit: String = sqlx::query_scalar("SELECT subject_sha256 FROM identification_verifications WHERE user_id=$1")
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audit.len(), 64);
    assert!(!audit.contains("fixture-id"));
    assert!(fixture.requests.lock().unwrap().iter().any(|request| {
        request.contains("fixture-id-123")
            && request.to_ascii_lowercase().contains("authorization: bearer fixture-only-secret")
    }));
    assert!(operations::verify_identification(&pool, &global, &owner, "tester", None).await.is_err());
    sqlx::query("UPDATE users SET id_card='changed-identity' WHERE id=$1").bind(&user).execute(&pool).await.unwrap();
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT is_verified FROM users WHERE id=$1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    sqlx::query("DELETE FROM users WHERE id=$1").bind(user).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM applications WHERE id=$1").bind(app).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM providers WHERE id=$1").bind(provider.id).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM organizations WHERE name=$1").bind(&owner).execute(&pool).await.unwrap();
}

#[handler]
async fn tenant(depot: &mut Depot) {
    depot.insert("user_id", "system-gap-http".to_string());
    depot.insert("user_owner", "tenant".to_string());
    depot.insert("user_name", "tester".to_string());
    depot.insert("is_admin", true);
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn rest_provider_configuration_persists_scan_fields_and_preserves_omitted_values() {
    let pool = pool().await;
    let name = uuid::Uuid::new_v4().to_string();
    let request: casdog::models::provider::CreateProviderRequest = serde_json::from_value(json!({
        "owner":"tenant","name":name,"display_name":"REST scanner","category":"Scan","type":"MCP Scan",
        "sub_type":"Intranet Scan","content":"8080,3000","scopes":"10.0.0.1/32","endpoint":"/mcp"
    }))
    .unwrap();
    let created = casdog::services::ProviderService::create(&pool, request).await.unwrap();
    assert_eq!(created.content.as_deref(), Some("8080,3000"));
    assert_eq!(created.scopes.as_deref(), Some("10.0.0.1/32"));
    let update: casdog::models::provider::UpdateProviderRequest =
        serde_json::from_value(json!({"content":"3001","scopes":"10.0.0.2/32"})).unwrap();
    let updated = casdog::services::ProviderService::update(&pool, &created.id, update).await.unwrap();
    assert_eq!(updated.content.as_deref(), Some("3001"));
    assert_eq!(updated.scopes.as_deref(), Some("10.0.0.2/32"));
    let update: casdog::models::provider::UpdateProviderRequest =
        serde_json::from_value(json!({"display_name":"Renamed"})).unwrap();
    let updated = casdog::services::ProviderService::update(&pool, &created.id, update).await.unwrap();
    assert_eq!(updated.content.as_deref(), Some("3001"));
    assert_eq!(updated.scopes.as_deref(), Some("10.0.0.2/32"));
    let fetched = casdog::services::ProviderService::get_by_id(&pool, &created.id).await.unwrap();
    assert_eq!(fetched.content.as_deref(), Some("3001"));
    sqlx::query("DELETE FROM providers WHERE id=$1").bind(created.id).execute(&pool).await.unwrap();
}

#[tokio::test]
async fn system_mutations_require_global_admin_and_provider_queries_require_owner() {
    let lazy = PgPool::connect_lazy("postgres://nobody@localhost/unused").unwrap();
    operations::reconcile_upgrades(&lazy, &SystemGapConfig::default()).await.unwrap();
    let service = Service::new(
        Router::with_path("api")
            .hoop(salvo::affix_state::AffixList::new().inject(lazy))
            .hoop(tenant)
            .push(system_gaps::routes()),
    );
    for endpoint in ["upgrade-system", "sync-intranet-servers"] {
        assert_eq!(
            TestClient::post(format!("http://localhost/api/{endpoint}"))
                .json(&json!({"version":"v9.9.9"}))
                .send(&service)
                .await
                .status_code,
            Some(StatusCode::FORBIDDEN)
        );
    }
    assert_eq!(
        TestClient::get("http://localhost/api/get-upgrade-info").send(&service).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let mut response = TestClient::get("http://localhost/api/scan?owner=other&name=provider").send(&service).await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["code"], 403);
}
