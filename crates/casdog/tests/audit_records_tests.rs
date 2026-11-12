use casdog::{
    hoops::record_filter::{RecordFilter, RequestLogger},
    models::RecordFilterRequest,
    services::RecordService,
};
use salvo::{prelude::*, test::TestClient};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};

#[handler]
async fn reached() -> &'static str {
    "ok"
}

#[derive(Clone)]
struct Buffer(Arc<Mutex<Vec<u8>>>);
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn request_tracing_never_records_query_credentials_or_login_codes() {
    let data = Arc::new(Mutex::new(Vec::new()));
    let writer = Buffer(data.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let service = Service::new(Router::with_path("api/probe").get(reached)).hoop(RequestLogger);
    let response=TestClient::get("http://localhost/api/probe?accessKey=public-id&accessSecret=NEVER_LOG_SECRET&code=NEVER_LOG_CODE")
        .add_header("Authorization","Basic NEVER_LOG_HEADER",true).send(&service).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let output = String::from_utf8(data.lock().unwrap().clone()).unwrap();
    assert!(
        output.contains("HTTP request") && output.contains("/api/probe"),
        "{output}"
    );
    for sensitive in [
        "NEVER_LOG_SECRET",
        "NEVER_LOG_CODE",
        "NEVER_LOG_HEADER",
        "accessSecret",
        "public-id",
    ] {
        assert!(!output.contains(sensitive), "{output}");
    }
}

#[derive(Clone)]
struct Actor {
    owner: String,
    name: String,
}
#[handler]
async fn identify(depot: &mut Depot) {
    let actor = depot.obtain::<Actor>().unwrap().clone();
    depot.insert("user_owner", actor.owner);
    depot.insert("user_name", actor.name);
}
async fn pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires migrated disposable PostgreSQL"]
async fn audit_filter_persists_long_service_actor_and_record_api_reads_real_timestamp() {
    let pool = pool().await;
    let owner = format!("audit-{}", uuid::Uuid::new_v4());
    let actor = format!("app/{owner}/{}", "n".repeat(90));
    let service = Service::new(Router::with_path("api/probe").get(reached))
        .hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(Actor {
                    owner: owner.clone(),
                    name: actor.clone(),
                }),
        )
        .hoop(identify)
        .hoop(RecordFilter);
    let response = TestClient::get("http://localhost/api/probe?accessSecret=NEVER_RECORD_SECRET")
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let mut found = false;
    for _ in 0..100 {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE owner=$1")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
        if count == 1 {
            found = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(found, "RecordFilter must actually persist its audit row");
    let filter = RecordFilterRequest {
        owner: Some(owner.clone()),
        organization: None,
        user: Some(actor.clone()),
        action: None,
        start_time: None,
        end_time: None,
    };
    let (rows, total) = RecordService::list_filtered(&pool, filter, 1, 20)
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows.len(), 1);
    let record = RecordService::get_by_id(&pool, &rows[0].id).await.unwrap();
    assert_eq!(record.user.as_deref(), Some(actor.as_str()));
    assert_eq!(record.request_uri, "/api/probe");
    assert!(record.created_at > chrono::Utc::now() - chrono::Duration::minutes(1));
    assert!(
        !serde_json::to_string(&record)
            .unwrap()
            .contains("NEVER_RECORD_SECRET")
    );
    sqlx::query("DELETE FROM records WHERE owner=$1")
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL schema creation"]
async fn audit_migration_preserves_legacy_actor_and_database_timezone_instant() {
    let pool = pool().await;
    let mut connection = pool.acquire().await.unwrap();
    for kind in ["TIMESTAMP", "TIMESTAMPTZ"] {
        let schema = format!("audit_{}", uuid::Uuid::new_v4().simple());
        let instant = if kind == "TIMESTAMP" {
            "2025-03-05 12:34:56"
        } else {
            "2025-11-02 01:30:00-04"
        };
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}; SET search_path TO {schema},public; SET TIME ZONE 'America/New_York'; CREATE TABLE records(id TEXT PRIMARY KEY,user_id VARCHAR(100),created_at {kind} NOT NULL); INSERT INTO records VALUES('old','legacy-user','{instant}');"))
            .execute(&mut *connection).await.unwrap();
        let query = if kind == "TIMESTAMP" {
            "SELECT created_at AT TIME ZONE current_setting('TimeZone') FROM records WHERE id='old'"
        } else {
            "SELECT created_at FROM records WHERE id='old'"
        };
        let before: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(query)
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../../../migrations/032_audit_records.sql"))
            .execute(&mut *connection)
            .await
            .unwrap();
        let (actor, after): (String, chrono::DateTime<chrono::Utc>) =
            sqlx::query_as("SELECT \"user\",created_at FROM records WHERE id='old'")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
        assert_eq!(actor, "legacy-user");
        assert_eq!(after, before);
        sqlx::query("UPDATE records SET \"user\"=$1 WHERE id='old'")
            .bind("service-actor".repeat(30))
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::raw_sql(&format!(
            "RESET TimeZone; RESET search_path; DROP SCHEMA {schema} CASCADE;"
        ))
        .execute(&mut *connection)
        .await
        .unwrap();
    }
    drop(connection);
    pool.close().await;
}
