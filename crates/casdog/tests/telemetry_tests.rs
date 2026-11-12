//! Real generated OTLP protobuf vectors, wire limits and normal authenticated
//! receiver APIs backed by PostgreSQL (not a JSON placeholder receiver).
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    hoops::authz::Principal,
    services::telemetry_service::{self as telemetry, MAX_BODY, ReceiverInput, Signal},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use opentelemetry_proto::tonic::{
    collector::{
        logs::v1::{ExportLogsServiceRequest, ExportLogsServiceResponse},
        metrics::v1::{ExportMetricsServiceRequest, ExportMetricsServiceResponse},
        trace::v1::{ExportTraceServiceRequest, ExportTraceServiceResponse},
    },
    common::v1::{AnyValue, KeyValue, any_value::Value as Any},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    metrics::v1::{
        Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric::Data,
        number_data_point::Value as Number,
    },
    resource::v1::Resource,
    trace::v1::{ResourceSpans, ScopeSpans, Span},
};
use prost::Message;
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::io::Write;

fn traces() -> Vec<u8> {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "organization".into(),
                    value: Some(AnyValue {
                        value: Some(Any::StringValue("forged-tenant".into())),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![1; 16],
                    span_id: vec![2; 8],
                    name: "openclaw.agent".into(),
                    start_time_unix_nano: 1_700_000_000_000_000_000,
                    end_time_unix_nano: 1_700_000_000_000_000_001,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}
fn metrics() -> Vec<u8> {
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            scope_metrics: vec![ScopeMetrics {
                metrics: vec![Metric {
                    name: "openclaw.tokens".into(),
                    data: Some(Data::Gauge(Gauge {
                        data_points: vec![NumberDataPoint {
                            value: Some(Number::AsInt(42)),
                            ..Default::default()
                        }],
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}
fn logs() -> Vec<u8> {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 1_700_000_000_000_000_000,
                    body: Some(AnyValue {
                        value: Some(Any::StringValue("hello OpenClaw".into())),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn official_protobuf_signals_decode_and_preserve_otlp_json_semantics() {
    for (signal, bytes, key) in [
        (Signal::Traces, traces(), "resourceSpans"),
        (Signal::Metrics, metrics(), "resourceMetrics"),
        (Signal::Logs, logs(), "resourceLogs"),
    ] {
        let (raw, text, count) = telemetry::decode_batch(signal, &bytes, None).unwrap();
        assert_eq!(raw, bytes);
        assert_eq!(count, 1);
        let value: Value = serde_json::from_str(&text).unwrap();
        assert!(value[key].is_array());
        let (decoded, text2, count2) =
            telemetry::decode_batch(signal, &gzip(&bytes), Some("gzip")).unwrap();
        assert_eq!((decoded, text2, count2), (raw, text, count));
    }
    let (_, trace, _) = telemetry::decode_batch(Signal::Traces, &traces(), None).unwrap();
    assert!(trace.contains("01010101010101010101010101010101"));
    assert!(trace.contains("\"1700000000000000000\""));
    for signal in [Signal::Traces, Signal::Metrics, Signal::Logs] {
        assert_eq!(telemetry::decode_batch(signal, &[], None).unwrap().2, 0);
    }
}
#[test]
fn protobuf_unknown_fields_are_retained_and_bad_ids_wire_and_encoding_are_rejected() {
    let mut bytes = traces();
    bytes.extend_from_slice(&[0xf8, 0x07, 0x2a]); // Unknown field 127, varint42.
    assert_eq!(
        telemetry::decode_batch(Signal::Traces, &bytes, None)
            .unwrap()
            .0,
        bytes
    );
    for invalid in [vec![0], vec![0x0a, 0xff, 0xff], vec![0x0f], vec![0x80; 12]] {
        assert_eq!(
            telemetry::decode_batch(Signal::Traces, &invalid, None)
                .unwrap_err()
                .status,
            400
        );
    }
    let mut request = ExportTraceServiceRequest::decode(traces().as_slice()).unwrap();
    request.resource_spans[0].scope_spans[0].spans[0].trace_id = vec![0; 16];
    assert_eq!(
        telemetry::decode_batch(Signal::Traces, &request.encode_to_vec(), None)
            .unwrap_err()
            .status,
        400
    );
    assert_eq!(
        telemetry::decode_batch(Signal::Logs, b"not gzip", Some("gzip"))
            .unwrap_err()
            .status,
        400
    );
    assert_eq!(
        telemetry::decode_batch(Signal::Logs, &logs(), Some("br"))
            .unwrap_err()
            .status,
        415
    );
}
#[test]
fn compressed_size_expansion_structural_amplification_and_recursion_are_bounded() {
    assert_eq!(
        telemetry::decode_batch(Signal::Logs, &vec![0; MAX_BODY + 1], None)
            .unwrap_err()
            .status,
        413
    );
    let compressed = gzip(&vec![0; MAX_BODY + 1]);
    assert_eq!(
        telemetry::decode_batch(Signal::Logs, &compressed, Some("gzip"))
            .unwrap_err()
            .status,
        413
    );
    // Fifty thousand empty ResourceLogs would otherwise allocate a much larger
    // vector before the generated decoder reached our semantic item budget.
    let many = [0x0a, 0].repeat(50_001);
    assert_eq!(
        telemetry::decode_batch(Signal::Logs, &many, None)
            .unwrap_err()
            .status,
        413
    );
    // Deep recursive AnyValue.arrayValue, valid protobuf but beyond the limit.
    fn length(n: usize) -> Vec<u8> {
        let mut n = n;
        let mut out = Vec::new();
        while n >= 128 {
            out.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        out.push(n as u8);
        out
    }
    fn field(tag: u8, child: Vec<u8>) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(length(child.len()));
        out.extend(child);
        out
    }
    let mut any = vec![0x0a, 0];
    for _ in 0..40 {
        any = field(0x2a, field(0x0a, any));
    }
    let batch = field(0x0a, field(0x12, field(0x12, field(0x2a, any))));
    assert_eq!(
        telemetry::decode_batch(Signal::Logs, &batch, None)
            .unwrap_err()
            .status,
        400
    );
}

#[test]
fn gzip_members_are_fully_consumed_and_invalid_or_oversized_trailing_members_are_rejected() {
    let bytes = logs();
    let mut two = gzip(&bytes);
    two.extend(gzip(&bytes));
    let (raw, _, count) = telemetry::decode_batch(Signal::Logs, &two, Some("gzip")).unwrap();
    let mut expected = bytes.clone();
    expected.extend(&bytes);
    assert_eq!(raw, expected);
    assert_eq!(count, 2);
    let mut trailing = gzip(&bytes);
    trailing.extend(b"unread invalid trailing member");
    assert_eq!(
        telemetry::decode_batch(Signal::Logs, &trailing, Some("gzip"))
            .unwrap_err()
            .status,
        400
    );
    let mut truncated = gzip(&bytes);
    let second = gzip(&bytes);
    truncated.extend(&second[..second.len() - 4]);
    assert_eq!(
        telemetry::decode_batch(Signal::Logs, &truncated, Some("gzip"))
            .unwrap_err()
            .status,
        400
    );
    let mut expanded = gzip(&bytes);
    expanded.extend(gzip(&vec![0; MAX_BODY]));
    assert_eq!(
        telemetry::decode_batch(Signal::Logs, &expanded, Some("gzip"))
            .unwrap_err()
            .status,
        413
    );
}

struct Fixture {
    pool: PgPool,
    service: Service,
    owner: String,
    other: String,
    admin: String,
    user: String,
    provider: String,
    app: String,
    other_app: String,
}
impl Fixture {
    async fn new() -> Self {
        AppConfig::load().unwrap();
        let url = std::env::var("CASDOG_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();
        let diesel = create_diesel_pool(&url).await.unwrap();
        let service = Service::new(casdog::routes::create_router()).hoop(
            salvo::affix_state::AffixList::new()
                .inject(pool.clone())
                .inject(diesel),
        );
        let owner = format!("otlp-{}", uuid::Uuid::new_v4());
        let other = format!("otlp-other-{}", uuid::Uuid::new_v4());
        let admin = uuid::Uuid::new_v4().to_string();
        let user = uuid::Uuid::new_v4().to_string();
        let provider = uuid::Uuid::new_v4().to_string();
        let app = uuid::Uuid::new_v4().to_string();
        let other_app = uuid::Uuid::new_v4().to_string();
        for tenant in [&owner, &other] {
            sqlx::query("INSERT INTO organizations(id,owner,name,display_name) VALUES($1,$2,$2,'OTLP tenant')").bind(uuid::Uuid::new_v4().to_string()).bind(tenant).execute(&pool).await.unwrap();
        }
        for (id, name, is_admin) in [(&admin, "admin", true), (&user, "ordinary", false)] {
            sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,$3,'test-not-a-password',$4)").bind(id).bind(&owner).bind(name).bind(is_admin).execute(&pool).await.unwrap();
        }
        for (id, tenant) in [(&app, &owner), (&other_app, &other)] {
            sqlx::query("INSERT INTO applications(id,owner,name,display_name,organization,client_id,client_secret,redirect_uris) VALUES($1,$2,'app','OTLP app',$2,$1,'test-only-secret','')").bind(id).bind(tenant).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,sub_type) VALUES($1,$2,'openclaw','OTLP','Log','Agent','OpenClaw')").bind(&provider).bind(&owner).execute(&pool).await.unwrap();
        Self {
            pool,
            service,
            owner,
            other,
            admin,
            user,
            provider,
            app,
            other_app,
        }
    }
    fn principal(&self) -> Principal {
        Principal {
            id: self.admin.clone(),
            owner: self.owner.clone(),
            name: "admin".into(),
            admin: true,
            application_identity: false,
        }
    }
    fn jwt(&self, admin: bool) -> String {
        let now = chrono::Utc::now();
        encode(&Header::default(),&json!({"sub":if admin{&self.admin}else{&self.user},"owner":self.owner,"name":if admin{"admin"}else{"ordinary"},"is_admin":admin,"iat":now.timestamp(),"issued_at_ms":now.timestamp_millis(),"exp":now.timestamp()+3600,"iss":AppConfig::get().jwt.issuer}),&EncodingKey::from_secret(AppConfig::get().jwt.secret.as_bytes())).unwrap()
    }
    fn input(&self) -> Value {
        json!({"provider":self.provider,"application":self.app,"authMode":"token"})
    }
    async fn save(&self, input: Value) -> Value {
        let mut response = TestClient::post("http://localhost/api/telemetry/receivers")
            .bearer_auth(self.jwt(true))
            .json(&input)
            .send(&self.service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        response.take_json().await.unwrap()
    }
    async fn receiver(&self) -> (String, String) {
        let value = self.save(self.input()).await;
        (
            value["data"]["id"].as_str().unwrap().into(),
            value["data"]["token"].as_str().unwrap().into(),
        )
    }
    async fn export(&self, path: &str, token: Option<&str>, body: Vec<u8>, gzip: bool) -> Response {
        let mut req = TestClient::post(format!("http://localhost{path}"))
            .add_header("content-type", "application/x-protobuf", true)
            .body(body);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        if gzip {
            req = req.add_header("content-encoding", "gzip", true);
        }
        req.send(&self.service).await
    }
    async fn count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM telemetry_ingestions WHERE organization=$1")
            .bind(&self.owner)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-039"]
async fn actual_http_protobuf_and_gzip_all_signals_commit_tenant_bound_entries_and_raw_bytes() {
    let f = Fixture::new().await;
    let (_, token) = f.receiver().await;
    for (path, bytes, compressed) in [
        ("/api/v1/traces", traces(), false),
        ("/v1/metrics", metrics(), true),
        ("/api/v1/logs", logs(), true),
    ] {
        let mut response = f
            .export(
                path,
                Some(&token),
                if compressed {
                    gzip(&bytes)
                } else {
                    bytes.clone()
                },
                compressed,
            )
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(response.headers()["content-type"], "application/x-protobuf");
        let body = response.take_bytes(None).await.unwrap();
        match path {
            "/api/v1/traces" => {
                assert!(
                    ExportTraceServiceResponse::decode(body)
                        .unwrap()
                        .partial_success
                        .is_none()
                );
            }
            "/v1/metrics" => {
                assert!(
                    ExportMetricsServiceResponse::decode(body)
                        .unwrap()
                        .partial_success
                        .is_none()
                );
            }
            _ => {
                assert!(
                    ExportLogsServiceResponse::decode(body)
                        .unwrap()
                        .partial_success
                        .is_none()
                );
            }
        }
    }
    assert_eq!(f.count().await, 3);
    let rows:Vec<(String,i32,Vec<u8>,Value)>=sqlx::query_as("SELECT t.signal,t.item_count,t.protobuf,e.document FROM telemetry_ingestions t JOIN casdoor_objects e ON e.kind='entry' AND e.owner=t.organization AND e.name=t.id WHERE t.organization=$1 ORDER BY signal").bind(&f.owner).fetch_all(&f.pool).await.unwrap();
    assert_eq!(rows.len(), 3);
    for (signal, count, bytes, document) in rows {
        assert_eq!(count, 1);
        assert_eq!(document["owner"], f.owner);
        assert_eq!(document["application"], format!("{}/app", f.owner));
        assert_eq!(document["provider"], format!("{}/openclaw", f.owner));
        assert_eq!(
            bytes,
            match signal.as_str() {
                "traces" => traces(),
                "metrics" => metrics(),
                _ => logs(),
            }
        );
        let message: Value = serde_json::from_str(document["message"].as_str().unwrap()).unwrap();
        assert!(message.is_object());
        let path = format!(
            "http://localhost/api/get-entry?id={}/{}",
            f.owner,
            document["name"].as_str().unwrap()
        );
        let mut response = TestClient::get(path)
            .bearer_auth(f.jwt(true))
            .send(&f.service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let read: Value = response.take_json().await.unwrap();
        assert_eq!(read["data"]["message"], document["message"]);
        let response = TestClient::post(format!(
            "http://localhost/api/update-entry?id={}/{}",
            f.owner,
            document["name"].as_str().unwrap()
        ))
        .bearer_auth(f.jwt(true))
        .json(&json!({"displayName":"OTLP entry"}))
        .send(&f.service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-039"]
async fn receiver_admin_scope_masking_token_preservation_rotation_and_revocation_work_across_pools()
{
    let f = Fixture::new().await;
    let (id, token) = f.receiver().await;
    let ordinary = TestClient::post("http://localhost/api/telemetry/receivers")
        .bearer_auth(f.jwt(false))
        .json(&f.input())
        .send(&f.service)
        .await;
    assert_eq!(ordinary.status_code, Some(StatusCode::FORBIDDEN));
    let mut bad = f.input();
    bad["application"] = json!(f.other_app);
    let response = TestClient::post("http://localhost/api/telemetry/receivers")
        .bearer_auth(f.jwt(true))
        .json(&bad)
        .send(&f.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    let preserved = f.save(f.input()).await;
    assert!(preserved["data"].get("token").is_none());
    let mut response = TestClient::get("http://localhost/api/telemetry/receivers")
        .bearer_auth(f.jwt(true))
        .send(&f.service)
        .await;
    let listed: Value = response.take_json().await.unwrap();
    assert_eq!(listed["data"].as_array().unwrap().len(), 1);
    let public = listed.to_string();
    assert!(!public.contains(&token));
    assert!(!public.contains("token_hash"));
    let stored: String =
        sqlx::query_scalar("SELECT token_hash FROM telemetry_receivers WHERE id=$1")
            .bind(&id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(stored.len(), 64);
    assert_ne!(stored, token);
    let other_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    telemetry::ingest(
        &other_pool,
        Signal::Logs,
        Some(&format!("Bearer {token}")),
        None,
        "test",
        &logs(),
        None,
    )
    .await
    .unwrap();
    let mut rotate = f.input();
    rotate["rotate"] = json!(true);
    let rotated = f.save(rotate).await;
    let new = rotated["data"]["token"].as_str().unwrap();
    assert_ne!(new, token);
    assert_eq!(
        telemetry::ingest(
            &other_pool,
            Signal::Logs,
            Some(&format!("Bearer {token}")),
            None,
            "test",
            &logs(),
            None
        )
        .await
        .unwrap_err()
        .status,
        401
    );
    telemetry::ingest(
        &other_pool,
        Signal::Logs,
        Some(&format!("Bearer {new}")),
        None,
        "test",
        &logs(),
        None,
    )
    .await
    .unwrap();
    let response = TestClient::delete(format!("http://localhost/api/telemetry/receivers/{id}"))
        .bearer_auth(f.jwt(true))
        .send(&f.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(
        telemetry::ingest(
            &other_pool,
            Signal::Logs,
            Some(&format!("Bearer {new}")),
            None,
            "test",
            &logs(),
            None
        )
        .await
        .unwrap_err()
        .status,
        401
    );
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-039"]
async fn source_ip_requires_explicit_unique_rules_ignores_forwarded_and_never_falls_back_on_bad_token()
 {
    let f = Fixture::new().await;
    let mut input = f.input();
    input["authMode"] = json!("source_ip");
    assert!(
        telemetry::save(
            &f.pool,
            &f.principal(),
            serde_json::from_value::<ReceiverInput>(input.clone()).unwrap()
        )
        .await
        .is_err()
    );
    input["allowedSources"] = json!(["0.0.0.0/0"]);
    assert!(
        telemetry::save(
            &f.pool,
            &f.principal(),
            serde_json::from_value(input.clone()).unwrap()
        )
        .await
        .is_err()
    );
    input["allowedSources"] = json!(["192.0.2.17/24"]);
    let created = f.save(input.clone()).await;
    assert_eq!(created["data"]["allowedSources"], json!(["192.0.2.0/24"]));
    assert!(created["data"].get("token").is_none());
    let peer = Some("192.0.2.34".parse().unwrap());
    telemetry::ingest(&f.pool, Signal::Logs, None, peer, "test", &logs(), None)
        .await
        .unwrap();
    for auth in [Some("Bearer otlp_invalid"), Some("Basic Zm9vOmJhcg==")] {
        assert_eq!(
            telemetry::ingest(&f.pool, Signal::Logs, auth, peer, "test", &logs(), None)
                .await
                .unwrap_err()
                .status,
            401
        );
    }
    let response = TestClient::post("http://localhost/v1/logs")
        .add_header("content-type", "application/x-protobuf", true)
        .add_header("x-forwarded-for", "192.0.2.34", true)
        .body(logs())
        .send(&f.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    let second = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO providers(id,owner,name,display_name,category,type,sub_type) VALUES($1,$2,'openclaw2','OTLP','Log','Agent','OpenClaw')").bind(&second).bind(&f.owner).execute(&f.pool).await.unwrap();
    input["provider"] = json!(second);
    f.save(input).await;
    assert_eq!(
        telemetry::ingest(&f.pool, Signal::Logs, None, peer, "test", &logs(), None)
            .await
            .unwrap_err()
            .status,
        401
    );
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-039"]
async fn malformed_and_semantic_failures_never_create_entries_and_persist_the_error_budget() {
    let f = Fixture::new().await;
    let (id, token) = f.receiver().await;
    for (body, compressed) in [(vec![0x0a, 0xff], false), (b"bad gzip".to_vec(), true)] {
        let response = f.export("/v1/traces", Some(&token), body, compressed).await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }
    let response = f
        .export(
            "/v1/traces",
            Some("otlp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            traces(),
            false,
        )
        .await;
    assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    let response = TestClient::post("http://localhost/v1/traces")
        .bearer_auth(&token)
        .json(&json!({"resourceSpans":[]}))
        .send(&f.service)
        .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::UNSUPPORTED_MEDIA_TYPE)
    );
    let count: i32 = sqlx::query_scalar("SELECT batch_count FROM telemetry_receivers WHERE id=$1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    assert_eq!(f.count().await, 0);
    let response = f
        .export("/v1/traces", Some(&token), Vec::new(), false)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(f.count().await, 1);
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-039"]
async fn receiver_rate_budget_is_atomic_across_concurrent_instance_pools() {
    let f = Fixture::new().await;
    let (id, token) = f.receiver().await;
    sqlx::query("UPDATE telemetry_receivers SET batch_count=119,window_started_at=clock_timestamp() WHERE id=$1").bind(id).execute(&f.pool).await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("CASDOG_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let authorization = format!("Bearer {token}");
    let bytes = logs();
    let (a, b) = tokio::join!(
        telemetry::ingest(
            &f.pool,
            Signal::Logs,
            Some(&authorization),
            None,
            "a",
            &bytes,
            None
        ),
        telemetry::ingest(
            &pool,
            Signal::Logs,
            Some(&authorization),
            None,
            "b",
            &bytes,
            None
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()).unwrap().status, 429);
    assert_eq!(f.count().await, 1);
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-039"]
async fn provider_application_and_organization_changes_revoke_live_approval() {
    let f = Fixture::new().await;
    let (_, token) = f.receiver().await;
    sqlx::query("UPDATE providers SET sub_type='Other' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.export("/v1/logs", Some(&token), logs(), false)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE providers SET sub_type='OpenClaw' WHERE id=$1")
        .bind(&f.provider)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE applications SET organization=$2 WHERE id=$1")
        .bind(&f.app)
        .bind(&f.other)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.export("/v1/logs", Some(&token), logs(), false)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    sqlx::query("UPDATE applications SET organization=$2 WHERE id=$1")
        .bind(&f.app)
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE organizations SET disable_signin=true WHERE name=$1")
        .bind(&f.owner)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.export("/v1/logs", Some(&token), logs(), false)
            .await
            .status_code,
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(f.count().await, 0);
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-039"]
async fn storage_failure_returns_retryable_error_and_rolls_back_both_raw_batch_and_entry() {
    let f = Fixture::new().await;
    let (_, token) = f.receiver().await;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let function = format!("otlp_fail_{suffix}");
    sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.organization='{}' THEN RAISE EXCEPTION 'test storage failure'; END IF; RETURN NEW; END $$",f.owner)).execute(&f.pool).await.unwrap();
    sqlx::query(&format!("CREATE TRIGGER {function} BEFORE INSERT ON telemetry_ingestions FOR EACH ROW EXECUTE FUNCTION {function}()" )).execute(&f.pool).await.unwrap();
    let response = f.export("/v1/logs", Some(&token), logs(), false).await;
    sqlx::query(&format!("DROP TRIGGER {function} ON telemetry_ingestions"))
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION {function}()"))
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(response.status_code, Some(StatusCode::SERVICE_UNAVAILABLE));
    assert_eq!(f.count().await, 0);
    let entries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM casdoor_objects WHERE kind='entry' AND owner=$1")
            .bind(&f.owner)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(entries, 0);
    assert_eq!(
        f.export("/v1/logs", Some(&token), logs(), false)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL and migrations 001-039"]
async fn upstream_agent_crud_masks_tokens_in_detail_and_list_and_preserves_masked_updates() {
    let f = Fixture::new().await;
    let secret = "agent-secret-must-never-appear-in-read-api";
    let input = json!({"owner":f.owner,"name":"agent","url":"https://example.invalid/agent","application":format!("{}/app",f.owner),"token":secret});
    let response = TestClient::post("http://localhost/api/add-agent")
        .bearer_auth(f.jwt(true))
        .json(&input)
        .send(&f.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    for path in [
        format!("/api/get-agent?id={}/agent", f.owner),
        format!("/api/get-agents?owner={}", f.owner),
    ] {
        let mut response = TestClient::get(format!("http://localhost{path}"))
            .bearer_auth(f.jwt(true))
            .send(&f.service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let value: Value = response.take_json().await.unwrap();
        assert!(!value.to_string().contains(secret));
    }
    for placeholder in ["", "***"] {
        let response = TestClient::post(format!(
            "http://localhost/api/update-agent?id={}/agent",
            f.owner
        ))
        .bearer_auth(f.jwt(true))
        .json(&json!({"token":placeholder,"displayName":"Updated"}))
        .send(&f.service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let stored:String=sqlx::query_scalar("SELECT document->>'token' FROM casdoor_objects WHERE kind='agent' AND owner=$1 AND name='agent'").bind(&f.owner).fetch_one(&f.pool).await.unwrap();
        assert_eq!(stored, secret);
    }
    let response = TestClient::get(format!(
        "http://localhost/api/get-agent?id={}/agent",
        f.other
    ))
    .bearer_auth(f.jwt(true))
    .send(&f.service)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
}
