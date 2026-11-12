use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};

use casdog::{
    hoops::authz::Principal,
    services::{
        protocol_gap_service,
        providers::{StorageProvider, s3_storage::S3StorageProvider},
    },
};
use hmac::{Hmac, Mac};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const RANGE: u8 = 0;
const IGNORE_RANGE: u8 = 1;
const CHUNKED: u8 = 2;
const INVALID_RANGE: u8 = 3;
const REDIRECT: u8 = 4;
const SHORT_RANGE: u8 = 5;
const SLOW_CHUNKED: u8 = 6;
const UNKNOWN_PARTIAL: u8 = 7;

#[derive(Default)]
struct WireState {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    mode: AtomicU8,
    fail_upload: AtomicBool,
    requests: AtomicUsize,
    auth_failures: AtomicUsize,
    ranges: Mutex<Vec<String>>,
}
struct S3Fixture {
    endpoint: String,
    state: Arc<WireState>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for S3Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl S3Fixture {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(WireState::default());
        let server = state.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let state = server.clone();
                tokio::spawn(async move {
                    let _ = serve(socket, state).await;
                });
            }
        });
        Self {
            endpoint,
            state,
            task,
        }
    }
    fn provider(&self) -> S3StorageProvider {
        S3StorageProvider::new(
            "fixture-access".into(),
            "fixture-secret".into(),
            "us-east-1".into(),
            "transcripts".into(),
            self.endpoint.clone(),
        )
    }
}

fn mac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
// The fixture authenticates the actual wire path, Host, Range and body. A
// published AWS known-answer test separately anchors the signing algorithm.
fn authorized(method: &str, path: &str, headers: &BTreeMap<String, String>, body: &[u8]) -> bool {
    let Some(date) = headers.get("x-amz-date").filter(|date| date.len() == 16) else {
        return false;
    };
    let digest = hex::encode(Sha256::digest(body));
    if headers.get("x-amz-content-sha256") != Some(&digest) {
        return false;
    }
    let names = if headers.contains_key("range") {
        vec!["host", "range", "x-amz-content-sha256", "x-amz-date"]
    } else {
        vec!["host", "x-amz-content-sha256", "x-amz-date"]
    };
    let canonical_headers = names
        .iter()
        .map(|name| {
            format!(
                "{name}:{}\n",
                headers.get(*name).map(String::as_str).unwrap_or("")
            )
        })
        .collect::<String>();
    let signed = names.join(";");
    let request = format!("{method}\n{path}\n\n{canonical_headers}\n{signed}\n{digest}");
    let scope = format!("{}/us-east-1/s3/aws4_request", &date[..8]);
    let payload = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        hex::encode(Sha256::digest(request.as_bytes()))
    );
    let key = mac(b"AWS4fixture-secret", &date[..8]);
    let key = mac(&key, "us-east-1");
    let key = mac(&key, "s3");
    let key = mac(&key, "aws4_request");
    headers.get("authorization")
        == Some(&format!(
            "AWS4-HMAC-SHA256 Credential=fixture-access/{scope},SignedHeaders={signed},Signature={}",
            hex::encode(mac(&key, &payload))
        ))
}
async fn reply(
    socket: &mut TcpStream,
    status: &str,
    headers: &str,
    body: &[u8],
) -> std::io::Result<()> {
    socket
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    socket.write_all(body).await
}
async fn chunk(socket: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    socket
        .write_all(format!("{:X}\r\n", bytes.len()).as_bytes())
        .await?;
    socket.write_all(bytes).await?;
    socket.write_all(b"\r\n").await
}
async fn serve(mut socket: TcpStream, state: Arc<WireState>) -> std::io::Result<()> {
    let mut request = Vec::new();
    let boundary = loop {
        let mut buffer = [0u8; 8192];
        let read = socket.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(position) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            break position + 4;
        }
        assert!(request.len() < 64 * 1024);
    };
    let head = String::from_utf8(request[..boundary].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap();
    let path = first.next().unwrap();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while request.len() - boundary < length {
        let mut buffer = [0u8; 8192];
        let read = socket.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
    }
    state.requests.fetch_add(1, Ordering::SeqCst);
    if !authorized(
        method,
        path,
        &headers,
        &request[boundary..boundary + length],
    ) {
        state.auth_failures.fetch_add(1, Ordering::SeqCst);
        return reply(&mut socket, "403 Forbidden", "", b"invalid signature").await;
    }
    match method {
        "PUT" => {
            if state.fail_upload.load(Ordering::SeqCst) {
                return reply(
                    &mut socket,
                    "503 Service Unavailable",
                    "",
                    b"fixture-secret: must not appear in API errors",
                )
                .await;
            }
            state.objects.lock().unwrap().insert(
                path.to_string(),
                request[boundary..boundary + length].to_vec(),
            );
            reply(&mut socket, "200 OK", "", b"").await
        }
        "DELETE" => {
            let existed = state.objects.lock().unwrap().remove(path).is_some();
            reply(
                &mut socket,
                if existed {
                    "204 No Content"
                } else {
                    "404 Not Found"
                },
                "",
                b"",
            )
            .await
        }
        "GET" => {
            let bytes = state.objects.lock().unwrap().get(path).cloned();
            let Some(bytes) = bytes else {
                return reply(&mut socket, "404 Not Found", "", b"").await;
            };
            let mode = state.mode.load(Ordering::SeqCst);
            if mode == REDIRECT {
                return reply(
                    &mut socket,
                    "307 Temporary Redirect",
                    "Location: http://127.0.0.1:1/leaked\r\n",
                    b"",
                )
                .await;
            }
            if let Some(range) = headers.get("range") {
                state.ranges.lock().unwrap().push(range.clone());
                let end: usize = range.strip_prefix("bytes=0-").unwrap().parse().unwrap();
                if mode == CHUNKED || mode == SLOW_CHUNKED {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n").await?;
                    for (index, bytes) in bytes.chunks(65_536).enumerate() {
                        chunk(&mut socket, bytes).await?;
                        if mode == SLOW_CHUNKED && index == 0 {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                    }
                    return socket.write_all(b"0\r\n\r\n").await;
                }
                if mode == IGNORE_RANGE {
                    return reply(&mut socket, "200 OK", "", &bytes).await;
                }
                if bytes.is_empty() {
                    return reply(
                        &mut socket,
                        "416 Range Not Satisfiable",
                        "Content-Range: bytes */0\r\n",
                        b"",
                    )
                    .await;
                }
                let end = end.min(bytes.len() - 1);
                let total = if mode == UNKNOWN_PARTIAL {
                    "*".into()
                } else {
                    bytes.len().to_string()
                };
                let content_range = if mode == INVALID_RANGE {
                    "bytes 1-2/999".to_string()
                } else {
                    format!("bytes 0-{end}/{total}")
                };
                let body = if mode == SHORT_RANGE {
                    &bytes[..end / 2]
                } else {
                    &bytes[..=end]
                };
                return reply(
                    &mut socket,
                    "206 Partial Content",
                    &format!("Content-Range: {content_range}\r\n"),
                    body,
                )
                .await;
            }
            reply(&mut socket, "200 OK", "", &bytes).await
        }
        _ => reply(&mut socket, "405 Method Not Allowed", "", b"").await,
    }
}

#[tokio::test]
async fn s3_signed_wire_roundtrip_encodes_unicode_reserved_bytes_and_deletes() {
    let f = S3Fixture::new().await;
    let storage = f.provider();
    let key = "folder/空 格+%?#.jsonl";
    let bytes = "{\"message\":\"你好\"}\n".as_bytes();
    let url = storage
        .upload(key, bytes, "application/jsonl")
        .await
        .unwrap();
    let path = "/transcripts/folder/%E7%A9%BA%20%E6%A0%BC%2B%25%3F%23.jsonl";
    assert_eq!(url, format!("{}{path}", f.endpoint));
    assert_eq!(storage.download(key).await.unwrap(), bytes);
    let preview = storage.preview(key, 1024).await.unwrap();
    assert_eq!(preview.bytes, bytes);
    assert_eq!(preview.size, Some(bytes.len() as u64));
    assert!(!preview.truncated);
    assert_eq!(f.state.objects.lock().unwrap().get(path).unwrap(), bytes);
    storage.delete(key).await.unwrap();
    assert!(matches!(
        storage.download(key).await,
        Err(casdog::error::AppError::NotFound(_))
    ));
    assert_eq!(f.state.auth_failures.load(Ordering::SeqCst), 0);
    let wrong = S3StorageProvider::new(
        "fixture-access".into(),
        "wrong".into(),
        "us-east-1".into(),
        "transcripts".into(),
        f.endpoint.clone(),
    );
    assert!(
        wrong
            .upload("bad.jsonl", bytes, "application/jsonl")
            .await
            .is_err()
    );
    assert!(
        !f.state
            .objects
            .lock()
            .unwrap()
            .contains_key("/transcripts/bad.jsonl")
    );
    assert_eq!(f.state.auth_failures.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn s3_preview_bounds_range_ignored_range_and_chunked_unknown_length() {
    let f = S3Fixture::new().await;
    let storage = f.provider();
    let data = vec![b'x'; 3 * 1024 * 1024];
    storage
        .upload("large.jsonl", &data, "application/jsonl")
        .await
        .unwrap();
    for mode in [RANGE, IGNORE_RANGE, CHUNKED, SLOW_CHUNKED, UNKNOWN_PARTIAL] {
        f.state.mode.store(mode, Ordering::SeqCst);
        let preview =
            tokio::time::timeout(Duration::from_secs(1), storage.preview("large.jsonl", 4096))
                .await
                .expect("preview must return before an unbounded stream ends")
                .unwrap();
        assert_eq!(preview.bytes, vec![b'x'; 4096]);
        assert!(preview.truncated);
        assert_eq!(
            preview.size,
            if [CHUNKED, SLOW_CHUNKED, UNKNOWN_PARTIAL].contains(&mode) {
                None
            } else {
                Some(data.len() as u64)
            }
        );
    }
    assert!(
        f.state
            .ranges
            .lock()
            .unwrap()
            .iter()
            .all(|range| range == "bytes=0-4096")
    );
    for mode in [INVALID_RANGE, SHORT_RANGE, REDIRECT] {
        f.state.mode.store(mode, Ordering::SeqCst);
        assert!(storage.preview("large.jsonl", 4096).await.is_err());
    }
    f.state.mode.store(RANGE, Ordering::SeqCst);
    storage
        .upload("empty.jsonl", &[], "application/jsonl")
        .await
        .unwrap();
    let empty = storage.preview("empty.jsonl", 4096).await.unwrap();
    assert!(empty.bytes.is_empty());
    assert_eq!(empty.size, Some(0));
    assert!(!empty.truncated);
    storage
        .upload("exact.jsonl", &vec![b'e'; 4096], "application/jsonl")
        .await
        .unwrap();
    let exact = storage.preview("exact.jsonl", 4096).await.unwrap();
    assert!(!exact.truncated);
    f.state.mode.store(CHUNKED, Ordering::SeqCst);
    let complete = storage.preview("exact.jsonl", 4096).await.unwrap();
    assert_eq!(complete.size, Some(4096));
    assert!(!complete.truncated);
    assert_eq!(f.state.auth_failures.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn s3_rejects_unsafe_keys_endpoints_and_partial_credentials_without_requests() {
    let f = S3Fixture::new().await;
    let storage = f.provider();
    for key in [
        "",
        "/absolute",
        "../parent",
        "a/../parent",
        "a/./file",
        "a//file",
        "a\\file",
        "C:/file",
        "a\nfile",
    ] {
        assert!(
            storage.upload(key, b"x", "text/plain").await.is_err(),
            "{key:?}"
        );
        assert!(storage.preview(key, 12).await.is_err(), "{key:?}");
    }
    let huge = "x".repeat(1025);
    assert!(storage.get_url(&huge).await.is_err());
    for endpoint in [
        format!("{}/?token=secret", f.endpoint),
        format!("{}/#fragment", f.endpoint),
        "http://access:secret@localhost".into(),
        "file:///outside".into(),
    ] {
        let storage = S3StorageProvider::new(
            "fixture-access".into(),
            "fixture-secret".into(),
            "us-east-1".into(),
            "transcripts".into(),
            endpoint,
        );
        assert!(storage.upload("a", b"x", "text/plain").await.is_err());
    }
    let partial = S3StorageProvider::new(
        "fixture-access".into(),
        "".into(),
        "us-east-1".into(),
        "transcripts".into(),
        f.endpoint.clone(),
    );
    assert!(partial.upload("a", b"x", "text/plain").await.is_err());
    assert_eq!(f.state.requests.load(Ordering::SeqCst), 0);
}

#[salvo::handler]
async fn fixture_identity(depot: &mut Depot) {
    let principal = depot.obtain::<Principal>().unwrap().clone();
    depot.insert("user_id", principal.id);
    depot.insert("user_owner", principal.owner);
    depot.insert("user_name", principal.name);
    depot.insert("is_admin", principal.admin);
}
fn api(pool: &PgPool, principal: Principal) -> Service {
    Service::new(
        Router::with_path("api")
            .hoop(
                salvo::affix_state::AffixList::new()
                    .inject(pool.clone())
                    .inject(principal),
            )
            .hoop(fixture_identity)
            .push(Router::with_path("providers").post(casdog::handlers::provider::create_provider))
            .push(
                Router::with_path("add-entry").post(casdog::handlers::parity_resources::add_entry),
            )
            .push(
                Router::with_path("upload-resource")
                    .post(casdog::handlers::upload::upload_resource),
            )
            .push(
                Router::with_path("get-openclaw-session-transcript")
                    .get(casdog::handlers::protocol_gaps::get_openclaw_session_transcript),
            )
            .push(Router::with_path("resources").get(casdog::handlers::resource::list_resources)),
    )
}
fn multipart(owner: &str, provider: &str, entry: &str, bytes: &str) -> String {
    let mut body = String::new();
    for (key, value) in [
        ("owner", owner),
        ("tag", "openclawTranscript"),
        ("provider", provider),
        ("entryId", entry),
    ] {
        body.push_str(&format!("--storage-boundary\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n"));
    }
    body.push_str(&format!("--storage-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"session.jsonl\"\r\nContent-Type: application/jsonl\r\n\r\n{bytes}\r\n--storage-boundary--\r\n"));
    body
}
async fn upload(api: &Service, body: String) -> salvo::Response {
    TestClient::post("http://localhost/api/upload-resource")
        .add_header(
            "Content-Type",
            "multipart/form-data; boundary=storage-boundary",
            true,
        )
        .body(body)
        .send(api)
        .await
}
async fn database() -> PgPool {
    casdog::config::AppConfig::load().unwrap();
    PgPoolOptions::new()
        .max_connections(3)
        .connect(
            &std::env::var("CASDOG_TEST_DATABASE_URL").expect("CASDOG_TEST_DATABASE_URL required"),
        )
        .await
        .unwrap()
}
fn admin() -> Principal {
    Principal {
        application_identity: false,
        id: "storage-fixture-admin".into(),
        owner: "built-in".into(),
        name: "storage-fixture-admin".into(),
        admin: true,
    }
}
async fn create_api_objects(api: &Service, owner: &str, endpoint: &str, session: &str) {
    for provider in [
        json!({"owner":owner,"name":"storage","display_name":"S3 fixture","category":"Storage","type":"S3","client_id":"fixture-access","client_secret":"fixture-secret","region_id":"us-east-1","bucket":"transcripts","endpoint":endpoint}),
        json!({"owner":owner,"name":"log","display_name":"Session log","category":"Log","type":"OpenClaw"}),
    ] {
        let mut response = TestClient::post("http://localhost/api/providers")
            .json(&provider)
            .send(api)
            .await;
        let status = response.status_code;
        let body = response.take_string().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{body}");
    }
    let mut response = TestClient::post("http://localhost/api/add-entry").json(&json!({"owner":owner,"name":"session","type":"session","provider":"log","message":json!({"sessionId":session,"entryId":"root","kind":"task"}).to_string()})).send(api).await;
    let status = response.status_code;
    let body = response.take_string().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
}
async fn preview(api: &Service, owner: &str) -> salvo::Response {
    TestClient::get(format!(
        "http://localhost/api/get-openclaw-session-transcript?id={owner}/session"
    ))
    .send(api)
    .await
}
async fn cleanup(pool: &PgPool, owner: &str) {
    for table in ["resources", "providers", "casdoor_objects"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE owner=$1"))
            .bind(owner)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn transcript_s3_normal_upload_preview_and_resource_apis_persist_only_successful_objects() {
    let pool = database().await;
    let f = S3Fixture::new().await;
    let owner = format!("storage-{}", uuid::Uuid::new_v4().simple());
    let api = api(&pool, admin());
    create_api_objects(&api, &owner, &f.endpoint, "s3-api-session").await;
    let entry = format!("{owner}/session");
    let content = "{\"type\":\"message\",\"content\":\"hello S3\"}\n";
    let mut response = upload(&api, multipart(&owner, "storage", &entry, content)).await;
    let status = response.status_code;
    let result: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{result}");
    assert_eq!(result["name"], "session.jsonl");
    let key: String = sqlx::query_scalar("SELECT name FROM resources WHERE owner=$1")
        .bind(&owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(key.starts_with("openclaw/"));
    assert_eq!(
        f.state
            .objects
            .lock()
            .unwrap()
            .get(&format!("/transcripts/{key}"))
            .unwrap(),
        content.as_bytes()
    );
    let mut response = preview(&api, &owner).await;
    let result: Value = response.take_json().await.unwrap();
    assert_eq!(result["data"]["content"], content);
    assert_eq!(result["data"]["fileSize"], content.len());
    assert_eq!(result["data"]["loadedSize"], content.len());
    assert_eq!(result["data"]["truncated"], false);
    let mut response = TestClient::get(format!("http://localhost/api/resources?owner={owner}"))
        .send(&api)
        .await;
    let listed: Value = response.take_json().await.unwrap();
    assert_eq!(listed["total"], 1);
    assert_eq!(listed["data"][0]["provider"], "storage");
    assert_eq!(listed["data"][0]["user"], "storage-fixture-admin");

    // Failed remote writes cannot publish rows or replace the previous version.
    f.state.fail_upload.store(true, Ordering::SeqCst);
    let mut response = upload(&api, multipart(&owner, "storage", &entry, "failed version")).await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert!(
        !response
            .take_string()
            .await
            .unwrap()
            .contains("fixture-secret")
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM resources WHERE owner=$1")
        .bind(&owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(f.state.objects.lock().unwrap().len(), 1);
    let mut response = preview(&api, &owner).await;
    let result: Value = response.take_json().await.unwrap();
    assert_eq!(result["data"]["content"], content);
    f.state.fail_upload.store(false, Ordering::SeqCst);

    // Use the normal multipart endpoint for the large version as well.
    let big = format!("{}\n", "x".repeat(2 * 1024 * 1024 + 8192));
    let mut response = upload(&api, multipart(&owner, "storage", &entry, &big)).await;
    let status = response.status_code;
    let result: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{result}");
    for mode in [RANGE, IGNORE_RANGE, CHUNKED] {
        f.state.mode.store(mode, Ordering::SeqCst);
        let mut response = preview(&api, &owner).await;
        let status = response.status_code;
        let result: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{result}");
        assert_eq!(result["data"]["loadedSize"], 2 * 1024 * 1024);
        assert_eq!(
            result["data"]["content"].as_str().unwrap().len(),
            2 * 1024 * 1024
        );
        assert_eq!(result["data"]["truncated"], true);
        assert_eq!(
            result["data"]["fileSize"],
            if mode == CHUNKED {
                Value::Null
            } else {
                json!(big.len())
            }
        );
    }
    assert_eq!(f.state.auth_failures.load(Ordering::SeqCst), 0);
    cleanup(&pool, &owner).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn transcript_s3_api_rechecks_tenant_provider_owner_keys_and_private_dns_on_every_read_write()
{
    let pool = database().await;
    let f = S3Fixture::new().await;
    let owner = format!("storage-{}", uuid::Uuid::new_v4().simple());
    let global = api(&pool, admin());
    create_api_objects(&global, &owner, &f.endpoint, "s3-tenant-session").await;
    let entry = format!("{owner}/session");
    let body = multipart(&owner, "storage", &entry, "private transcript");
    let response = upload(&global, body.clone()).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let before = f.state.requests.load(Ordering::SeqCst);
    let tenant = api(
        &pool,
        Principal {
            application_identity: false,
            owner: owner.clone(),
            ..admin()
        },
    );
    let response = upload(&tenant, body.clone()).await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    assert_eq!(
        preview(&tenant, &owner).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let outsider = api(
        &pool,
        Principal {
            application_identity: false,
            owner: "other-organization".into(),
            ..admin()
        },
    );
    assert_eq!(
        upload(&outsider, body.clone()).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        preview(&outsider, &owner).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    let ordinary = api(
        &pool,
        Principal {
            application_identity: false,
            owner: owner.clone(),
            admin: false,
            ..admin()
        },
    );
    assert_eq!(
        upload(&ordinary, body).await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        upload(
            &global,
            multipart(&owner, "foreign/storage", &entry, "attack")
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(f.state.requests.load(Ordering::SeqCst), before);
    for key in ["../outside", "/absolute", "a\\outside"] {
        sqlx::query("UPDATE resources SET name=$2 WHERE owner=$1")
            .bind(&owner)
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            preview(&global, &owner).await.status_code,
            Some(StatusCode::BAD_REQUEST)
        );
    }
    assert_eq!(f.state.requests.load(Ordering::SeqCst), before);
    let provider: casdog::models::Provider =
        sqlx::query_as("SELECT * FROM providers WHERE owner=$1 AND name='storage'")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(matches!(
        protocol_gap_service::storage_for_owner(&admin(), "another-owner", Some(&provider), false)
            .await,
        Err(casdog::error::AppError::Authorization(_))
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM resources WHERE owner=$1")
        .bind(&owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    cleanup(&pool, &owner).await;
    pool.close().await;
}
