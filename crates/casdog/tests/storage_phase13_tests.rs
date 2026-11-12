//! Local protocol fixtures, never real cloud accounts or production credentials.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use casdog::{
    hoops::authz::Principal,
    services::providers::{
        StorageProvider, azure_storage::AzureBlobStorageProvider,
        gcs_storage::GoogleCloudStorageProvider, get_storage_provider,
    },
};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::Url;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding},
    signature::Verifier,
};
use salvo::{
    prelude::*,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDaVGOgy29SRkTt\n\
lQ6+BSqyxeI6Fn17qGMiRMTrA3KFctNFai6Uxj7ggj5lGE22IIuMjr0hKP4lyBgi\n\
bKSwbucmlDGhpgmarU5tzxz6gRHzHx6c5asNsoIRO1ikYc6tFgaAN1AkXGRytqzE\n\
OIrcsHBlR+dGk3FYXJ/oJZ9Jyj6zYjCZJ2YmQ2azSINTA5HBDBoo54RNR3iASjpi\n\
wb5yFXgxRf8AeBIP6yyo5zUwmTQV4n6mwMQtzdE6OM7GdxeRkLrBOIwK/o5Xk1hz\n\
G6Vb4pEfyB3zWVUaHzaQ92f0KlPBTCjLMatD+8jBUOILxyA55kvzxpq8BFiW5i6o\n\
/+uclftVAgMBAAECggEAAJwL+FHFtyK/WgtnyFDSe4MH3wFHOkBx+E34eqtjqbNZ\n\
jc/tlJNwYajfpDI/M2bk3AFdszvRCgss5JnRGoZebRtv6xbNgXuZzrFBrpZPnKZk\n\
1E1dOC8tAg1BccImx7Mx27b+WJOkgzRR8JWSChnao4hG8F4BLI97U4wLw56ibt1N\n\
BVpQc9cu6OuhPGXEPi403/NZ6sUv9kFQ9CTa3udfbPthxALg+KQNMu5noTASOtR6\n\
DbOSOqo7w8stKEoKA68YVlIm84zha+QRUca/tUui6i0pbpDtEt9XtDXiKnrhY5eF\n\
EiEUU82bV2nnodX+oE95ppTJRMigiLIbzhKFyIksEwKBgQD2XoosMSgUo6pABgDr\n\
cHSZ0qMtvHbmXIFb696uckfgkNlNOQMsHv7qq7WR3pm3+HbbJ45UaYc2cxZJn7yc\n\
LrEtBJA/4kWehl0VbxrUaiW9ORbWsbDpbdihROJEbtutKXIgEQwvqA3V2PyIP3SO\n\
JD0l4H8Bab2CN905K5Ds52yo1wKBgQDi3UB1Rs0sI9mLBab+5p/3QyLoax0WJDSa\n\
S4+4q+vDrlEQvJO9acQ9OgU5HcQQfCkMqMZcSmKAOwL/jDhhx5pqXICFRquTBc3h\n\
l0F9yFmaGZ2vwpyEQVL+onvs2hv8yZxbLS23o/l0cZOBFAPeWdqv9LKxhh2r6NTu\n\
52r/4LTbswKBgQDl/I0qAd1znvEggTo8jycaLYsM+AFavII5yC+BU8eLeEySjSVL\n\
+8dmVFLUUCPZnIV/wiZY4IZLqxXkNszAU8orxzXNnTH2cWHVz3kRT+HZCcErPId0\n\
8YknywEadw51UNpr2t4wYsY/mibsHah1xJickjydmhNBy1qlsujAbq190wKBgQCf\n\
Iln7qd1zz/XiKeXZOccN9979r10o0d7AOK6o+JeZnKYqmkz7+bv4wsE1LmcAtUdK\n\
JP13cYokrsBMp3xJQm1TnG1ej5L8v36KdsIuzCHmEX/l8Ro/P19LVIifPOOS740o\n\
+8js3y21e5HfYj3Qc7EN6hSKqCwaEWmD53rL4ECdNwKBgQDIL6p/ch7XkoiRpdky\n\
C6XPikIjIl6b7njxUX0jMIkcKb26YGj4tF7SGj38agvso671HsyD0Af/dyDvHtJD\n\
ngpSx3/MHCmr6zE0Tj6gk0WWFnPLn6CD6paY4wMacfDf2x181k6LcTNzcxIRK+RP\n\
MVw1e5ecwsurVANeERC5cSJ2ow==\n\
-----END PRIVATE KEY-----";
const ACCOUNT_KEY: &[u8] = b"local-fixture-azure-account-key-32";

#[derive(Default)]
struct State {
    objects: Mutex<BTreeMap<String, (Vec<u8>, String)>>,
    requests: AtomicUsize,
    auth_failures: AtomicUsize,
    token_requests: AtomicUsize,
    reject_before: AtomicUsize,
    expires: AtomicU64,
    mode: AtomicU8, // 1=ignore range, 2=bad range, 3=redirect
    fail: AtomicBool,
    fail_token: AtomicBool,
    public_reads: AtomicBool,
    assertions: Mutex<Vec<Value>>,
}
struct Fixture {
    endpoint: String,
    state: Arc<State>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new(gcs: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(State::default());
        state.expires.store(3600, Ordering::SeqCst);
        let server = state.clone();
        let base = endpoint.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let state = server.clone();
                let endpoint = base.clone();
                tokio::spawn(async move {
                    let _ = serve(socket, state, gcs, &endpoint).await;
                });
            }
        });
        Self {
            endpoint,
            state,
            task,
        }
    }
    fn credentials(&self, key_id: &str) -> String {
        json!({"type":"service_account", "client_email":"fixture@casdog-test.iam.gserviceaccount.com", "private_key":TEST_PRIVATE_KEY,
            "private_key_id":key_id,"token_uri":format!("{}/token",self.endpoint)}).to_string()
    }
    fn azure(&self, public_base: &str) -> AzureBlobStorageProvider {
        AzureBlobStorageProvider::new(
            "fixtureaccount".into(),
            STANDARD.encode(ACCOUNT_KEY),
            "assets".into(),
            public_base.into(),
        )
        .unwrap()
        .with_api_endpoint(self.endpoint.clone())
        .unwrap()
    }
    fn google(&self, public_base: &str) -> GoogleCloudStorageProvider {
        GoogleCloudStorageProvider::new(
            self.credentials("fixture-key"),
            "assets".into(),
            public_base.into(),
        )
        .unwrap()
        .with_api_endpoint(self.endpoint.clone())
        .unwrap()
    }
}
fn public_key() -> RsaPublicKey {
    RsaPrivateKey::from_pkcs8_pem(TEST_PRIVATE_KEY)
        .unwrap()
        .to_public_key()
}
fn mac(value: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(ACCOUNT_KEY).unwrap();
    mac.update(value.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}
fn azure_authorized(
    method: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    length: usize,
) -> bool {
    let Some(date) = headers.get("x-ms-date") else {
        return false;
    };
    if headers.get("x-ms-version").map(String::as_str) != Some("2022-11-02") {
        return false;
    }
    let mut fields = vec![
        method.to_string(),
        String::new(),
        String::new(),
        if length == 0 {
            String::new()
        } else {
            length.to_string()
        },
        String::new(),
        headers.get("content-type").cloned().unwrap_or_default(),
    ];
    fields.extend((0..5).map(|_| String::new()));
    fields.push(headers.get("range").cloned().unwrap_or_default());
    let mut canonical = format!("{}\n", fields.join("\n"));
    if method == "PUT" {
        if headers.get("x-ms-blob-type").map(String::as_str) != Some("BlockBlob") {
            return false;
        }
        canonical.push_str("x-ms-blob-type:BlockBlob\n");
    }
    canonical.push_str(&format!(
        "x-ms-date:{date}\nx-ms-version:2022-11-02\n/fixtureaccount{path}"
    ));
    headers.get("authorization") == Some(&format!("SharedKey fixtureaccount:{}", mac(&canonical)))
}
fn signed_url_valid(url: &Url, gcs: bool) -> bool {
    let query: BTreeMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if !gcs {
        if query.get("sp").map(String::as_str) != Some("r")
            || query.get("sr").map(String::as_str) != Some("b")
        {
            return false;
        }
        let path = urlencoding::decode(url.path()).unwrap();
        let resource = format!("/blob/fixtureaccount{path}");
        let get = |key| query.get(key).map(String::as_str).unwrap_or("");
        let fields = [
            get("sp"),
            get("st"),
            get("se"),
            &resource,
            "",
            "",
            get("spr"),
            get("sv"),
            get("sr"),
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ];
        let now = chrono::Utc::now();
        if chrono::DateTime::parse_from_rfc3339(get("se")).map_or(true, |expiry| {
            expiry <= now || expiry > now + chrono::Duration::minutes(16)
        }) {
            return false;
        }
        return get("sig") == mac(&fields.join("\n"));
    }
    if query.get("X-Goog-Algorithm").map(String::as_str) != Some("GOOG4-RSA-SHA256")
        || query.get("X-Goog-Expires").map(String::as_str) != Some("900")
    {
        return false;
    }
    let Some(signature) = query
        .get("X-Goog-Signature")
        .and_then(|s| hex::decode(s).ok())
        .and_then(|s| Signature::try_from(s.as_slice()).ok())
    else {
        return false;
    };
    let unsigned = url
        .query()
        .unwrap()
        .split('&')
        .filter(|s| !s.starts_with("X-Goog-Signature="))
        .collect::<Vec<_>>()
        .join("&");
    let host = url.authority();
    let canonical = format!(
        "GET\n{}\n{unsigned}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
        url.path()
    );
    let credential = &query["X-Goog-Credential"];
    let Some((email, scope)) = credential.split_once('/') else {
        return false;
    };
    if email != "fixture@casdog-test.iam.gserviceaccount.com" {
        return false;
    }
    let value = format!(
        "GOOG4-RSA-SHA256\n{}\n{scope}\n{}",
        query["X-Goog-Date"],
        hex::encode(Sha256::digest(canonical))
    );
    VerifyingKey::<Sha256>::new(public_key())
        .verify(value.as_bytes(), &signature)
        .is_ok()
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
async fn serve(
    mut socket: TcpStream,
    state: Arc<State>,
    gcs: bool,
    endpoint: &str,
) -> std::io::Result<()> {
    let mut bytes = Vec::new();
    let boundary = loop {
        let mut chunk = [0; 8192];
        let count = socket.read(&mut chunk).await?;
        if count == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(i) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
            break i + 4;
        }
        assert!(bytes.len() < 128 * 1024);
    };
    let head = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap();
    let target = first.next().unwrap();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().into()))
        })
        .collect();
    let length = headers
        .get("content-length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() - boundary < length {
        let mut chunk = [0; 8192];
        let count = socket.read(&mut chunk).await?;
        if count == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let body = &bytes[boundary..boundary + length];
    let url = Url::parse(&format!("{endpoint}{target}")).unwrap();
    if gcs && url.path() == "/token" {
        state.token_requests.fetch_add(1, Ordering::SeqCst);
        if state.fail_token.load(Ordering::SeqCst) {
            return reply(
                &mut socket,
                "400 Bad Request",
                "",
                b"PRIVATE KEY fixture-secret",
            )
            .await;
        }
        let form_url = Url::parse(&format!(
            "http://fixture/?{}",
            String::from_utf8_lossy(body)
        ))
        .unwrap();
        let form: BTreeMap<String, String> = form_url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let assertion = &form["assertion"];
        assert_eq!(
            form["grant_type"],
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        );
        let public = public_key().to_public_key_pem(LineEnding::LF).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[format!("{endpoint}/token")]);
        validation.set_issuer(&["fixture@casdog-test.iam.gserviceaccount.com"]);
        let claims = jsonwebtoken::decode::<Value>(
            assertion,
            &DecodingKey::from_rsa_pem(public.as_bytes()).unwrap(),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            3600
        );
        assert_eq!(
            claims["scope"],
            "https://www.googleapis.com/auth/devstorage.read_write"
        );
        assert!(matches!(
            jsonwebtoken::decode_header(assertion)
                .unwrap()
                .kid
                .as_deref(),
            Some("fixture-key" | "rotated-key")
        ));
        state.assertions.lock().unwrap().push(claims);
        let token = state.token_requests.load(Ordering::SeqCst);
        return reply(&mut socket,"200 OK","Content-Type: application/json\r\n", json!({"access_token":format!("fixture-access-{token}"),"token_type":"Bearer","expires_in":state.expires.load(Ordering::SeqCst)}).to_string().as_bytes()).await;
    }
    state.requests.fetch_add(1, Ordering::SeqCst);
    let signed = url
        .query()
        .is_some_and(|q| q.contains("sig=") || q.contains("X-Goog-Signature="));
    let authorized = if state.public_reads.load(Ordering::SeqCst)
        && method == "GET"
        && url.path().starts_with("/assets/")
        && !headers.contains_key("authorization")
    {
        true
    } else if signed {
        method == "GET" && signed_url_valid(&url, gcs)
    } else if gcs {
        headers
            .get("authorization")
            .and_then(|s| s.strip_prefix("Bearer fixture-access-"))
            .and_then(|s| s.parse::<usize>().ok())
            .is_some_and(|token| token > state.reject_before.load(Ordering::SeqCst))
    } else {
        azure_authorized(method, url.path(), &headers, length)
    };
    if !authorized {
        state.auth_failures.fetch_add(1, Ordering::SeqCst);
        return reply(
            &mut socket,
            if gcs {
                "401 Unauthorized"
            } else {
                "403 Forbidden"
            },
            "",
            b"fixture-secret",
        )
        .await;
    }
    if state.fail.load(Ordering::SeqCst) {
        return reply(
            &mut socket,
            "503 Service Unavailable",
            "",
            b"fixture-secret PRIVATE KEY",
        )
        .await;
    }
    if state.mode.load(Ordering::SeqCst) == 3 {
        return reply(
            &mut socket,
            "307 Temporary Redirect",
            &format!("Location: {endpoint}/credential-sink\r\n"),
            b"",
        )
        .await;
    }
    let query: BTreeMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let key = if gcs && method == "POST" {
        assert_eq!(url.path(), "/upload/storage/v1/b/assets/o");
        assert_eq!(query.get("uploadType").map(String::as_str), Some("media"));
        assert!(!query.contains_key("predefinedAcl"));
        query["name"].clone()
    } else if gcs && !signed && !url.path().starts_with("/assets/") {
        urlencoding::decode(url.path().strip_prefix("/storage/v1/b/assets/o/").unwrap())
            .unwrap()
            .into_owned()
    } else {
        urlencoding::decode(url.path().strip_prefix("/assets/").unwrap())
            .unwrap()
            .into_owned()
    };
    if method == "PUT" || method == "POST" {
        state.objects.lock().unwrap().insert(
            key,
            (
                body.to_vec(),
                headers.get("content-type").cloned().unwrap_or_default(),
            ),
        );
        return reply(
            &mut socket,
            "200 OK",
            "Content-Type: application/json\r\n",
            b"{}",
        )
        .await;
    }
    if method == "DELETE" {
        let removed = state.objects.lock().unwrap().remove(&key).is_some();
        return reply(
            &mut socket,
            if removed {
                "204 No Content"
            } else {
                "404 Not Found"
            },
            "",
            b"",
        )
        .await;
    }
    let object = state.objects.lock().unwrap().get(&key).cloned();
    let Some((bytes, mime)) = object else {
        return reply(&mut socket, "404 Not Found", "", b"").await;
    };
    if method == "HEAD" {
        return reply(
            &mut socket,
            "200 OK",
            &format!("Content-Type: {mime}\r\n"),
            b"",
        )
        .await;
    }
    if gcs
        && !signed
        && !url.path().starts_with("/assets/")
        && query.get("alt").map(String::as_str) != Some("media")
    {
        return reply(
            &mut socket,
            "200 OK",
            "Content-Type: application/json\r\n",
            json!({"name":key,"size":bytes.len().to_string(),"contentType":mime})
                .to_string()
                .as_bytes(),
        )
        .await;
    }
    if let Some(end) = headers
        .get("range")
        .and_then(|v| v.strip_prefix("bytes=0-"))
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|_| state.mode.load(Ordering::SeqCst) != 1)
    {
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
        let start = if state.mode.load(Ordering::SeqCst) == 2 {
            1
        } else {
            0
        };
        return reply(
            &mut socket,
            "206 Partial Content",
            &format!(
                "Content-Range: bytes {start}-{end}/{}\r\nContent-Type: {mime}\r\n",
                bytes.len()
            ),
            &bytes[..=end],
        )
        .await;
    }
    reply(
        &mut socket,
        "200 OK",
        &format!("Content-Type: {mime}\r\n"),
        &bytes,
    )
    .await
}

#[tokio::test]
async fn azure_native_shared_key_wire_private_sas_public_cdn_and_bounded_preview() {
    let f = Fixture::new(false).await;
    let storage = f.azure("");
    let key = "tenant/目录 space+#%.txt";
    let url = storage
        .upload(key, b"azure data body", "text/plain; charset=utf-8")
        .await
        .unwrap();
    assert!(storage.exists(key).await.unwrap());
    assert!(!storage.exists("missing.txt").await.unwrap());
    assert_eq!(storage.download(key).await.unwrap(), b"azure data body");
    assert_eq!(
        f.state.objects.lock().unwrap()[key].1,
        "text/plain; charset=utf-8"
    );
    assert!(url.contains("%E7%9B%AE%E5%BD%95%20space%2B%23%25.txt"));
    assert!(signed_url_valid(&Url::parse(&url).unwrap(), false));
    assert_eq!(
        reqwest::get(&url)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        b"azure data body"
    );
    for mode in [0, 1] {
        f.state.mode.store(mode, Ordering::SeqCst);
        let p = storage.preview(key, 5).await.unwrap();
        assert_eq!(p.bytes, b"azure");
        assert_eq!(p.size, Some(15));
        assert!(p.truncated);
    }
    f.state.mode.store(2, Ordering::SeqCst);
    assert!(storage.preview(key, 5).await.is_err());
    f.state.mode.store(0, Ordering::SeqCst);
    storage
        .upload("empty", b"", "application/octet-stream")
        .await
        .unwrap();
    let empty = storage.preview("empty", 5).await.unwrap();
    assert_eq!(empty.size, Some(0));
    assert!(!empty.truncated);
    let public = f.azure("https://cdn.example.test/assets-base");
    assert_eq!(
        public.get_url("folder/a b").await.unwrap(),
        "https://cdn.example.test/assets-base/assets/folder/a%20b"
    );
    // A public URL is an explicit operator declaration; no request grants ACLs.
    assert!(
        public
            .upload("public", b"body", "text/plain")
            .await
            .unwrap()
            .starts_with("https://cdn.example.test/")
    );
    storage.delete(key).await.unwrap();
    assert!(!storage.exists(key).await.unwrap());
    assert!(matches!(
        storage.download(key).await,
        Err(casdog::error::AppError::NotFound(_))
    ));
    assert_eq!(f.state.auth_failures.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn gcs_real_jwt_oauth_json_wire_signed_get_and_shared_cache_revocation_expiry() {
    let f = Fixture::new(true).await;
    let storage = f.google("");
    let key = "tenant/目录 space+#%.txt";
    let url = storage
        .upload(key, b"google bytes", "text/plain")
        .await
        .unwrap();
    assert_eq!(storage.download(key).await.unwrap(), b"google bytes");
    assert!(storage.exists(key).await.unwrap());
    assert!(!storage.exists("missing").await.unwrap());
    assert!(signed_url_valid(&Url::parse(&url).unwrap(), true));
    assert_eq!(
        reqwest::get(&url)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        b"google bytes"
    );
    let p = storage.preview(key, 6).await.unwrap();
    assert_eq!(p.bytes, b"google");
    assert!(p.truncated);
    assert_eq!(p.size, Some(12));
    let second = f.google("");
    let mut jobs = Vec::new();
    for _ in 0..12 {
        let next = f.google("");
        let key = key.to_string();
        jobs.push(tokio::spawn(
            async move { next.download(&key).await.unwrap() },
        ));
    }
    for job in jobs {
        assert_eq!(job.await.unwrap(), b"google bytes");
    }
    assert_eq!(f.state.token_requests.load(Ordering::SeqCst), 1);
    f.state.reject_before.store(1, Ordering::SeqCst);
    assert_eq!(second.download(key).await.unwrap(), b"google bytes");
    assert_eq!(f.state.token_requests.load(Ordering::SeqCst), 2);
    assert_eq!(storage.download(key).await.unwrap(), b"google bytes"); // old instance sees refreshed slot
    assert_eq!(f.state.token_requests.load(Ordering::SeqCst), 2);
    let public = f.google("https://cdn.example.test/base");
    assert_eq!(
        public.get_url("a b").await.unwrap(),
        "https://cdn.example.test/base/assets/a%20b"
    );
    assert!(
        public
            .upload("public", b"x", "text/plain")
            .await
            .unwrap()
            .starts_with("https://cdn.example.test/")
    );
    storage.delete(key).await.unwrap();
    assert!(!storage.exists(key).await.unwrap());
    // Expiring OAuth responses are usable now, never treated as long-lived.
    let rotated =
        GoogleCloudStorageProvider::new(f.credentials("rotated-key"), "assets".into(), "".into())
            .unwrap()
            .with_api_endpoint(f.endpoint.clone())
            .unwrap();
    assert!(rotated.exists("public").await.unwrap());
    assert_eq!(f.state.token_requests.load(Ordering::SeqCst), 3);
    let short = Fixture::new(true).await;
    short.state.expires.store(1, Ordering::SeqCst);
    let client = short.google("");
    client.upload("short", b"x", "text/plain").await.unwrap();
    client.download("short").await.unwrap();
    assert_eq!(short.state.token_requests.load(Ordering::SeqCst), 2);
    assert_eq!(f.state.assertions.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn native_cloud_validation_errors_redirects_and_credentials_never_leak() {
    for gcs in [false, true] {
        let f = Fixture::new(gcs).await;
        let storage: Box<dyn StorageProvider> = if gcs {
            Box::new(f.google(""))
        } else {
            Box::new(f.azure(""))
        };
        for key in ["", "../a", "a/../b", "a//b", "a\\b", "/a", "a\nb", "C:/a"] {
            assert!(storage.upload(key, b"x", "text/plain").await.is_err());
        }
        assert_eq!(f.state.requests.load(Ordering::SeqCst), 0);
        assert_eq!(f.state.token_requests.load(Ordering::SeqCst), 0);
        storage
            .upload("valid", b"complete-body", "text/plain")
            .await
            .unwrap();
        f.state.fail.store(true, Ordering::SeqCst);
        for error in [
            storage
                .upload("fail", b"x", "text/plain")
                .await
                .unwrap_err(),
            storage.download("valid").await.unwrap_err(),
            storage.delete("valid").await.unwrap_err(),
        ] {
            let error = error.to_string();
            assert!(!error.contains("fixture-secret"));
            assert!(!error.contains("PRIVATE KEY"));
            assert!(!error.contains("Bearer"));
        }
        f.state.fail.store(false, Ordering::SeqCst);
        f.state.mode.store(3, Ordering::SeqCst);
        let before = f.state.requests.load(Ordering::SeqCst);
        assert!(storage.download("valid").await.is_err());
        assert_eq!(f.state.requests.load(Ordering::SeqCst), before + 1);
        if gcs {
            let next = Fixture::new(true).await;
            next.state.fail_token.store(true, Ordering::SeqCst);
            let e = next
                .google("")
                .download("valid")
                .await
                .unwrap_err()
                .to_string();
            assert!(!e.contains("PRIVATE KEY"));
            assert!(!e.contains("fixture-secret"));
        }
    }
    assert!(
        AzureBlobStorageProvider::new(
            "fixtureaccount".into(),
            "secret".into(),
            "assets".into(),
            "".into()
        )
        .is_err()
    );
    assert!(GoogleCloudStorageProvider::new("{}".into(), "assets".into(), "".into()).is_err());
    for alias in ["AWS S3", "s3", "MinIO"] {
        assert!(get_storage_provider(alias, "a", "b", "us-east-1", "assets", "").is_ok());
    }
    let f = Fixture::new(true).await;
    assert!(
        GoogleCloudStorageProvider::new(
            f.credentials("fixture-key"),
            "assets".into(),
            "https://user:pass@cdn.example.test".into()
        )
        .is_err()
    );
    assert!(
        f.google("")
            .with_api_endpoint("http://example.test".into())
            .is_err()
    );
    assert!(
        f.azure("")
            .with_api_endpoint("http://example.test".into())
            .is_err()
    );
}

#[salvo::handler]
async fn identity(depot: &mut Depot) {
    let p = depot.obtain::<Principal>().unwrap().clone();
    depot.insert("user_id", p.id);
    depot.insert("user_owner", p.owner);
    depot.insert("user_name", p.name);
    depot.insert("is_admin", p.admin);
}
fn api(pool: &PgPool, principal: Principal) -> Service {
    Service::new(
        Router::with_path("api")
            .hoop(
                salvo::affix_state::AffixList::new()
                    .inject(pool.clone())
                    .inject(principal),
            )
            .hoop(identity)
            .hoop(casdog::hoops::AuthzFilter)
            .push(
                Router::with_path("get-provider")
                    .get(casdog::handlers::casdoor_compat::get_provider),
            )
            .push(
                Router::with_path("get-providers")
                    .get(casdog::handlers::casdoor_compat::get_providers),
            )
            .push(
                Router::with_path("update-provider")
                    .post(casdog::handlers::casdoor_compat::update_provider),
            )
            .push(
                Router::with_path("add-provider")
                    .post(casdog::handlers::casdoor_compat::add_provider),
            )
            .push(Router::with_path("providers").post(casdog::handlers::provider::create_provider))
            .push(
                Router::with_path("providers/{id}")
                    .get(casdog::handlers::provider::get_provider)
                    .put(casdog::handlers::provider::update_provider),
            )
            .push(
                Router::with_path("upload-resource")
                    .post(casdog::handlers::upload::upload_resource),
            )
            .push(
                Router::with_path("download-resource/{id}")
                    .get(casdog::handlers::upload::download_resource),
            )
            .push(
                Router::with_path("resource-url/{id}").get(casdog::handlers::upload::resource_url),
            )
            .push(
                Router::with_path("delete-resource/{id}")
                    .post(casdog::handlers::upload::delete_resource_with_file),
            ),
    )
}
fn principal(owner: &str, global: bool) -> Principal {
    Principal {
        application_identity: false,
        id: "cloud-fixture-admin".into(),
        name: "cloud-fixture-admin".into(),
        owner: if global {
            "built-in".into()
        } else {
            owner.into()
        },
        admin: true,
    }
}
fn multipart(owner: &str, provider: &str) -> String {
    format!(
        "--cloud-boundary\r\nContent-Disposition: form-data; name=\"owner\"\r\n\r\n{owner}\r\n--cloud-boundary\r\nContent-Disposition: form-data; name=\"provider\"\r\n\r\n{provider}\r\n--cloud-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"cloud.txt\"\r\nContent-Type: text/plain\r\n\r\ncloud actual object\r\n--cloud-boundary--\r\n"
    )
}
async fn upload(api: &Service, owner: &str, provider: &str) -> Response {
    TestClient::post("http://localhost/api/upload-resource")
        .add_header(
            "Content-Type",
            "multipart/form-data; boundary=cloud-boundary",
            true,
        )
        .body(multipart(owner, provider))
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

fn user_token(id: &str, owner: &str, name: &str, admin: bool) -> String {
    let config = casdog::config::AppConfig::get();
    let now = chrono::Utc::now();
    jsonwebtoken::encode(&jsonwebtoken::Header::default(),&json!({"sub":id,"owner":owner,"name":name,"is_admin":admin,"iat":now.timestamp(),"exp":now.timestamp()+3600,"issued_at_ms":now.timestamp_millis(),"iss":config.jwt.issuer}),&jsonwebtoken::EncodingKey::from_secret(config.jwt.secret.as_bytes())).unwrap()
}
async fn protected_request(
    service: &Service,
    path: &str,
    token: Option<&str>,
    post: bool,
) -> Response {
    let builder = if post {
        TestClient::post(format!("http://localhost/api/{path}"))
    } else {
        TestClient::get(format!("http://localhost/api/{path}"))
    };
    if let Some(token) = token {
        builder
            .add_header("Authorization", format!("Bearer {token}"), true)
            .send(service)
            .await
    } else {
        builder.send(service).await
    }
}

async fn protected_file_authorization(pool: &PgPool, owner: &str) {
    let real = Service::new(casdog::routes::create_router())
        .hoop(salvo::affix_state::AffixList::new().inject(pool.clone()));
    let buyer = uuid::Uuid::new_v4().to_string();
    let other = uuid::Uuid::new_v4().to_string();
    let tenant_admin = uuid::Uuid::new_v4().to_string();
    let global = uuid::Uuid::new_v4().to_string();
    let foreign = uuid::Uuid::new_v4().to_string();
    let foreign_owner = format!("{owner}-other");
    for (id, tenant, name, admin) in [
        (&buyer, owner, "buyer", false),
        (&other, owner, "other", false),
        (&tenant_admin, owner, "tenant-admin", true),
        (&global, "built-in", owner, true),
        (&foreign, foreign_owner.as_str(), "foreign", true),
    ] {
        sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,is_admin) VALUES($1,$2,$3,$3,'unused',$4)").bind(id).bind(tenant).bind(name).bind(admin).execute(pool).await.unwrap();
    }
    let buyer_token = user_token(&buyer, owner, "buyer", false);
    let other_token = user_token(&other, owner, "other", false);
    let tenant_token = user_token(&tenant_admin, owner, "tenant-admin", true);
    let global_token = user_token(&global, "built-in", owner, true);
    let foreign_token = user_token(&foreign, &foreign_owner, "foreign", true);
    // A real ordinary user gets the resource UUID directly from upload. No
    // administrator list, SQL lookup or identity rewrite is needed to download.
    let mut response = TestClient::post("http://localhost/api/upload-resource")
        .add_header("Authorization", format!("Bearer {buyer_token}"), true)
        .add_header(
            "Content-Type",
            "multipart/form-data; boundary=cloud-boundary",
            true,
        )
        .body(multipart(owner, "local"))
        .send(&real)
        .await;
    let status = response.status_code;
    let uploaded: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{uploaded}");
    let id = uploaded["id"]
        .as_str()
        .expect("upload returns resource UUID")
        .to_string();
    assert!(uuid::Uuid::parse_str(&id).is_ok());
    assert_eq!(uploaded["url"], format!("/api/download-resource/{id}"));
    assert!(!uploaded.to_string().contains("file://"));
    assert_eq!(
        protected_request(&real, "resources", Some(&buyer_token), false)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    for (path, post) in [
        (format!("resource-url/{id}"), false),
        (format!("download-resource/{id}"), false),
        (format!("delete-resource/{id}"), true),
    ] {
        assert_eq!(
            protected_request(&real, &path, None, post)
                .await
                .status_code,
            Some(StatusCode::UNAUTHORIZED)
        );
        for token in [&other_token, &foreign_token] {
            assert_eq!(
                protected_request(&real, &path, Some(token), post)
                    .await
                    .status_code,
                Some(StatusCode::FORBIDDEN)
            );
        }
    }
    for token in [&buyer_token, &tenant_token, &global_token] {
        let mut response =
            protected_request(&real, &format!("resource-url/{id}"), Some(token), false).await;
        let status = response.status_code;
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let value: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{value}");
        assert_eq!(value["access"], "proxy");
        assert!(value["expires_at"].is_null());
        assert_eq!(value["url"], format!("/api/download-resource/{id}"));
        let mut download = protected_request(
            &real,
            &format!("download-resource/{id}"),
            Some(token),
            false,
        )
        .await;
        assert_eq!(download.status_code, Some(StatusCode::OK));
        assert_eq!(download.take_string().await.unwrap(), "cloud actual object");
    }
    // UUID ownership survives rename. A preexisting account taking the old name
    // must not inherit either pinned resources or legacy name-only rows.
    sqlx::query("UPDATE users SET name='renamed-buyer' WHERE id=$1")
        .bind(&buyer)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET name='buyer' WHERE id=$1")
        .bind(&other)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        protected_request(
            &real,
            &format!("resource-url/{id}"),
            Some(&buyer_token),
            false
        )
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        protected_request(
            &real,
            &format!("resource-url/{id}"),
            Some(&other_token),
            false
        )
        .await
        .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    sqlx::query("UPDATE resources SET user_id='buyer' WHERE id=$1")
        .bind(&id)
        .execute(pool)
        .await
        .unwrap();
    for token in [&buyer_token, &other_token] {
        assert_eq!(
            protected_request(&real, &format!("resource-url/{id}"), Some(token), false)
                .await
                .status_code,
            Some(StatusCode::FORBIDDEN)
        );
    }
    assert_eq!(
        protected_request(
            &real,
            &format!("resource-url/{id}"),
            Some(&tenant_token),
            false
        )
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    sqlx::query("UPDATE resources SET user_id=$2 WHERE id=$1")
        .bind(&id)
        .bind(&buyer)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        protected_request(
            &real,
            &format!("delete-resource/{id}"),
            Some(&buyer_token),
            true
        )
        .await
        .status_code,
        Some(StatusCode::OK)
    );
    for id in [&buyer, &other, &tenant_admin, &global, &foreign] {
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }
}

async fn normal_route(gcs: bool) {
    let pool = database().await;
    let f = Fixture::new(gcs).await;
    let owner = format!("cloud-{}", uuid::Uuid::new_v4().simple());
    let service = api(&pool, principal(&owner, true));
    let secret = if gcs {
        f.credentials("fixture-key")
    } else {
        STANDARD.encode(ACCOUNT_KEY)
    };
    let provider = json!({"owner":owner,"name":"storage","display_name":"Native cloud fixture","category":"Storage","type":if gcs {"Google Cloud Storage"} else {"Azure Blob"},"client_id":if gcs {""} else {"fixtureaccount"},"client_secret":secret,"bucket":"assets","metadata":json!({"storageApiEndpoint":f.endpoint,"secretAccessKey":"fixture-secret"}).to_string()});
    let mut response = TestClient::post("http://localhost/api/providers")
        .json(&provider)
        .send(&service)
        .await;
    let status = response.status_code;
    let text = response.take_string().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{text}");
    assert!(!text.contains(TEST_PRIVATE_KEY));
    assert!(!text.contains(&STANDARD.encode(ACCOUNT_KEY)));
    assert!(!text.contains("fixture-secret"));
    let saved_response: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(saved_response["bucket"], "assets");
    assert_eq!(
        serde_json::from_str::<Value>(saved_response["metadata"].as_str().unwrap()).unwrap(),
        json!({"storageApiEndpoint":f.endpoint})
    );
    sqlx::query("UPDATE providers SET client_secret2='secondary-fixture-secret' WHERE owner=$1 AND name='storage'").bind(&owner).execute(&pool).await.unwrap();
    for route in [
        format!("get-provider?id={owner}/storage"),
        format!("get-providers?owner={owner}"),
    ] {
        let mut response = TestClient::get(format!("http://localhost/api/{route}"))
            .send(&service)
            .await;
        let status = response.status_code;
        let result: Value = response.take_json().await.unwrap();
        assert_eq!(status, Some(StatusCode::OK), "{result}");
        let masked = if result["data"].is_array() {
            &result["data"][0]
        } else {
            &result["data"]
        };
        assert_eq!(masked["clientSecret"], "***");
        assert_eq!(masked["clientSecret2"], "***");
        assert!(!result.to_string().contains(&secret));
        assert!(!result.to_string().contains("secondary-fixture-secret"));
    }
    let mut response = TestClient::post(format!(
        "http://localhost/api/update-provider?id={owner}/storage"
    ))
    .json(&json!({"owner":owner,"name":"storage","clientSecret":"***","clientSecret2":"***"}))
    .send(&service)
    .await;
    let status = response.status_code;
    let result: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{result}");
    assert_eq!(result["object"]["clientSecret"], "***");
    let retained: (String, String) = sqlx::query_as(
        "SELECT client_secret,client_secret2 FROM providers WHERE owner=$1 AND name='storage'",
    )
    .bind(&owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        retained,
        (secret.clone(), "secondary-fixture-secret".into())
    );
    let before: Value =
        sqlx::query_scalar("SELECT to_jsonb(p) FROM providers p WHERE owner=$1 AND name='storage'")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    for (index, invalid) in [
        json!({"owner":owner,"name":"storage","clientSecret":"invalid-key","displayName":"must-rollback-key"}),
        json!({"owner":owner,"name":"storage","domain":"https://cdn.example.test/a/%2e%2e/escape","displayName":"must-rollback-path"}),
    ].into_iter().enumerate() {
        let mut response = TestClient::post(format!(
            "http://localhost/api/update-provider?id={owner}/storage"
        ))
        .json(&invalid)
        .send(&service)
        .await;
        let status = response.status_code;
        let error = response.take_string().await.unwrap();
        let body:Value=serde_json::from_str(&error).unwrap();
        if index == 0 {
            assert_eq!(status,Some(StatusCode::INTERNAL_SERVER_ERROR),"{error}");
            assert_eq!(body["message"],"Configuration error");
        } else {
            assert_eq!(status,Some(StatusCode::BAD_REQUEST),"{error}");
            assert_eq!(body["message"],"Validation error");
        }
        let after: Value = sqlx::query_scalar(
            "SELECT to_jsonb(p) FROM providers p WHERE owner=$1 AND name='storage'",
        )
        .bind(&owner)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(after, before);
    }
    let mut invalid_add = provider.clone();
    invalid_add["name"] = json!("invalid-legacy");
    invalid_add["client_secret"] = json!("invalid-key");
    let mut response = TestClient::post("http://localhost/api/add-provider")
        .json(&invalid_add)
        .send(&service)
        .await;
    let status = response.status_code;
    let error = response.take_string().await.unwrap();
    assert_eq!(status, Some(StatusCode::INTERNAL_SERVER_ERROR), "{error}");
    assert_eq!(
        serde_json::from_str::<Value>(&error).unwrap()["message"],
        "Configuration error"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM providers WHERE owner=$1 AND name='invalid-legacy'",
    )
    .bind(&owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
    let mut response = upload(&service, &owner, "storage").await;
    let status = response.status_code;
    let value: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{value}");
    let (id, key, url): (String, String, String) =
        sqlx::query_as("SELECT id,name,url FROM resources WHERE owner=$1")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(url.contains(if gcs { "X-Goog-Signature=" } else { "sig=" }));
    assert_eq!(
        f.state.objects.lock().unwrap()[&key].0,
        b"cloud actual object"
    );
    let mut download = TestClient::get(format!("http://localhost/api/download-resource/{id}"))
        .send(&service)
        .await;
    assert_eq!(download.status_code, Some(StatusCode::OK));
    assert_eq!(download.take_string().await.unwrap(), "cloud actual object");
    // Signed links are regenerated from the saved key and current provider,
    // never from an expired or tampered persisted resource URL.
    sqlx::query("UPDATE resources SET url='https://expired.invalid/old-signed-url' WHERE id=$1")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
    let mut response = TestClient::get(format!("http://localhost/api/resource-url/{id}"))
        .send(&service)
        .await;
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let status = response.status_code;
    let fresh: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{fresh}");
    assert_eq!(fresh["access"], "signed");
    assert!(fresh["expires_at"].as_str().is_some());
    assert!(signed_url_valid(
        &Url::parse(fresh["url"].as_str().unwrap()).unwrap(),
        gcs
    ));
    let provider_id = saved_response["id"].as_str().unwrap();
    let mut response=TestClient::put(format!("http://localhost/api/providers/{provider_id}")).json(&json!({"domain":"https://cdn.current.example.test/new-prefix","path_prefix":"future-only"})).send(&service).await;
    let status = response.status_code;
    let updated: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{updated}");
    assert_eq!(updated["path_prefix"], "future-only");
    let mut response = TestClient::get(format!("http://localhost/api/resource-url/{id}"))
        .send(&service)
        .await;
    let fresh: Value = response.take_json().await.unwrap();
    assert_eq!(fresh["access"], "public");
    assert!(fresh["expires_at"].is_null());
    assert_eq!(
        fresh["url"],
        format!("https://cdn.current.example.test/assets/{key}")
    );
    assert_eq!(
        TestClient::put(format!("http://localhost/api/providers/{provider_id}"))
            .json(&json!({"domain":"","path_prefix":""}))
            .send(&service)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let foreign = api(&pool, principal("other-tenant", false));
    let before = f.state.requests.load(Ordering::SeqCst);
    let tokens = f.state.token_requests.load(Ordering::SeqCst);
    assert_eq!(
        upload(&foreign, &owner, "storage").await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        upload(&foreign, "other-tenant", &format!("{owner}/storage"))
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        TestClient::get(format!("http://localhost/api/download-resource/{id}"))
            .send(&foreign)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        TestClient::post(format!("http://localhost/api/delete-resource/{id}"))
            .send(&foreign)
            .await
            .status_code,
        Some(StatusCode::FORBIDDEN)
    );
    // Even same-tenant admins cannot turn a provider into a private-network SSRF.
    let tenant = api(&pool, principal(&owner, false));
    assert_eq!(
        upload(&tenant, &owner, "storage").await.status_code,
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(f.state.requests.load(Ordering::SeqCst), before);
    assert_eq!(f.state.token_requests.load(Ordering::SeqCst), tokens);
    if gcs {
        // The storage origin is now public/default, while OAuth remains local.
        // Validating only the object origin would leak the signed assertion.
        sqlx::query("UPDATE providers SET metadata=NULL WHERE owner=$1 AND name='storage'")
            .bind(&owner)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            upload(&tenant, &owner, "storage").await.status_code,
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(f.state.token_requests.load(Ordering::SeqCst), tokens);
        sqlx::query("UPDATE providers SET metadata=$2 WHERE owner=$1 AND name='storage'")
            .bind(&owner)
            .bind(json!({"storageApiEndpoint":f.endpoint}).to_string())
            .execute(&pool)
            .await
            .unwrap();
    }
    f.state.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        upload(&service, &owner, "storage").await.status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert_eq!(
        TestClient::post(format!("http://localhost/api/delete-resource/{id}"))
            .send(&service)
            .await
            .status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM resources WHERE owner=$1")
        .bind(&owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    f.state.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        TestClient::post(format!("http://localhost/api/delete-resource/{id}"))
            .send(&service)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert!(f.state.objects.lock().unwrap().is_empty());
    protected_file_authorization(&pool, &owner).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM resources WHERE owner=$1")
        .bind(&owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    // Upstream Domain.path is part of the object key, before path_prefix.
    // A custom public origin does not change the independently configured API.
    let public_config = json!({"owner":owner,"name":"public-storage","display_name":"Public cloud fixture","category":"Storage",
        "type":if gcs {"Google Cloud Storage"} else {"Azure Blob"},"client_id":if gcs {""} else {"fixtureaccount"},
        "client_secret":secret,"bucket":"assets","domain":format!("{}/domain%20path",f.endpoint),
        "endpoint":"https://unused-fallback.example.test/not-selected","path_prefix":"folder/child",
        "metadata":json!({"storageApiEndpoint":f.endpoint}).to_string()});
    let mut response = TestClient::post("http://localhost/api/providers")
        .json(&public_config)
        .send(&service)
        .await;
    let status = response.status_code;
    let body = response.take_string().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    let saved: casdog::models::Provider =
        sqlx::query_as("SELECT * FROM providers WHERE owner=$1 AND name='public-storage'")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    let (display, prefix) =
        casdog::services::providers::cloud_public_configuration(&saved).unwrap();
    assert_eq!(display, f.endpoint);
    assert_eq!(prefix, "domain path/folder/child");
    let mut response = upload(&service, &owner, "public-storage").await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    let (public_id, public_key, public_url): (String, String, String) =
        sqlx::query_as("SELECT id,name,url FROM resources WHERE owner=$1")
            .bind(&owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(public_key.starts_with("domain path/folder/child/"));
    assert!(public_url.starts_with(&format!(
        "{}/assets/domain%20path/folder/child/",
        f.endpoint
    )));
    assert!(!public_url.contains("sig="));
    assert!(!public_url.contains("X-Goog-"));
    assert_eq!(
        f.state.objects.lock().unwrap()[&public_key].0,
        b"cloud actual object"
    );
    let (current_storage, _) = casdog::services::protocol_gap_service::storage_for_owner(
        &principal(&owner, true),
        &owner,
        Some(&saved),
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        current_storage.get_url(&public_key).await.unwrap(),
        public_url
    );
    let mut download = TestClient::get(format!(
        "http://localhost/api/download-resource/{public_id}"
    ))
    .send(&service)
    .await;
    assert_eq!(download.status_code, Some(StatusCode::OK));
    assert_eq!(download.take_string().await.unwrap(), "cloud actual object");
    f.state.public_reads.store(true, Ordering::SeqCst);
    assert_eq!(
        reqwest::get(&public_url)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        b"cloud actual object"
    );
    let mut naked = saved.clone();
    naked.domain = Some("cdn.example.test/nested%20path".into());
    assert_eq!(
        casdog::services::providers::cloud_public_configuration(&naked).unwrap(),
        (
            "https://cdn.example.test".into(),
            "nested path/folder/child".into()
        )
    );
    for path in [
        "https://cdn.example.test/a/../escape",
        "https://cdn.example.test/a/%2e%2e/escape",
        "https://cdn.example.test/a/%5c/escape",
    ] {
        naked.domain = Some(path.into());
        assert!(casdog::services::providers::cloud_public_configuration(&naked).is_err());
    }
    let before = f.state.requests.load(Ordering::SeqCst);
    sqlx::query(
        "UPDATE providers SET path_prefix='../escape' WHERE owner=$1 AND name='public-storage'",
    )
    .bind(&owner)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        upload(&service, &owner, "public-storage").await.status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    assert_eq!(f.state.requests.load(Ordering::SeqCst), before);
    sqlx::query(
        "UPDATE providers SET path_prefix='folder/child' WHERE owner=$1 AND name='public-storage'",
    )
    .bind(&owner)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        TestClient::post(format!("http://localhost/api/delete-resource/{public_id}"))
            .send(&service)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert!(f.state.objects.lock().unwrap().is_empty());
    sqlx::query("DELETE FROM providers WHERE owner=$1")
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn azure_normal_upload_download_delete_routes_recheck_tenant_and_persist_only_remote_success()
{
    normal_route(false).await;
}
#[tokio::test]
#[ignore = "requires CASDOG_TEST_DATABASE_URL"]
async fn gcs_normal_upload_download_delete_routes_recheck_both_origins_and_tenant() {
    normal_route(true).await;
}
