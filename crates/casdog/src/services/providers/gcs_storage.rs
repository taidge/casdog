//! Native GCS JSON API and service-account OAuth. Private objects are exposed
//! only through expiring read-only V4 URLs; uploads do not grant public ACLs.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Client, Method, Url};
use rsa::{
    RsaPrivateKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::SigningKey,
    pkcs8::DecodePrivateKey,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::storage_provider::{
    ObjectPreview, StorageProvider, encode_component, remote_endpoint, remote_preview,
    storage_response, validate_object_key,
};
use crate::error::{AppError, AppResult};

const SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_write";
const TOKEN_BODY_LIMIT: usize = 64 * 1024;

#[derive(Deserialize)]
struct ServiceAccount {
    #[serde(rename = "type")]
    kind: String,
    client_email: String,
    private_key: String,
    private_key_id: Option<String>,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}
fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".into()
}

struct AccessToken {
    value: String,
    expires: Instant,
}
type TokenSlot = Arc<tokio::sync::Mutex<Option<AccessToken>>>;
static TOKENS: OnceLock<Mutex<HashMap<String, TokenSlot>>> = OnceLock::new();

pub struct GoogleCloudStorageProvider {
    client: Client,
    token_client: Client,
    account: ServiceAccount,
    encoding_key: EncodingKey,
    signing_key: SigningKey<Sha256>,
    endpoint: Url,
    public_base: Option<Url>,
    token_endpoint: Url,
    bucket: String,
    token: TokenSlot,
}

impl GoogleCloudStorageProvider {
    pub fn new(service_account_json: String, bucket: String, endpoint: String) -> AppResult<Self> {
        if service_account_json.len() > 64 * 1024 {
            return Err(AppError::Config(
                "GCS service account exceeds 64 KiB".into(),
            ));
        }
        let account: ServiceAccount = serde_json::from_str(&service_account_json)
            .map_err(|_| AppError::Config("Invalid GCS service account JSON".into()))?;
        if account.kind != "service_account"
            || account.client_email.len() > 320
            || !account.client_email.contains('@')
            || account
                .client_email
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || account
                .private_key_id
                .as_ref()
                .is_some_and(|s| s.len() > 256 || s.chars().any(char::is_control))
        {
            return Err(AppError::Config(
                "Invalid GCS service account identity".into(),
            ));
        }
        if !(3..=222).contains(&bucket.len())
            || matches!(bucket.as_str(), "." | "..")
            || !bucket.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
            })
        {
            return Err(AppError::Validation("Invalid GCS bucket".into()));
        }
        let public_base = if endpoint.is_empty() {
            None
        } else {
            Some(remote_endpoint(&endpoint)?)
        };
        let endpoint = remote_endpoint("https://storage.googleapis.com")?;
        let token_endpoint = remote_endpoint(&account.token_uri)?;
        // HTTP is useful for a local emulator, but credentials must never cross
        // plaintext remote networks. The normal route also DNS-pins both origins.
        for url in [&endpoint, &token_endpoint] {
            if url.scheme() == "http"
                && !matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
            {
                return Err(AppError::Config(
                    "GCS endpoints require HTTPS except loopback emulators".into(),
                ));
            }
        }
        let encoding_key = EncodingKey::from_rsa_pem(account.private_key.as_bytes())
            .map_err(|_| AppError::Config("Invalid GCS RSA private key".into()))?;
        let private = RsaPrivateKey::from_pkcs8_pem(&account.private_key)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&account.private_key))
            .map_err(|_| AppError::Config("Invalid GCS RSA private key".into()))?;
        if private.size() < 256 {
            return Err(AppError::Config(
                "GCS requires an RSA key of at least 2048 bits".into(),
            ));
        }
        let signing_key = SigningKey::<Sha256>::new(private);
        // Include the complete secret and endpoints: key rotation, account
        // changes, or alternate issuers can never reuse another identity's token.
        let fingerprint = hex::encode(Sha256::digest(format!(
            "{service_account_json}\n{token_endpoint}\n{endpoint}\n{SCOPE}"
        )));
        let token = {
            let mut cache = TOKENS
                .get_or_init(Default::default)
                .lock()
                .map_err(|_| AppError::Internal("GCS credential cache unavailable".into()))?;
            if cache.len() >= 256 && !cache.contains_key(&fingerprint) {
                cache.clear();
            }
            cache
                .entry(fingerprint)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
                .clone()
        };
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(8))
            .build()
            .expect("static storage client");
        Ok(Self {
            token_client: client.clone(),
            client,
            account,
            encoding_key,
            signing_key,
            endpoint,
            public_base,
            token_endpoint,
            bucket,
            token,
        })
    }

    pub fn base_url(&self) -> AppResult<Url> {
        Ok(self.endpoint.clone())
    }
    pub fn token_url(&self) -> AppResult<Url> {
        Ok(self.token_endpoint.clone())
    }
    /// Explicit Provider.metadata.storageApiEndpoint extension. Endpoint itself
    /// retains upstream public/CDN semantics and is never an OAuth API target.
    pub fn with_api_endpoint(mut self, endpoint: String) -> AppResult<Self> {
        let endpoint = remote_endpoint(&endpoint)?;
        if endpoint.scheme() == "http"
            && !matches!(
                endpoint.host_str(),
                Some("127.0.0.1" | "[::1]" | "localhost")
            )
        {
            return Err(AppError::Config(
                "GCS API requires HTTPS except loopback emulators".into(),
            ));
        }
        self.endpoint = endpoint;
        Ok(self)
    }
    /// Both origins must be checked independently before injecting these clients.
    pub fn with_clients(mut self, storage: Client, token: Client) -> Self {
        self.client = storage;
        self.token_client = token;
        self
    }

    fn object_url(&self, key: &str, upload: bool, media: bool) -> AppResult<Url> {
        validate_object_key(key)?;
        let base = self.endpoint.as_str().trim_end_matches('/');
        let mut url = if upload {
            Url::parse(&format!("{base}/upload/storage/v1/b/{}/o", self.bucket))
        } else {
            Url::parse(&format!(
                "{base}/storage/v1/b/{}/o/{}",
                self.bucket,
                encode_component(key)
            ))
        }
        .map_err(|_| AppError::Validation("Invalid GCS object URL".into()))?;
        if upload {
            url.query_pairs_mut()
                .append_pair("uploadType", "media")
                .append_pair("name", key);
        } else if media {
            url.query_pairs_mut().append_pair("alt", "media");
        }
        Ok(url)
    }

    async fn access_token(&self) -> AppResult<String> {
        let mut slot = self.token.lock().await;
        if let Some(token) = slot.as_ref().filter(|t| t.expires > Instant::now()) {
            return Ok(token.value.clone());
        }
        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            scope: &'a str,
            aud: &'a str,
            iat: i64,
            exp: i64,
        }
        let now = Utc::now().timestamp();
        let claims = Claims {
            iss: &self.account.client_email,
            scope: SCOPE,
            aud: self.token_endpoint.as_str(),
            iat: now,
            exp: now + 3600,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = self.account.private_key_id.clone();
        let assertion = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|_| AppError::Config("Cannot sign GCS OAuth assertion".into()))?;
        let mut response = self
            .token_client
            .post(self.token_endpoint.clone())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ])
            .send()
            .await
            .map_err(|_| AppError::Internal("GCS OAuth token request failed".into()))?;
        if !response.status().is_success() {
            *slot = None;
            return Err(AppError::Authentication(format!(
                "GCS OAuth returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AppError::Internal("GCS OAuth response interrupted".into()))?
        {
            if body.len() + chunk.len() > TOKEN_BODY_LIMIT {
                return Err(AppError::Authentication(
                    "GCS OAuth response too large".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        #[derive(Deserialize)]
        struct Token {
            access_token: String,
            expires_in: u64,
            token_type: String,
        }
        let token: Token = serde_json::from_slice(&body)
            .map_err(|_| AppError::Authentication("Invalid GCS OAuth response".into()))?;
        if token.access_token.is_empty()
            || token.access_token.len() > 16 * 1024
            || token.access_token.bytes().any(|b| b <= b' ' || b >= 127)
            || !token.token_type.eq_ignore_ascii_case("Bearer")
            || token.expires_in == 0
            || token.expires_in > 3600
        {
            return Err(AppError::Authentication("Invalid GCS OAuth token".into()));
        }
        let value = token.access_token;
        // Small expiry values remain usable for this request but are not cached.
        *slot = Some(AccessToken {
            value: value.clone(),
            expires: Instant::now() + Duration::from_secs(token.expires_in.saturating_sub(60)),
        });
        Ok(value)
    }

    async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<(&[u8], &str)>,
        range: Option<&str>,
    ) -> AppResult<reqwest::Response> {
        for attempt in 0..2 {
            let token = self.access_token().await?;
            let mut request = self
                .client
                .request(method.clone(), url.clone())
                .bearer_auth(&token)
                .header("Accept-Encoding", "identity");
            if let Some((data, mime)) = body {
                request = request.header("Content-Type", mime).body(data.to_vec());
            }
            if let Some(range) = range {
                request = request.header("Range", range);
            }
            let response = request
                .send()
                .await
                .map_err(|_| AppError::Internal("GCS object request failed".into()))?;
            if response.status() != reqwest::StatusCode::UNAUTHORIZED {
                return Ok(response);
            }
            // Never invalidate a newer token installed by another concurrent
            // request. A rejected token cannot poison later provider instances.
            let mut slot = self.token.lock().await;
            if slot.as_ref().is_some_and(|cached| cached.value == token) {
                *slot = None;
            }
            if attempt == 1 {
                return Ok(response);
            }
        }
        unreachable!()
    }

    pub async fn exists(&self, key: &str) -> AppResult<bool> {
        let response = self
            .request(Method::GET, self.object_url(key, false, false)?, None, None)
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        storage_response(&response, "GCS metadata")?;
        Ok(true)
    }
}

#[async_trait]
impl StorageProvider for GoogleCloudStorageProvider {
    async fn upload(&self, key: &str, data: &[u8], content_type: &str) -> AppResult<String> {
        let response = self
            .request(
                Method::POST,
                self.object_url(key, true, false)?,
                Some((data, content_type)),
                None,
            )
            .await?;
        storage_response(&response, "GCS upload")?;
        self.get_url(key).await
    }
    async fn download(&self, key: &str) -> AppResult<Vec<u8>> {
        let response = self
            .request(Method::GET, self.object_url(key, false, true)?, None, None)
            .await?;
        storage_response(&response, "GCS download")?;
        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|_| AppError::Internal("GCS object read failed".into()))
    }
    async fn preview(&self, key: &str, limit: usize) -> AppResult<ObjectPreview> {
        if limit == 0 || limit == usize::MAX {
            return Err(AppError::Validation("Invalid storage preview limit".into()));
        }
        let response = self
            .request(
                Method::GET,
                self.object_url(key, false, true)?,
                None,
                Some(&format!("bytes=0-{limit}")),
            )
            .await?;
        remote_preview(response, limit).await
    }
    async fn delete(&self, key: &str) -> AppResult<()> {
        let response = self
            .request(
                Method::DELETE,
                self.object_url(key, false, false)?,
                None,
                None,
            )
            .await?;
        storage_response(&response, "GCS delete")
    }
    async fn get_url(&self, key: &str) -> AppResult<String> {
        validate_object_key(key)?;
        if let Some(base) = &self.public_base {
            let path = key
                .split('/')
                .map(encode_component)
                .collect::<Vec<_>>()
                .join("/");
            return Ok(format!(
                "{}/{}/{path}",
                base.as_str().trim_end_matches('/'),
                self.bucket
            ));
        }
        let now = Utc::now();
        let date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let scope = format!("{}/auto/storage/goog4_request", now.format("%Y%m%d"));
        let credential = format!("{}/{scope}", self.account.client_email);
        let key_path = key
            .split('/')
            .map(encode_component)
            .collect::<Vec<_>>()
            .join("/");
        let mut url = Url::parse(&format!(
            "{}/{}/{key_path}",
            self.endpoint.as_str().trim_end_matches('/'),
            self.bucket
        ))
        .map_err(|_| AppError::Validation("Invalid GCS signed URL".into()))?;
        let query = [
            ("X-Goog-Algorithm", "GOOG4-RSA-SHA256"),
            ("X-Goog-Credential", &credential),
            ("X-Goog-Date", &date),
            ("X-Goog-Expires", "900"),
            ("X-Goog-SignedHeaders", "host"),
        ]
        .iter()
        .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
        .collect::<Vec<_>>()
        .join("&");
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        let canonical = format!(
            "GET\n{}\n{query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
            url.path()
        );
        let to_sign = format!(
            "GOOG4-RSA-SHA256\n{date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical))
        );
        let signature = self.signing_key.sign(to_sign.as_bytes());
        url.set_query(Some(&format!(
            "{query}&X-Goog-Signature={}",
            hex::encode(signature.to_vec())
        )));
        Ok(url.into())
    }
}
