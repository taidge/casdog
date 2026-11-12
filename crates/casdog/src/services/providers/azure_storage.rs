//! Azure Blob's native REST API, using an account Shared Key (Casdoor's
//! clientId/clientSecret). Uploads never enable anonymous container access.
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use reqwest::{Client, Method, RequestBuilder, Url};
use sha2::Sha256;

use super::storage_provider::{
    ObjectPreview, StorageProvider, encode_component, remote_endpoint, remote_preview,
    storage_response, validate_object_key,
};
use crate::error::{AppError, AppResult};

const VERSION: &str = "2022-11-02";

pub struct AzureBlobStorageProvider {
    client: Client,
    account: String,
    key: Vec<u8>,
    container: String,
    endpoint: Url,
    public_base: Option<Url>,
}

impl AzureBlobStorageProvider {
    pub fn new(account: String, key: String, bucket: String, endpoint: String) -> AppResult<Self> {
        if !(3..=24).contains(&account.len())
            || !account
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || !(3..=63).contains(&bucket.len())
            || bucket.starts_with('-')
            || bucket.ends_with('-')
            || bucket.contains("--")
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(AppError::Validation(
                "Invalid Azure storage account or container".into(),
            ));
        }
        let key = STANDARD
            .decode(key)
            .map_err(|_| AppError::Config("Invalid Azure account key".into()))?;
        if !(16..=128).contains(&key.len()) {
            return Err(AppError::Config("Invalid Azure account key".into()));
        }
        let public_base = if endpoint.is_empty() {
            None
        } else {
            Some(remote_endpoint(&endpoint)?)
        };
        let endpoint = remote_endpoint(&format!("https://{account}.blob.core.windows.net"))?;
        Ok(Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(8))
                .build()
                .expect("static storage client"),
            account,
            key,
            container: bucket,
            endpoint,
            public_base,
        })
    }

    pub fn base_url(&self) -> AppResult<Url> {
        Ok(self.endpoint.clone())
    }
    /// Every application entry point supplies the checked, DNS-pinned client.
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }
    /// Explicit extension for sovereign clouds/emulators. Casdoor's Endpoint
    /// remains the public/CDN base and never receives account credentials.
    pub fn with_api_endpoint(mut self, endpoint: String) -> AppResult<Self> {
        let endpoint = remote_endpoint(&endpoint)?;
        if endpoint.scheme() == "http"
            && !matches!(
                endpoint.host_str(),
                Some("127.0.0.1" | "[::1]" | "localhost")
            )
        {
            return Err(AppError::Config(
                "Azure API requires HTTPS except loopback emulators".into(),
            ));
        }
        self.endpoint = endpoint;
        Ok(self)
    }

    fn object_url(&self, key: &str) -> AppResult<Url> {
        validate_object_key(key)?;
        let path = key
            .split('/')
            .map(encode_component)
            .collect::<Vec<_>>()
            .join("/");
        Url::parse(&format!(
            "{}/{}/{}",
            self.endpoint.as_str().trim_end_matches('/'),
            self.container,
            path
        ))
        .map_err(|_| AppError::Validation("Invalid Azure object URL".into()))
    }

    fn signature(&self, value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key");
        mac.update(value.as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    }

    fn request(
        &self,
        method: Method,
        url: Url,
        length: usize,
        content_type: Option<&str>,
        range: Option<&str>,
    ) -> AppResult<RequestBuilder> {
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let upload = method == Method::PUT;
        let mut headers = if upload {
            "x-ms-blob-type:BlockBlob\n".to_string()
        } else {
            String::new()
        };
        headers.push_str(&format!("x-ms-date:{date}\nx-ms-version:{VERSION}\n"));
        // https://learn.microsoft.com/rest/api/storageservices/authorize-with-shared-key
        let mut fields = vec![
            method.as_str().to_string(),
            String::new(),
            String::new(),
            if length == 0 {
                String::new()
            } else {
                length.to_string()
            },
            String::new(),
            content_type.unwrap_or("").into(),
        ];
        fields.extend((0..5).map(|_| String::new())); // Date + conditional headers
        fields.push(range.unwrap_or("").into());
        let canonical = format!(
            "{}\n{headers}/{}{}",
            fields.join("\n"),
            self.account,
            url.path()
        );
        let auth = format!("SharedKey {}:{}", self.account, self.signature(&canonical));
        let mut request = self
            .client
            .request(method, url)
            .header("x-ms-date", date)
            .header("x-ms-version", VERSION)
            .header("Authorization", auth)
            .header("Accept-Encoding", "identity");
        if upload {
            request = request
                .header("x-ms-blob-type", "BlockBlob")
                .header("Content-Length", length);
        }
        if let Some(value) = content_type {
            request = request.header("Content-Type", value);
        }
        if let Some(value) = range {
            request = request.header("Range", value);
        }
        Ok(request)
    }

    pub async fn exists(&self, key: &str) -> AppResult<bool> {
        let response = self
            .request(Method::HEAD, self.object_url(key)?, 0, None, None)?
            .send()
            .await
            .map_err(|_| AppError::Internal("Azure object metadata request failed".into()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        storage_response(&response, "Azure metadata")?;
        Ok(true)
    }
}

#[async_trait]
impl StorageProvider for AzureBlobStorageProvider {
    async fn upload(&self, key: &str, data: &[u8], content_type: &str) -> AppResult<String> {
        let response = self
            .request(
                Method::PUT,
                self.object_url(key)?,
                data.len(),
                Some(content_type),
                None,
            )?
            .body(data.to_vec())
            .send()
            .await
            .map_err(|_| AppError::Internal("Azure upload failed".into()))?;
        storage_response(&response, "Azure upload")?;
        self.get_url(key).await
    }
    async fn download(&self, key: &str) -> AppResult<Vec<u8>> {
        let response = self
            .request(Method::GET, self.object_url(key)?, 0, None, None)?
            .send()
            .await
            .map_err(|_| AppError::Internal("Azure download failed".into()))?;
        storage_response(&response, "Azure download")?;
        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|_| AppError::Internal("Azure object read failed".into()))
    }
    async fn preview(&self, key: &str, limit: usize) -> AppResult<ObjectPreview> {
        if limit == 0 || limit == usize::MAX {
            return Err(AppError::Validation("Invalid storage preview limit".into()));
        }
        let response = self
            .request(
                Method::GET,
                self.object_url(key)?,
                0,
                None,
                Some(&format!("bytes=0-{limit}")),
            )?
            .send()
            .await
            .map_err(|_| AppError::Internal("Azure preview failed".into()))?;
        remote_preview(response, limit).await
    }
    async fn delete(&self, key: &str) -> AppResult<()> {
        let response = self
            .request(Method::DELETE, self.object_url(key)?, 0, None, None)?
            .send()
            .await
            .map_err(|_| AppError::Internal("Azure delete failed".into()))?;
        storage_response(&response, "Azure delete")
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
                self.container
            ));
        }
        let mut url = self.object_url(key)?;
        let now = Utc::now();
        let start = (now - Duration::minutes(5)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let expiry = (now + Duration::minutes(15)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let protocol = if url.scheme() == "https" {
            "https"
        } else {
            "https,http"
        };
        let resource = format!("/blob/{}/{}/{}", self.account, self.container, key);
        let fields = [
            "r", &start, &expiry, &resource, "", "", protocol, VERSION, "b", "", "", "", "", "",
            "", "",
        ];
        let signature = self.signature(&fields.join("\n"));
        url.query_pairs_mut().extend_pairs([
            ("sp", "r"),
            ("st", &start),
            ("se", &expiry),
            ("spr", protocol),
            ("sv", VERSION),
            ("sr", "b"),
            ("sig", &signature),
        ]);
        Ok(url.into())
    }
}
