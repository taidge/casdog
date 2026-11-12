use async_trait::async_trait;

use crate::error::{AppError, AppResult};

/// A bounded prefix of an object. `size` is absent when the remote server did
/// not disclose the total and reading stopped before the end of the response.
pub struct ObjectPreview {
    pub bytes: Vec<u8>,
    pub size: Option<u64>,
    pub truncated: bool,
}

pub(crate) fn validate_object_key(key: &str) -> AppResult<()> {
    if key.is_empty()
        || key.len() > 1024
        || key.contains(['\\', ':'])
        || key.chars().any(char::is_control)
        || key.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(AppError::Validation("Invalid storage object key".into()));
    }
    Ok(())
}

/// Casdoor puts Domain's path into the *object key*, then places the bucket
/// between the public origin and that key. Keep this independent from the API
/// origin: CDN configuration must never receive storage/OAuth credentials.
/// Returns (public origin or empty for private signed URLs, relative key prefix).
pub fn cloud_public_configuration(
    provider: &crate::models::Provider,
) -> AppResult<(String, String)> {
    let domain = provider.domain.as_deref().unwrap_or("").trim();
    let endpoint = provider.endpoint.as_deref().unwrap_or("").trim();
    let display = if !domain.is_empty() { domain } else { endpoint };
    let mut parts = Vec::new();
    let origin = if display.is_empty() {
        String::new()
    } else {
        let display = if !domain.is_empty() && !display.contains("://") {
            format!("https://{display}")
        } else {
            display.to_string()
        };
        // Validate before Url normalizes dot segments, including percent-encoded
        // dots. Otherwise /a/../b would silently become an accepted /b prefix.
        let raw_path = display
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('/').map(|(_, path)| path))
            .unwrap_or("");
        let decoded = urlencoding::decode(raw_path)
            .map_err(|_| AppError::Validation("Invalid public storage path encoding".into()))?;
        let path = decoded.trim_matches('/');
        if !path.is_empty() {
            validate_object_key(path)?;
            parts.push(path.to_string());
        }
        let url = remote_endpoint(&display)?;
        url.origin().ascii_serialization()
    };
    if let Some(prefix) = provider.path_prefix.as_deref() {
        let prefix = prefix.trim_matches('/');
        if !prefix.is_empty() {
            validate_object_key(prefix)?;
            parts.push(prefix.to_string());
        }
    }
    let prefix = parts.join("/");
    if !prefix.is_empty() {
        validate_object_key(&prefix)?;
    }
    Ok((origin, prefix))
}

/// RFC 3986 encoding for one path/query component, without form '+' encoding.
pub(crate) fn encode_component(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            result.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(result, "%{byte:02X}").expect("String write");
        }
    }
    result
}

pub(crate) fn remote_endpoint(value: &str) -> AppResult<reqwest::Url> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| AppError::Validation("Invalid storage endpoint".into()))?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().split('/').any(|s| s == "." || s == "..")
    {
        return Err(AppError::Validation(
            "Storage endpoint must be HTTP(S) without credentials, query or fragment".into(),
        ));
    }
    Ok(url)
}

pub(crate) fn storage_response(response: &reqwest::Response, operation: &str) -> AppResult<()> {
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(AppError::NotFound("Storage object not found".into()));
    }
    if !response.status().is_success() {
        // Never expose untrusted remote error bodies, request URLs or credentials.
        return Err(AppError::Internal(format!(
            "{operation} returned HTTP {}",
            response.status().as_u16()
        )));
    }
    Ok(())
}

/// Bounded streaming preview shared by the native cloud adapters. An extra
/// sentinel byte detects truncation even when the service ignores Range.
pub(crate) async fn remote_preview(
    mut response: reqwest::Response,
    limit: usize,
) -> AppResult<ObjectPreview> {
    use reqwest::StatusCode;
    let invalid = || AppError::Validation("Invalid storage preview response".into());
    if limit == 0 || limit == usize::MAX {
        return Err(invalid());
    }
    if response.status() == StatusCode::RANGE_NOT_SATISFIABLE
        && response
            .headers()
            .get("Content-Range")
            .and_then(|s| s.to_str().ok())
            == Some("bytes */0")
    {
        return Ok(ObjectPreview {
            bytes: Vec::new(),
            size: Some(0),
            truncated: false,
        });
    }
    storage_response(&response, "Storage preview")?;
    if response
        .headers()
        .get("Content-Encoding")
        .is_some_and(|s| s != "identity")
    {
        return Err(invalid());
    }
    let partial = response.status() == StatusCode::PARTIAL_CONTENT;
    let (mut size, expected) = if partial {
        let range = response
            .headers()
            .get("Content-Range")
            .and_then(|s| s.to_str().ok())
            .and_then(|s| s.strip_prefix("bytes 0-"))
            .ok_or_else(invalid)?;
        let (end, total) = range.split_once('/').ok_or_else(invalid)?;
        let end: u64 = end.parse().map_err(|_| invalid())?;
        let total = if total == "*" {
            None
        } else {
            Some(total.parse::<u64>().map_err(|_| invalid())?)
        };
        if end > limit as u64 || total.is_some_and(|total| total <= end) {
            return Err(invalid());
        }
        (total, Some(end + 1))
    } else if response.status() == StatusCode::OK {
        (response.content_length(), None)
    } else {
        return Err(invalid());
    };
    let mut bytes = Vec::new();
    let mut complete = false;
    while bytes.len() <= limit {
        let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AppError::Internal("Storage preview interrupted".into()))?
        else {
            complete = true;
            break;
        };
        let remaining = limit + 1 - bytes.len();
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    if complete && expected.is_some_and(|count| count != bytes.len() as u64) {
        return Err(invalid());
    }
    if complete && !partial && size.is_none() {
        size = Some(bytes.len() as u64);
    }
    let truncated = bytes.len() > limit
        || size.is_some_and(|s| s > bytes.len() as u64)
        || (partial && size.is_none());
    bytes.truncate(limit);
    Ok(ObjectPreview {
        bytes,
        size,
        truncated,
    })
}

/// Trait for storage providers
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Upload a file to storage
    /// Returns the URL where the file can be accessed
    async fn upload(&self, key: &str, data: &[u8], content_type: &str) -> AppResult<String>;

    /// Download a file from storage
    async fn download(&self, key: &str) -> AppResult<Vec<u8>>;

    /// Read at most `limit` bytes without buffering the complete object.
    async fn preview(&self, key: &str, limit: usize) -> AppResult<ObjectPreview>;

    /// Delete a file from storage
    async fn delete(&self, key: &str) -> AppResult<()>;

    /// Get the URL for accessing a file
    async fn get_url(&self, key: &str) -> AppResult<String>;
}

/// Factory function to create storage providers
pub fn get_storage_provider(
    provider_type: &str,
    client_id: &str,
    client_secret: &str,
    region: &str,
    bucket: &str,
    endpoint: &str,
) -> AppResult<Box<dyn StorageProvider>> {
    match provider_type.to_lowercase().as_str() {
        "local" | "local file system" => {
            let provider = super::local_storage::LocalStorageProvider::new(bucket.to_string());
            Ok(Box::new(provider))
        }
        "s3" | "aws s3" | "minio" => {
            let provider = super::s3_storage::S3StorageProvider::new(
                client_id.to_string(),
                client_secret.to_string(),
                region.to_string(),
                bucket.to_string(),
                endpoint.to_string(),
            );
            Ok(Box::new(provider))
        }
        "azure blob" => Ok(Box::new(
            super::azure_storage::AzureBlobStorageProvider::new(
                client_id.into(),
                client_secret.into(),
                bucket.into(),
                endpoint.into(),
            )?,
        )),
        "google cloud storage" => Ok(Box::new(
            super::gcs_storage::GoogleCloudStorageProvider::new(
                client_secret.into(),
                bucket.into(),
                endpoint.into(),
            )?,
        )),
        _ => Err(AppError::Config(format!(
            "Unsupported storage provider type: {}",
            provider_type
        ))),
    }
}
