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
        "local" => {
            let provider = super::local_storage::LocalStorageProvider::new(bucket.to_string());
            Ok(Box::new(provider))
        }
        "s3" => {
            let provider = super::s3_storage::S3StorageProvider::new(
                client_id.to_string(),
                client_secret.to_string(),
                region.to_string(),
                bucket.to_string(),
                endpoint.to_string(),
            );
            Ok(Box::new(provider))
        }
        _ => Err(AppError::Config(format!(
            "Unsupported storage provider type: {}",
            provider_type
        ))),
    }
}
