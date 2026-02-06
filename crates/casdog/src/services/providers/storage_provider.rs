use crate::error::{AppError, AppResult};
use async_trait::async_trait;

/// Trait for storage providers
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Upload a file to storage
    /// Returns the URL where the file can be accessed
    async fn upload(&self, key: &str, data: &[u8], content_type: &str) -> AppResult<String>;

    /// Download a file from storage
    async fn download(&self, key: &str) -> AppResult<Vec<u8>>;

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
