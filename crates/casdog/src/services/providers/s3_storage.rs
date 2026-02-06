use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose;
use reqwest::Client;
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::services::providers::storage_provider::StorageProvider;

/// S3-compatible storage provider using raw HTTP
/// This implementation uses simple HTTP operations for S3-compatible storage
/// For production use with private buckets, consider using the official AWS SDK
pub struct S3StorageProvider {
    client: Client,
    access_key: String,
    secret_key: String,
    region: String,
    bucket: String,
    endpoint: String,
}

impl S3StorageProvider {
    /// Create a new S3 storage provider
    pub fn new(
        access_key: String,
        secret_key: String,
        region: String,
        bucket: String,
        endpoint: String,
    ) -> Self {
        Self {
            client: Client::new(),
            access_key,
            secret_key,
            region,
            bucket,
            endpoint,
        }
    }

    /// Get the base URL for the bucket
    fn get_base_url(&self) -> String {
        if self.endpoint.is_empty() {
            format!("https://{}.s3.{}.amazonaws.com", self.bucket, self.region)
        } else {
            format!("{}/{}", self.endpoint.trim_end_matches('/'), self.bucket)
        }
    }

    /// Get the full URL for a key
    fn get_object_url(&self, key: &str) -> String {
        format!("{}/{}", self.get_base_url(), key.trim_start_matches('/'))
    }

    /// Create a basic authorization header using access key and secret
    /// Note: This is a simplified implementation. For production with AWS S3,
    /// you should implement full AWS Signature V4 or use the AWS SDK
    fn create_basic_auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.access_key, self.secret_key);
        let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
        format!("Basic {}", encoded)
    }

    /// Calculate SHA256 hash of content
    fn calculate_content_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

#[async_trait]
impl StorageProvider for S3StorageProvider {
    async fn upload(&self, key: &str, data: &[u8], content_type: &str) -> AppResult<String> {
        let url = self.get_object_url(key);

        // Calculate content hash
        let content_hash = Self::calculate_content_hash(data);

        // Get current date in ISO 8601 format
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        // Build the request with basic headers
        // Note: For production S3, implement full AWS Signature V4 or use AWS SDK
        let mut request = self
            .client
            .put(&url)
            .header("Content-Type", content_type)
            .header("x-amz-content-sha256", &content_hash)
            .header("x-amz-date", &amz_date);

        // Add basic auth if credentials are provided (for S3-compatible services like MinIO)
        if !self.access_key.is_empty() && !self.secret_key.is_empty() {
            request = request.header("Authorization", self.create_basic_auth_header());
        }

        let response = request
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("S3 upload failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Internal(format!(
                "S3 upload failed with status {}: {}",
                status, body
            )));
        }

        Ok(url)
    }

    async fn download(&self, key: &str) -> AppResult<Vec<u8>> {
        let url = self.get_object_url(key);

        // Build the request
        let mut request = self.client.get(&url);

        // Add basic auth if credentials are provided
        if !self.access_key.is_empty() && !self.secret_key.is_empty() {
            request = request.header("Authorization", self.create_basic_auth_header());
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("S3 download failed: {}", e)))?;

        if response.status() == 404 {
            return Err(AppError::NotFound(format!("Object not found: {}", key)));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Internal(format!(
                "S3 download failed with status {}: {}",
                status, body
            )));
        }

        let data = response
            .bytes()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read S3 response: {}", e)))?
            .to_vec();

        Ok(data)
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let url = self.get_object_url(key);

        // Build the request
        let mut request = self.client.delete(&url);

        // Add basic auth if credentials are provided
        if !self.access_key.is_empty() && !self.secret_key.is_empty() {
            request = request.header("Authorization", self.create_basic_auth_header());
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("S3 delete failed: {}", e)))?;

        if response.status() == 404 {
            return Err(AppError::NotFound(format!("Object not found: {}", key)));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Internal(format!(
                "S3 delete failed with status {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    async fn get_url(&self, key: &str) -> AppResult<String> {
        // For public buckets, just return the URL
        // For private buckets, you'd want to generate a presigned URL
        Ok(self.get_object_url(key))
    }
}
