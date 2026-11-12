use std::path::PathBuf;

use async_trait::async_trait;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{AppError, AppResult};
use crate::services::providers::storage_provider::{
    ObjectPreview, StorageProvider, validate_object_key,
};

/// Local file system storage provider
pub struct LocalStorageProvider {
    base_dir: PathBuf,
}

impl LocalStorageProvider {
    /// Create a new local storage provider
    /// base_dir is the root directory where files will be stored
    pub fn new(base_dir: String) -> Self {
        Self {
            base_dir: PathBuf::from(base_dir),
        }
    }

    /// Get the full file path for a given key
    fn get_file_path(&self, key: &str) -> PathBuf {
        self.base_dir.join(key)
    }

    /// Ensure the parent directory exists
    async fn ensure_parent_dir(&self, path: &PathBuf) -> AppResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to create directory: {}", e)))?;
        }
        Ok(())
    }
}

#[async_trait]
impl StorageProvider for LocalStorageProvider {
    async fn upload(&self, key: &str, data: &[u8], _content_type: &str) -> AppResult<String> {
        let file_path = self.get_file_path(key);

        // Ensure parent directory exists
        self.ensure_parent_dir(&file_path).await?;

        // Write the file
        let mut file = fs::File::create(&file_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create file: {}", e)))?;

        file.write_all(data)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to write file: {}", e)))?;

        file.flush()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to flush file: {}", e)))?;

        // Return file:// URL
        let url = format!("file://{}", file_path.display());
        Ok(url)
    }

    async fn download(&self, key: &str) -> AppResult<Vec<u8>> {
        let file_path = self.get_file_path(key);

        // Check if file exists
        if !file_path.exists() {
            return Err(AppError::NotFound(format!("File not found: {}", key)));
        }

        // Read the file
        let data = fs::read(&file_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read file: {}", e)))?;

        Ok(data)
    }

    async fn preview(&self, key: &str, limit: usize) -> AppResult<ObjectPreview> {
        validate_object_key(key)?;
        // Canonicalize both sides on every read: an existing resource must not
        // turn a later symlink/reparse-point replacement into a root escape.
        let root = fs::canonicalize(&self.base_dir)
            .await
            .map_err(|_| AppError::NotFound("Storage directory unavailable".into()))?;
        let path = fs::canonicalize(self.get_file_path(key))
            .await
            .map_err(|_| AppError::NotFound("Transcript object not found".into()))?;
        if !path.starts_with(&root) {
            return Err(AppError::Authorization(
                "Transcript path escapes storage root".into(),
            ));
        }
        let file = fs::File::open(path)
            .await
            .map_err(|_| AppError::NotFound("Transcript object unavailable".into()))?;
        let size = file
            .metadata()
            .await
            .map_err(|_| AppError::Internal("Cannot read transcript size".into()))?
            .len();
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| AppError::Internal("Cannot read transcript".into()))?;
        let truncated = bytes.len() > limit || size > bytes.len() as u64;
        bytes.truncate(limit);
        Ok(ObjectPreview {
            bytes,
            size: Some(size),
            truncated,
        })
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let file_path = self.get_file_path(key);

        // Check if file exists
        if !file_path.exists() {
            return Err(AppError::NotFound(format!("File not found: {}", key)));
        }

        // Delete the file
        fs::remove_file(&file_path)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to delete file: {}", e)))?;

        Ok(())
    }

    async fn get_url(&self, key: &str) -> AppResult<String> {
        let file_path = self.get_file_path(key);

        // Check if file exists
        if !file_path.exists() {
            return Err(AppError::NotFound(format!("File not found: {}", key)));
        }

        // Return file:// URL
        let url = format!("file://{}", file_path.display());
        Ok(url)
    }
}
