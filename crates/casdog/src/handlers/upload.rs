use salvo::oapi::{ToSchema, endpoint};
use salvo::prelude::*;
use serde::Serialize;
use sqlx::{Pool, Postgres};

use crate::error::AppError;
use crate::services::providers::storage_provider::{StorageProvider, get_storage_provider};
use crate::services::{ProviderService, ResourceService};

#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResponse {
    pub name: String,
    pub url: String,
    pub size: u64,
    pub file_type: String,
}

/// Upload a resource file.
///
/// Accepts multipart form with:
/// - `file`: The file to upload
/// - `owner`: Owner organization
/// - `tag`: Optional tag/category
/// - `application`: Optional application name
/// - `provider`: Optional storage provider name (defaults to local)
/// - `description`: Optional description
#[endpoint(
    tags("Resources"),
    responses(
        (status_code = 200, description = "File uploaded successfully", body = UploadResponse),
        (status_code = 400, description = "Invalid file or missing parameters"),
    )
)]
pub async fn upload_resource(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<UploadResponse>, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    // Extract user context set by JwtAuth middleware
    let user_id = depot
        .get::<String>("user_id")
        .cloned()
        .map_err(|_| AppError::Authentication("Not authenticated".to_string()))?;
    let user_owner = depot
        .get::<String>("user_owner")
        .cloned()
        .unwrap_or_default();

    // Get the uploaded file from multipart form
    let file = req
        .file("file")
        .await
        .ok_or_else(|| AppError::Validation("No file provided".to_string()))?;

    let file_name = file
        .name()
        .map(|n| n.to_string())
        .unwrap_or_else(|| format!("file_{}", uuid::Uuid::new_v4()));
    let file_size = file.size();

    // Determine content type
    let content_type = file
        .content_type()
        .map(|ct| ct.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    // Read file bytes from the temp path
    let file_bytes = tokio::fs::read(file.path())
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read uploaded file: {}", e)))?;

    // Get form fields: owner, tag, provider, application, description
    let owner = req
        .form::<String>("owner")
        .await
        .unwrap_or(user_owner.clone());
    let tag = req.form::<String>("tag").await.unwrap_or_default();
    let application = req.form::<String>("application").await.unwrap_or_default();
    let description = req.form::<String>("description").await.unwrap_or_default();
    let provider_name = req.form::<String>("provider").await;

    // Determine storage provider
    let storage: Box<dyn StorageProvider> = if let Some(ref prov_name) = provider_name {
        // Look up configured storage provider from the database
        match ProviderService::get_by_name_internal(&pool, prov_name).await {
            Ok(prov) => get_storage_provider(
                &prov.provider_type,
                prov.client_id.as_deref().unwrap_or(""),
                prov.client_secret.as_deref().unwrap_or(""),
                prov.region_id.as_deref().unwrap_or(""),
                prov.bucket.as_deref().unwrap_or("./uploads"),
                prov.endpoint.as_deref().unwrap_or(""),
            )?,
            Err(_) => {
                // Fallback to local storage
                get_storage_provider("local", "", "", "", "./uploads", "")?
            }
        }
    } else {
        get_storage_provider("local", "", "", "", "./uploads", "")?
    };

    // Generate a unique object key with extension
    let ext = std::path::Path::new(&file_name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let object_key = format!("{}/{}/{}.{}", owner, tag, uuid::Uuid::new_v4(), ext);

    // Upload to storage provider
    let url = storage
        .upload(&object_key, &file_bytes, &content_type)
        .await?;

    // Create resource record in database
    let resource_req = crate::models::CreateResourceRequest {
        owner: owner.clone(),
        name: file_name.clone(),
        user: user_id,
        provider: provider_name.or_else(|| Some("local".to_string())),
        application: if application.is_empty() {
            None
        } else {
            Some(application)
        },
        tag: if tag.is_empty() { None } else { Some(tag) },
        parent: None,
        file_name: file_name.clone(),
        file_type: content_type.clone(),
        file_format: Some(ext.to_string()),
        file_size: file_size as i64,
        url: url.clone(),
        description: if description.is_empty() {
            None
        } else {
            Some(description)
        },
    };

    ResourceService::create(&pool, resource_req).await?;

    Ok(Json(UploadResponse {
        name: file_name,
        url,
        size: file_size as u64,
        file_type: content_type,
    }))
}

/// Delete a resource and its file from storage.
///
/// Removes both the physical file from the storage provider and the
/// database record for the resource.
#[endpoint(
    tags("Resources"),
    parameters(
        ("id" = String, Path, description = "Resource ID"),
    ),
    responses(
        (status_code = 200, description = "Resource and file deleted successfully"),
        (status_code = 404, description = "Resource not found"),
    )
)]
pub async fn delete_resource_with_file(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::Validation("Resource ID required".to_string()))?;

    // Get resource info to determine storage location
    let resource = ResourceService::get_by_id(&pool, &id).await?;

    // Resolve storage provider for deletion
    let storage: Box<dyn StorageProvider> = if let Some(ref prov_name) = resource.provider {
        match ProviderService::get_by_name_internal(&pool, prov_name).await {
            Ok(prov) => get_storage_provider(
                &prov.provider_type,
                prov.client_id.as_deref().unwrap_or(""),
                prov.client_secret.as_deref().unwrap_or(""),
                prov.region_id.as_deref().unwrap_or(""),
                prov.bucket.as_deref().unwrap_or("./uploads"),
                prov.endpoint.as_deref().unwrap_or(""),
            )
            .unwrap_or_else(|_| {
                Box::new(
                    crate::services::providers::local_storage::LocalStorageProvider::new(
                        "./uploads".to_string(),
                    ),
                )
            }),
            Err(_) => Box::new(
                crate::services::providers::local_storage::LocalStorageProvider::new(
                    "./uploads".to_string(),
                ),
            ),
        }
    } else {
        Box::new(
            crate::services::providers::local_storage::LocalStorageProvider::new(
                "./uploads".to_string(),
            ),
        )
    };

    // Best-effort: try to delete from storage, but always remove the DB record
    let _ = storage.delete(&resource.url).await;

    // Delete resource record from database
    ResourceService::delete(&pool, &id).await?;

    Ok("Resource deleted")
}

/// Download a resource file by ID.
///
/// Looks up the resource record, resolves the storage provider, and streams
/// the file back to the client with the correct Content-Type and
/// Content-Disposition headers.
#[endpoint(
    tags("Resources"),
    parameters(
        ("id" = String, Path, description = "Resource ID"),
    ),
    responses(
        (status_code = 200, description = "File content"),
        (status_code = 404, description = "Resource not found"),
    )
)]
pub async fn download_resource(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    let id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::Validation("Resource ID required".to_string()))?;

    // Look up resource record
    let resource = ResourceService::get_by_id(&pool, &id).await?;

    // Resolve storage provider
    let storage: Box<dyn StorageProvider> = if let Some(ref prov_name) = resource.provider {
        match ProviderService::get_by_name_internal(&pool, prov_name).await {
            Ok(prov) => get_storage_provider(
                &prov.provider_type,
                prov.client_id.as_deref().unwrap_or(""),
                prov.client_secret.as_deref().unwrap_or(""),
                prov.region_id.as_deref().unwrap_or(""),
                prov.bucket.as_deref().unwrap_or("./uploads"),
                prov.endpoint.as_deref().unwrap_or(""),
            )
            .unwrap_or_else(|_| {
                Box::new(
                    crate::services::providers::local_storage::LocalStorageProvider::new(
                        "./uploads".to_string(),
                    ),
                )
            }),
            Err(_) => Box::new(
                crate::services::providers::local_storage::LocalStorageProvider::new(
                    "./uploads".to_string(),
                ),
            ),
        }
    } else {
        Box::new(
            crate::services::providers::local_storage::LocalStorageProvider::new(
                "./uploads".to_string(),
            ),
        )
    };

    // Download file bytes from storage.
    // The `url` field stores the key/path that was used during upload.
    let data = storage.download(&resource.url).await?;

    let content_type = &resource.file_type;
    let filename = &resource.file_name;

    res.headers_mut().insert(
        salvo::http::header::CONTENT_TYPE,
        content_type
            .parse()
            .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
    );
    res.headers_mut().insert(
        salvo::http::header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", filename)
            .parse()
            .unwrap(),
    );
    res.write_body(data).ok();

    Ok(())
}
