use std::collections::HashMap;

use salvo::oapi::{ToSchema, endpoint};
use salvo::prelude::*;
use serde::Serialize;
use sqlx::{Pool, Postgres};

use crate::error::AppError;
use crate::models::{
    CreateGroupRequest, CreatePermissionRequest, CreateRoleRequest, CreateUserRequest,
};
use crate::services::providers::storage_provider::{StorageProvider, get_storage_provider};
use crate::services::{
    GroupService, PermissionService, ProviderService, ResourceService, RoleService, UserService,
};

#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResponse {
    pub name: String,
    pub url: String,
    pub size: u64,
    pub file_type: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BulkUploadResponse {
    pub total: usize,
    pub created: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

fn normalize_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn split_simple_line(line: &str, delimiter: char) -> Vec<String> {
    line.split(delimiter).map(normalize_value).collect()
}

fn parse_bool(value: Option<&String>) -> Option<bool> {
    value.and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "y" => Some(true),
        "false" | "0" | "no" | "n" => Some(false),
        _ => None,
    })
}

fn parse_records(bytes: &[u8]) -> Result<Vec<HashMap<String, String>>, AppError> {
    let content = String::from_utf8(bytes.to_vec())
        .map_err(|e| AppError::Validation(format!("Uploaded file is not UTF-8 text: {}", e)))?;
    let content = content.trim_start_matches('\u{feff}').trim();
    if content.is_empty() {
        return Ok(Vec::new());
    }

    if content.starts_with('[') {
        let values: Vec<serde_json::Value> = serde_json::from_str(content)
            .map_err(|e| AppError::Validation(format!("Invalid JSON upload content: {}", e)))?;

        let records = values
            .into_iter()
            .map(|value| {
                let mut record = HashMap::new();
                if let Some(object) = value.as_object() {
                    for (key, value) in object {
                        let string_value = value
                            .as_str()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| value.to_string());
                        record.insert(key.clone(), normalize_value(&string_value));
                    }
                }
                record
            })
            .collect();
        return Ok(records);
    }

    let delimiter = if content.lines().next().unwrap_or_default().contains('\t') {
        '\t'
    } else {
        ','
    };
    let mut lines = content.lines().filter(|line| !line.trim().is_empty());
    let headers = lines
        .next()
        .map(|line| split_simple_line(line, delimiter))
        .ok_or_else(|| AppError::Validation("Upload file has no header row".to_string()))?;

    let records = lines
        .map(|line| {
            let values = split_simple_line(line, delimiter);
            let mut record = HashMap::new();
            for (index, header) in headers.iter().enumerate() {
                record.insert(
                    header.clone(),
                    values.get(index).cloned().unwrap_or_default(),
                );
            }
            record
        })
        .collect();
    Ok(records)
}

async fn read_upload_records(req: &mut Request) -> Result<Vec<HashMap<String, String>>, AppError> {
    let file = req
        .file("file")
        .await
        .ok_or_else(|| AppError::Validation("No file provided".to_string()))?;
    let bytes = tokio::fs::read(file.path())
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read uploaded file: {}", e)))?;
    parse_records(&bytes)
}

fn require_field<'a>(record: &'a HashMap<String, String>, key: &str) -> Result<&'a str, AppError> {
    record
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Validation(format!("Missing required field '{}'", key)))
}

fn optional_field(record: &HashMap<String, String>, key: &str) -> Option<String> {
    record.get(key).filter(|value| !value.is_empty()).cloned()
}

async fn require_upload_context(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<(Pool<Postgres>, String), AppError> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let is_admin = depot.get::<bool>("is_admin").copied().unwrap_or(false);
    if !is_admin {
        return Err(AppError::Authentication(
            "Admin privileges required for bulk upload".to_string(),
        ));
    }

    let user_owner = depot
        .get::<String>("user_owner")
        .cloned()
        .unwrap_or_else(|_| "built-in".to_string());
    let owner = req.form::<String>("owner").await.unwrap_or(user_owner);

    Ok((pool, owner))
}

#[endpoint(tags("Resources"), summary = "Upload users")]
pub async fn upload_users(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<BulkUploadResponse>, AppError> {
    let (pool, owner) = require_upload_context(depot, req).await?;
    let records = read_upload_records(req).await?;
    let user_service = UserService::new(pool.clone());

    let mut created = 0usize;
    let mut errors = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let name = match require_field(record, "name") {
            Ok(value) => value,
            Err(err) => {
                errors.push(format!("row {}: {}", index + 2, err));
                continue;
            }
        };

        let request = CreateUserRequest {
            owner: optional_field(record, "owner").unwrap_or_else(|| owner.clone()),
            name: name.to_string(),
            password: optional_field(record, "password"),
            display_name: optional_field(record, "display_name")
                .or_else(|| optional_field(record, "displayName"))
                .unwrap_or_else(|| name.to_string()),
            email: optional_field(record, "email"),
            phone: optional_field(record, "phone"),
            avatar: optional_field(record, "avatar"),
            is_admin: parse_bool(record.get("is_admin"))
                .or_else(|| parse_bool(record.get("isAdmin"))),
            user_type: optional_field(record, "user_type")
                .or_else(|| optional_field(record, "userType")),
            first_name: optional_field(record, "first_name")
                .or_else(|| optional_field(record, "firstName")),
            last_name: optional_field(record, "last_name")
                .or_else(|| optional_field(record, "lastName")),
            country_code: optional_field(record, "country_code")
                .or_else(|| optional_field(record, "countryCode")),
            region: optional_field(record, "region"),
            location: optional_field(record, "location"),
            affiliation: optional_field(record, "affiliation"),
            tag: optional_field(record, "tag"),
            language: optional_field(record, "language"),
            gender: optional_field(record, "gender"),
            birthday: optional_field(record, "birthday"),
            education: optional_field(record, "education"),
            bio: optional_field(record, "bio"),
            homepage: optional_field(record, "homepage"),
            signup_application: optional_field(record, "signup_application")
                .or_else(|| optional_field(record, "signupApplication")),
            id_card_type: optional_field(record, "id_card_type")
                .or_else(|| optional_field(record, "idCardType")),
            id_card: optional_field(record, "id_card").or_else(|| optional_field(record, "idCard")),
            real_name: optional_field(record, "real_name")
                .or_else(|| optional_field(record, "realName")),
            properties: None,
        };

        match user_service.create(request).await {
            Ok(_) => created += 1,
            Err(err) => errors.push(format!("row {}: {}", index + 2, err)),
        }
    }

    Ok(Json(BulkUploadResponse {
        total: records.len(),
        created,
        failed: errors.len(),
        errors,
    }))
}

#[endpoint(tags("Resources"), summary = "Upload groups")]
pub async fn upload_groups(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<BulkUploadResponse>, AppError> {
    let (pool, owner) = require_upload_context(depot, req).await?;
    let records = read_upload_records(req).await?;

    let mut created = 0usize;
    let mut errors = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let name = match require_field(record, "name") {
            Ok(value) => value,
            Err(err) => {
                errors.push(format!("row {}: {}", index + 2, err));
                continue;
            }
        };

        let request = CreateGroupRequest {
            owner: optional_field(record, "owner").unwrap_or_else(|| owner.clone()),
            name: name.to_string(),
            display_name: optional_field(record, "display_name")
                .or_else(|| optional_field(record, "displayName"))
                .unwrap_or_else(|| name.to_string()),
            manager: optional_field(record, "manager"),
            contact_email: optional_field(record, "contact_email")
                .or_else(|| optional_field(record, "contactEmail")),
            group_type: optional_field(record, "type")
                .or_else(|| optional_field(record, "group_type"))
                .or_else(|| optional_field(record, "groupType")),
            parent_id: optional_field(record, "parent_id")
                .or_else(|| optional_field(record, "parentId")),
            is_top_group: parse_bool(record.get("is_top_group"))
                .or_else(|| parse_bool(record.get("isTopGroup"))),
            is_enabled: parse_bool(record.get("is_enabled"))
                .or_else(|| parse_bool(record.get("isEnabled"))),
        };

        match GroupService::create(&pool, request).await {
            Ok(_) => created += 1,
            Err(err) => errors.push(format!("row {}: {}", index + 2, err)),
        }
    }

    Ok(Json(BulkUploadResponse {
        total: records.len(),
        created,
        failed: errors.len(),
        errors,
    }))
}

#[endpoint(tags("Resources"), summary = "Upload roles")]
pub async fn upload_roles(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<BulkUploadResponse>, AppError> {
    let (pool, owner) = require_upload_context(depot, req).await?;
    let records = read_upload_records(req).await?;
    let role_service = RoleService::new(pool);

    let mut created = 0usize;
    let mut errors = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let name = match require_field(record, "name") {
            Ok(value) => value,
            Err(err) => {
                errors.push(format!("row {}: {}", index + 2, err));
                continue;
            }
        };

        let request = CreateRoleRequest {
            owner: optional_field(record, "owner").unwrap_or_else(|| owner.clone()),
            name: name.to_string(),
            display_name: optional_field(record, "display_name")
                .or_else(|| optional_field(record, "displayName"))
                .unwrap_or_else(|| name.to_string()),
            description: optional_field(record, "description"),
            is_enabled: parse_bool(record.get("is_enabled"))
                .or_else(|| parse_bool(record.get("isEnabled"))),
        };

        match role_service.create(request).await {
            Ok(_) => created += 1,
            Err(err) => errors.push(format!("row {}: {}", index + 2, err)),
        }
    }

    Ok(Json(BulkUploadResponse {
        total: records.len(),
        created,
        failed: errors.len(),
        errors,
    }))
}

#[endpoint(tags("Resources"), summary = "Upload permissions")]
pub async fn upload_permissions(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<BulkUploadResponse>, AppError> {
    let (pool, owner) = require_upload_context(depot, req).await?;
    let records = read_upload_records(req).await?;
    let permission_service = PermissionService::new(pool);

    let mut created = 0usize;
    let mut errors = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let name = match require_field(record, "name") {
            Ok(value) => value,
            Err(err) => {
                errors.push(format!("row {}: {}", index + 2, err));
                continue;
            }
        };

        let resources = match require_field(record, "resources") {
            Ok(value) => value,
            Err(err) => {
                errors.push(format!("row {}: {}", index + 2, err));
                continue;
            }
        };
        let actions = match require_field(record, "actions") {
            Ok(value) => value,
            Err(err) => {
                errors.push(format!("row {}: {}", index + 2, err));
                continue;
            }
        };

        let request = CreatePermissionRequest {
            owner: optional_field(record, "owner").unwrap_or_else(|| owner.clone()),
            name: name.to_string(),
            display_name: optional_field(record, "display_name")
                .or_else(|| optional_field(record, "displayName"))
                .unwrap_or_else(|| name.to_string()),
            description: optional_field(record, "description"),
            resource_type: optional_field(record, "resource_type")
                .or_else(|| optional_field(record, "resourceType"))
                .unwrap_or_else(|| "Application".to_string()),
            resources: resources.to_string(),
            actions: actions.to_string(),
            effect: optional_field(record, "effect"),
            is_enabled: parse_bool(record.get("is_enabled"))
                .or_else(|| parse_bool(record.get("isEnabled"))),
        };

        match permission_service.create(request).await {
            Ok(_) => created += 1,
            Err(err) => errors.push(format!("row {}: {}", index + 2, err)),
        }
    }

    Ok(Json(BulkUploadResponse {
        total: records.len(),
        created,
        failed: errors.len(),
        errors,
    }))
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

    // Extract user context set by the JwtAuth hoop
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
