use std::collections::HashMap;

use salvo::oapi::{ToSchema, endpoint};
use salvo::prelude::*;
use serde::Serialize;
use sqlx::{Pool, Postgres};

use crate::diesel_pool::DieselPool;
use crate::error::AppError;
use crate::models::{CreateGroupRequest, CreatePermissionRequest, CreateRoleRequest};
use crate::services::providers::storage_provider::{StorageProvider, get_storage_provider};
use crate::services::{GroupService, PermissionService, ResourceService, RoleService};

#[derive(Debug, Serialize, ToSchema)]
pub struct UploadResponse {
    pub id: String,
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
) -> Result<(DieselPool, Pool<Postgres>, String), AppError> {
    let diesel_pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pg_pool = depot
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

    Ok((diesel_pool, pg_pool, owner))
}

#[endpoint(tags("Resources"), summary = "Upload users")]
pub async fn upload_users(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<BulkUploadResponse>, AppError> {
    upload_users_mode(depot, req, false).await
}
#[endpoint(tags("Resources"), summary = "Restore users from a trusted MFA backup")]
pub async fn upload_users_with_mfa(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<BulkUploadResponse>, AppError> {
    upload_users_mode(depot, req, true).await
}
async fn upload_users_mode(
    depot: &mut Depot,
    req: &mut Request,
    restore: bool,
) -> Result<Json<BulkUploadResponse>, AppError> {
    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    if !principal.admin || principal.is_application() {
        return Err(AppError::Authorization(
            "A real administrator is required for user import".into(),
        ));
    }
    let pg_pool = depot
        .obtain::<Pool<Postgres>>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool not available".into()))?;
    let content_type = req.header::<String>("content-type").unwrap_or_default();
    let (bytes, filename, owner) = if content_type.split(';').next() == Some("application/json") {
        let owner = req.query::<String>("owner");
        let bytes = req
            .payload_with_max_size(crate::services::user_import_service::MAX_UPLOAD)
            .await
            .map_err(|_| AppError::Validation("Invalid upload body".into()))?
            .to_vec();
        (bytes, "users.json".to_owned(), owner)
    } else if content_type.starts_with("multipart/form-data") {
        req.set_secure_max_size(crate::services::user_import_service::MAX_UPLOAD + 64 * 1024);
        let owner = req
            .query::<String>("owner")
            .or(req.form::<String>("owner").await);
        let file = req
            .file("file")
            .await
            .ok_or_else(|| AppError::Validation("No file provided".into()))?;
        if file.size() > crate::services::user_import_service::MAX_UPLOAD as u64 {
            return Err(AppError::Validation("User upload exceeds 8 MiB".into()));
        }
        let name = file.name().unwrap_or("users.csv").to_owned();
        let bytes = tokio::fs::read(file.path())
            .await
            .map_err(|_| AppError::Internal("Could not read uploaded users".into()))?;
        (bytes, name, owner)
    } else {
        return Err(AppError::Validation(
            "Use multipart file upload or application/json".into(),
        ));
    };
    let records = crate::services::user_import_service::parse_upload(&bytes, &filename)?;
    if restore {
        return Ok(Json(
            crate::services::user_import_service::import_users_with_mfa(
                &pg_pool,
                &principal,
                owner.as_deref(),
                records,
            )
            .await?,
        ));
    }
    Ok(Json(
        crate::services::user_import_service::import_users(
            &pg_pool,
            &principal,
            owner.as_deref(),
            records,
        )
        .await?,
    ))
}

#[endpoint(tags("Resources"), summary = "Upload groups")]
pub async fn upload_groups(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<BulkUploadResponse>, AppError> {
    let (_pool, pg_pool, owner) = require_upload_context(depot, req).await?;
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

        match GroupService::create(&pg_pool, request).await {
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
    let (pool, _pg_pool, owner) = require_upload_context(depot, req).await?;
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
    let (pool, _pg_pool, owner) = require_upload_context(depot, req).await?;
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

    // Parse within the upload contract's explicit bound. Salvo's default form
    // limit is 64 KiB, which otherwise rejects valid large transcripts before
    // the per-file 32 MiB check can run. Reserve 64 KiB for multipart fields.
    req.form_data_max_size(32 * 1024 * 1024 + 64 * 1024)
        .await
        .map_err(|_| {
            AppError::Validation("Invalid multipart upload or upload exceeds 32 MiB".into())
        })?;

    // Get the uploaded file from multipart form
    let file = req
        .file("file")
        .await
        .ok_or_else(|| AppError::Validation("No file provided".to_string()))?;

    let file_name = file
        .name()
        .map(|n| n.to_string())
        .unwrap_or_else(|| format!("file_{}", uuid::Uuid::new_v4()));
    if file_name.chars().count() > 255 {
        return Err(AppError::Validation(
            "Filename exceeds 255 characters".into(),
        ));
    }
    let file_size = file.size();
    if file_size > 32 * 1024 * 1024 {
        return Err(AppError::Validation("File exceeds 32 MiB".into()));
    }

    // Determine content type
    let content_type = file
        .content_type()
        .map(|ct| ct.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    if content_type.chars().count() > 100 {
        return Err(AppError::Validation(
            "Content type exceeds 100 characters".into(),
        ));
    }
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
    let provider_name = req
        .form::<String>("provider")
        .await
        .filter(|value| !value.trim().is_empty());

    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    if !principal.global_admin() && owner != principal.owner {
        return Err(AppError::Authorization(
            "Upload owner belongs to another organization".into(),
        ));
    }
    crate::handlers::parity_resources::service::identity(&owner, "resource")?;
    if std::path::Path::new(&tag)
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
        || tag.contains(['\\', ':'])
    {
        return Err(AppError::Validation("Invalid resource tag".into()));
    }
    if tag == "openclawTranscript" {
        let entry = req.form::<String>("entryId").await.ok_or_else(|| {
            AppError::Validation("entryId is required for transcript uploads".into())
        })?;
        let provider = provider_name.as_deref().ok_or_else(|| {
            AppError::Validation("Storage provider is required for transcript uploads".into())
        })?;
        if entry.split_once('/').map(|(entry_owner, _)| entry_owner) != Some(owner.as_str()) {
            return Err(AppError::Validation(
                "Entry owner does not match upload owner".into(),
            ));
        }
        let value = crate::services::protocol_gap_service::upload_transcript(
            &pool,
            &principal,
            &entry,
            provider,
            &file_name,
            &file_bytes,
        )
        .await?;
        let id = value["id"]
            .as_str()
            .ok_or_else(|| AppError::Internal("Uploaded transcript has no resource ID".into()))?
            .to_string();
        let url = value["url"].as_str().unwrap_or_default();
        return Ok(Json(UploadResponse {
            id: id.clone(),
            name: value["name"].as_str().unwrap_or_default().into(),
            url: if url.starts_with("file://") {
                format!("/api/download-resource/{id}")
            } else {
                url.into()
            },
            size: file_size as u64,
            file_type: "application/jsonl".into(),
        }));
    }

    let provider = if let Some(reference) = provider_name.as_deref() {
        let (provider_owner, name) = reference.split_once('/').unwrap_or((&owner, reference));
        if provider_owner != owner {
            return Err(AppError::Authorization(
                "Storage provider belongs to another organization".into(),
            ));
        }
        let provider = sqlx::query_as::<_, crate::models::Provider>(
            "SELECT * FROM providers WHERE owner=$1 AND name=$2 AND category='Storage'",
        )
        .bind(&owner)
        .bind(name)
        .fetch_optional(&pool)
        .await?;
        if provider.is_none() && name != "local" {
            return Err(AppError::NotFound("Storage provider not found".into()));
        }
        provider
    } else {
        None
    };
    let (storage, local_root) = crate::services::protocol_gap_service::storage_for_owner(
        &principal,
        &owner,
        provider.as_ref(),
        true,
    )
    .await?;

    // Generate a unique object key with extension
    let ext = std::path::Path::new(&file_name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let filename = format!("{}.{}", uuid::Uuid::new_v4(), ext);
    let object_key = if tag.is_empty() {
        filename
    } else {
        format!("{tag}/{filename}")
    };
    let object_key =
        crate::services::protocol_gap_service::storage_object_key(provider.as_ref(), &object_key)?;

    if object_key.len() > 1024 || ext.chars().count() > 50 {
        return Err(AppError::Validation(
            "Object key or file extension exceeds storage limits".into(),
        ));
    }
    // Upload to storage provider
    let url = storage
        .upload(&object_key, &file_bytes, &content_type)
        .await?;

    // Create resource record in database
    let resource_req = crate::models::CreateResourceRequest {
        owner: owner.clone(),
        name: object_key.clone(),
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

    let resource = match ResourceService::create(&pool, resource_req).await {
        Ok(resource) => resource,
        Err(error) => {
            let _ = storage.delete(&object_key).await;
            return Err(error);
        }
    };
    let url = if local_root.is_some() {
        format!("/api/download-resource/{}", resource.id)
    } else {
        url
    };

    Ok(Json(UploadResponse {
        id: resource.id,
        name: file_name,
        url,
        size: file_size as u64,
        file_type: content_type,
    }))
}

fn authorize_file(
    principal: &crate::hoops::authz::Principal,
    resource: &crate::models::ResourceResponse,
) -> Result<(), AppError> {
    // New uploads pin the stable UUID. Historical name-only rows require an
    // administrator; a later account reusing that name cannot inherit a file.
    let own = resource.user == principal.id;
    if principal.global_admin() || (principal.owner == resource.owner && (principal.admin || own)) {
        Ok(())
    } else {
        Err(AppError::Authorization(
            "Resource belongs to another account or organization".into(),
        ))
    }
}
fn relative_object_key(key: &str) -> Result<(), AppError> {
    if key.len() > 1024
        || key.is_empty()
        || key.contains(['\\', ':'])
        || std::path::Path::new(key)
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(AppError::Validation("Invalid resource object key".into()));
    }
    Ok(())
}
async fn resource_storage(
    conn: &mut sqlx::PgConnection,
    principal: &crate::hoops::authz::Principal,
    resource: &crate::models::ResourceResponse,
) -> Result<(Box<dyn StorageProvider>, String), AppError> {
    let reference = resource.provider.as_deref().unwrap_or("local");
    let (owner, name) = reference
        .split_once('/')
        .unwrap_or((&resource.owner, reference));
    if owner != resource.owner {
        return Err(AppError::Authorization(
            "Storage provider belongs to another organization".into(),
        ));
    }
    let provider: Option<crate::models::Provider> = sqlx::query_as(
        "SELECT * FROM providers WHERE owner=$1 AND name=$2 AND category='Storage' FOR SHARE",
    )
    .bind(owner)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    if provider.is_none() && name != "local" {
        return Err(AppError::NotFound("Storage provider not found".into()));
    }
    let bucket = provider
        .as_ref()
        .and_then(|provider| provider.bucket.as_deref())
        .unwrap_or("");
    let legacy_default =
        principal.global_admin() && provider.is_none() && resource.name == resource.file_name;
    let (storage, local_root) = if legacy_default {
        let base =
            std::env::var("CASDOG_LOCAL_STORAGE_ROOT").unwrap_or_else(|_| "./uploads".into());
        let root = crate::services::protocol_gap_service::local_storage_root(
            principal,
            &resource.owner,
            Some(&base),
            false,
        )
        .await?;
        let storage = get_storage_provider(
            "local",
            "",
            "",
            "",
            root.to_str()
                .ok_or_else(|| AppError::Config("Storage path must be UTF-8".into()))?,
            "",
        )?;
        (storage, Some(root))
    } else {
        crate::services::protocol_gap_service::storage_for_owner(
            principal,
            &resource.owner,
            provider.as_ref(),
            false,
        )
        .await?
    };
    let mut key = resource.name.clone();
    if let Some(root) = local_root {
        let path = if resource.name == resource.file_name {
            // Older uploads saved the original filename in name and a file://
            // path in url. Resolve only files inside the configured storage root.
            let legacy = resource.url.strip_prefix("file://").ok_or_else(|| {
                AppError::Validation("Legacy resource has no local object reference".into())
            })?;
            std::path::PathBuf::from(legacy)
        } else {
            relative_object_key(&key)?;
            root.join(&key)
        };
        let parent = path
            .parent()
            .ok_or_else(|| AppError::Validation("Invalid local object reference".into()))?;
        let parent = tokio::fs::canonicalize(parent)
            .await
            .map_err(|_| AppError::NotFound("Resource object directory unavailable".into()))?;
        if !parent.starts_with(&root) {
            return Err(AppError::Authorization(
                "Resource path escapes storage root".into(),
            ));
        }
        let filename = path
            .file_name()
            .ok_or_else(|| AppError::Validation("Invalid local object name".into()))?;
        let candidate = parent.join(filename);
        if let Ok(resolved) = tokio::fs::canonicalize(&candidate).await {
            if !resolved.starts_with(&root) {
                return Err(AppError::Authorization(
                    "Resource path escapes storage root".into(),
                ));
            }
        }
        key = candidate
            .strip_prefix(&root)
            .map_err(|_| AppError::Authorization("Resource path escapes storage root".into()))?
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
    } else if resource.name == resource.file_name {
        // Existing S3 uploads stored a URL, not an object key. Strip only the
        // configured bucket's exact URL prefix, without making requests to it.
        let provider = provider
            .as_ref()
            .ok_or_else(|| AppError::NotFound("Storage provider missing".into()))?;
        let endpoint = provider.endpoint.as_deref().unwrap_or("");
        let cloud = provider.provider_type.eq_ignore_ascii_case("Azure Blob")
            || provider
                .provider_type
                .eq_ignore_ascii_case("Google Cloud Storage");
        if cloud {
            let (public, _) = crate::services::providers::cloud_public_configuration(provider)?;
            let base = if public.is_empty() {
                if let Some(api) =
                    crate::services::protocol_gap_service::storage_api_endpoint(provider)?
                {
                    api
                } else if provider.provider_type.eq_ignore_ascii_case("Azure Blob") {
                    format!(
                        "https://{}.blob.core.windows.net",
                        provider.client_id.as_deref().unwrap_or("")
                    )
                } else {
                    "https://storage.googleapis.com".into()
                }
            } else {
                public
            };
            let base = reqwest::Url::parse(&format!("{}/{}/", base.trim_end_matches('/'), bucket))
                .map_err(|_| AppError::Validation("Invalid legacy cloud URL base".into()))?;
            let url = reqwest::Url::parse(&resource.url)
                .map_err(|_| AppError::Validation("Invalid legacy cloud object URL".into()))?;
            if url.origin() != base.origin()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(AppError::Validation(
                    "Legacy URL does not match storage provider".into(),
                ));
            }
            key = urlencoding::decode(url.path().strip_prefix(base.path()).ok_or_else(|| {
                AppError::Validation("Legacy URL does not match storage bucket".into())
            })?)
            .map_err(|_| AppError::Validation("Invalid legacy cloud object key".into()))?
            .into_owned();
            relative_object_key(&key)?;
            return Ok((storage, key));
        }
        let base = if endpoint.is_empty() {
            format!(
                "https://{}.s3.{}.amazonaws.com",
                bucket,
                provider.region_id.as_deref().unwrap_or("")
            )
        } else {
            format!("{}/{}", endpoint.trim_end_matches('/'), bucket)
        };
        key = urlencoding::decode(resource.url.strip_prefix(&format!("{base}/")).ok_or_else(
            || AppError::Validation("Legacy URL does not match storage provider".into()),
        )?)
        .map_err(|_| AppError::Validation("Invalid legacy object URL".into()))?
        .into_owned();
    }
    relative_object_key(&key)?;
    Ok((storage, key))
}

/// Refresh an authorized resource's temporary cloud URL. Other providers use
/// the authenticated application download proxy rather than assuming a bucket
/// is public or returning a local filesystem path.
#[endpoint(tags("Resources"), summary = "Refresh resource access URL")]
pub async fn resource_url(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> Result<(), AppError> {
    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    res.headers_mut().insert(
        salvo::http::header::PRAGMA,
        "no-cache".parse().expect("static header"),
    );
    let pool = depot
        .obtain::<sqlx::PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    let id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::Validation("Resource ID required".into()))?;
    let mut tx = pool.begin().await?;
    let resource: crate::models::Resource = sqlx::query_as(
        "SELECT resources.*,user_id AS \"user\" FROM resources WHERE id=$1 FOR SHARE",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("Resource not found".into()))?;
    let resource: crate::models::ResourceResponse = resource.into();
    authorize_file(&principal, &resource)?;
    let (storage, key) = resource_storage(&mut tx, &principal, &resource).await?;
    let reference = resource.provider.as_deref().unwrap_or("local");
    let (owner, name) = reference
        .split_once('/')
        .unwrap_or((&resource.owner, reference));
    let provider: Option<crate::models::Provider> = sqlx::query_as(
        "SELECT * FROM providers WHERE owner=$1 AND name=$2 AND category='Storage' FOR SHARE",
    )
    .bind(owner)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    let cloud = provider.as_ref().is_some_and(|p| {
        p.provider_type.eq_ignore_ascii_case("Azure Blob")
            || p.provider_type.eq_ignore_ascii_case("Google Cloud Storage")
    });
    let (url, access, expires_at) = if cloud {
        let (public, _) = crate::services::providers::cloud_public_configuration(
            provider.as_ref().expect("cloud provider"),
        )?;
        let signed = public.is_empty();
        (
            storage.get_url(&key).await?,
            if signed { "signed" } else { "public" },
            signed.then(|| chrono::Utc::now() + chrono::Duration::minutes(15)),
        )
    } else {
        (format!("/api/download-resource/{id}"), "proxy", None)
    };
    tx.commit().await?;
    res.render(Json(
        serde_json::json!({"url":url,"access":access,"expires_at":expires_at}),
    ));
    Ok(())
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
        .obtain::<sqlx::PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    let id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::Validation("Resource ID required".into()))?;
    let mut tx = pool.begin().await?;
    let resource: crate::models::Resource = sqlx::query_as(
        "SELECT resources.*,user_id AS \"user\" FROM resources WHERE id=$1 FOR UPDATE",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("Resource not found".into()))?;
    let resource: crate::models::ResourceResponse = resource.into();
    authorize_file(&principal, &resource)?;
    // The provider lookup uses the current transaction so a one-slot pool works.
    // Release no resource lock before the corresponding object is removed.
    let (storage, key) = resource_storage(&mut tx, &principal, &resource).await?;
    match tokio::time::timeout(std::time::Duration::from_secs(30), storage.delete(&key))
        .await
        .map_err(|_| AppError::Internal("Storage delete timed out".into()))?
    {
        Ok(()) | Err(AppError::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    sqlx::query("DELETE FROM resources WHERE id=$1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
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
        .obtain::<sqlx::PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    let id = req
        .param::<String>("id")
        .ok_or_else(|| AppError::Validation("Resource ID required".into()))?;
    let resource = ResourceService::get_by_id(&pool, &id).await?;
    authorize_file(&principal, &resource)?;
    let mut conn = pool.acquire().await?;
    let (storage, key) = resource_storage(&mut conn, &principal, &resource).await?;
    drop(conn);
    let data = tokio::time::timeout(std::time::Duration::from_secs(30), storage.download(&key))
        .await
        .map_err(|_| AppError::Internal("Storage download timed out".into()))??;
    res.headers_mut().insert(
        salvo::http::header::CONTENT_TYPE,
        resource
            .file_type
            .parse()
            .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
    );
    res.headers_mut().insert(
        salvo::http::header::CONTENT_DISPOSITION,
        format!(
            "attachment; filename*=UTF-8''{}",
            urlencoding::encode(&resource.file_name)
        )
        .parse()
        .map_err(|_| AppError::Validation("Invalid filename".into()))?,
    );
    res.write_body(data)
        .map_err(|_| AppError::Internal("Cannot write download response".into()))?;
    Ok(())
}
