use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};
use crate::models::{CreateProviderRequest, Provider, ProviderResponse, UpdateProviderRequest};
use crate::services::ProviderService;
use crate::services::ldap_service::LdapService;

#[derive(Debug, Deserialize, ToSchema)]
pub struct LdapSyncRequest {
    pub host: String,
    pub port: u16,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub filter: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LdapSyncResponse {
    pub synced_count: usize,
    pub message: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LdapConfigRequest {
    pub id: Option<String>,
    pub owner: String,
    pub name: String,
    pub display_name: Option<String>,
    pub host: String,
    pub port: u16,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub filter: Option<String>,
    pub provider_type: Option<String>,
    pub disable_ssl: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteLdapRequest {
    pub id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LdapConfigResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub display_name: String,
    pub host: String,
    pub port: u16,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub filter: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    pub disable_ssl: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LdapUsersResponse {
    pub users: Vec<crate::services::ldap_service::LdapUser>,
    pub exist_uids: Vec<String>,
}

fn serialize_ldap_metadata(base_dn: &str, filter: Option<&str>) -> Result<String, AppError> {
    serde_json::to_string(&serde_json::json!({
        "base_dn": base_dn,
        "filter": filter.unwrap_or("(objectClass=person)"),
    }))
    .map_err(|e| AppError::Internal(format!("Failed to encode LDAP metadata: {}", e)))
}

fn parse_ldap_metadata(provider: &Provider) -> (String, String) {
    provider
        .metadata
        .as_deref()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
        .map(|metadata| {
            let base_dn = metadata
                .get("base_dn")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            let filter = metadata
                .get("filter")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("(objectClass=person)")
                .to_string();
            (base_dn, filter)
        })
        .unwrap_or_else(|| ("".to_string(), "(objectClass=person)".to_string()))
}

fn mask_secret(secret: Option<&str>) -> String {
    match secret {
        Some(value) if !value.is_empty() => "***".to_string(),
        _ => String::new(),
    }
}

fn ldap_config_response(provider: Provider) -> LdapConfigResponse {
    let (base_dn, filter) = parse_ldap_metadata(&provider);
    LdapConfigResponse {
        id: provider.id,
        owner: provider.owner,
        name: provider.name,
        created_at: provider.created_at,
        updated_at: provider.updated_at,
        display_name: provider.display_name,
        host: provider.host.unwrap_or_default(),
        port: provider.port.unwrap_or(389) as u16,
        bind_dn: provider.client_id.unwrap_or_default(),
        bind_password: mask_secret(provider.client_secret.as_deref()),
        base_dn,
        filter,
        provider_type: provider.provider_type,
        disable_ssl: provider.disable_ssl,
    }
}

async fn get_ldap_provider(pool: &Pool<Postgres>, id: &str) -> AppResult<Provider> {
    let provider = sqlx::query_as::<_, Provider>(
        "SELECT * FROM providers WHERE id = $1 AND category = 'LDAP'",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("LDAP provider '{}' not found", id)))?;

    Ok(provider)
}

/// Sync users from LDAP by explicit connection settings.
#[endpoint(tags("LDAP"), summary = "Sync LDAP users")]
pub async fn sync_ldap_users(
    req: JsonBody<LdapSyncRequest>,
) -> Result<Json<LdapSyncResponse>, AppError> {
    let req = req.into_inner();
    let filter = req.filter.as_deref().unwrap_or("(objectClass=person)");

    let users = LdapService::sync_users(
        &req.host,
        req.port,
        &req.bind_dn,
        &req.bind_password,
        &req.base_dn,
        filter,
    )
    .await?;

    Ok(Json(LdapSyncResponse {
        synced_count: users.len(),
        message: "LDAP sync completed".to_string(),
    }))
}

/// Test LDAP connection
#[endpoint(tags("LDAP"), summary = "Test LDAP connection")]
pub async fn test_ldap_connection(
    req: JsonBody<LdapSyncRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let req = req.into_inner();
    let success =
        LdapService::test_connection(&req.host, req.port, &req.bind_dn, &req.bind_password).await?;

    Ok(Json(serde_json::json!({
        "success": success,
        "message": if success { "Connection successful" } else { "Connection failed" }
    })))
}

/// List LDAP providers in Casdoor-compatible shape.
#[endpoint(tags("LDAP"), summary = "Get LDAP providers")]
pub async fn get_ldaps(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
) -> AppResult<Json<Vec<LdapConfigResponse>>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let providers: Vec<Provider> = if let Some(owner) = owner.as_deref() {
        sqlx::query_as("SELECT * FROM providers WHERE owner = $1 AND category = 'LDAP' ORDER BY created_at DESC")
            .bind(owner)
            .fetch_all(&pool)
            .await?
    } else {
        sqlx::query_as("SELECT * FROM providers WHERE category = 'LDAP' ORDER BY created_at DESC")
            .fetch_all(&pool)
            .await?
    };

    Ok(Json(
        providers.into_iter().map(ldap_config_response).collect(),
    ))
}

/// Get one LDAP provider.
#[endpoint(tags("LDAP"), summary = "Get LDAP provider")]
pub async fn get_ldap(
    depot: &mut Depot,
    id: QueryParam<String, true>,
) -> AppResult<Json<LdapConfigResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let provider = get_ldap_provider(&pool, id.as_str()).await?;
    Ok(Json(ldap_config_response(provider)))
}

/// Create an LDAP provider.
#[endpoint(tags("LDAP"), summary = "Add LDAP provider")]
pub async fn add_ldap(
    depot: &mut Depot,
    body: JsonBody<LdapConfigRequest>,
) -> AppResult<Json<LdapConfigResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let req = body.into_inner();
    let metadata = serialize_ldap_metadata(&req.base_dn, req.filter.as_deref())?;

    let provider = ProviderService::create(
        &pool,
        CreateProviderRequest {
            owner: req.owner,
            name: req.name,
            display_name: req.display_name.unwrap_or_else(|| "LDAP".to_string()),
            category: "LDAP".to_string(),
            provider_type: req.provider_type.unwrap_or_else(|| "LDAP".to_string()),
            sub_type: None,
            method: None,
            client_id: Some(req.bind_dn),
            client_secret: Some(req.bind_password),
            host: Some(req.host),
            port: Some(i32::from(req.port)),
            disable_ssl: req.disable_ssl,
            endpoint: None,
            bucket: None,
            domain: None,
            region_id: None,
            sign_name: None,
            template_code: None,
            app_id: None,
            metadata: Some(metadata),
            issuer_url: None,
            provider_url: None,
        },
    )
    .await?;

    let provider = get_ldap_provider(&pool, &provider.id).await?;
    Ok(Json(ldap_config_response(provider)))
}

/// Update an LDAP provider.
#[endpoint(tags("LDAP"), summary = "Update LDAP provider")]
pub async fn update_ldap(
    depot: &mut Depot,
    body: JsonBody<LdapConfigRequest>,
) -> AppResult<Json<LdapConfigResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let req = body.into_inner();
    let id = req
        .id
        .ok_or_else(|| AppError::Validation("id is required".to_string()))?;
    let metadata = serialize_ldap_metadata(&req.base_dn, req.filter.as_deref())?;

    ProviderService::update(
        &pool,
        &id,
        UpdateProviderRequest {
            display_name: req.display_name,
            category: Some("LDAP".to_string()),
            provider_type: req.provider_type.or(Some("LDAP".to_string())),
            sub_type: None,
            method: None,
            client_id: Some(req.bind_dn),
            client_secret: Some(req.bind_password),
            host: Some(req.host),
            port: Some(i32::from(req.port)),
            disable_ssl: req.disable_ssl,
            endpoint: None,
            bucket: None,
            domain: None,
            region_id: None,
            sign_name: None,
            template_code: None,
            app_id: None,
            metadata: Some(metadata),
            issuer_url: None,
            provider_url: None,
        },
    )
    .await?;

    let provider = get_ldap_provider(&pool, &id).await?;
    Ok(Json(ldap_config_response(provider)))
}

/// Delete an LDAP provider.
#[endpoint(tags("LDAP"), summary = "Delete LDAP provider")]
pub async fn delete_ldap(
    depot: &mut Depot,
    body: JsonBody<DeleteLdapRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let req = body.into_inner();

    let _ = get_ldap_provider(&pool, &req.id).await?;
    ProviderService::delete(&pool, &req.id).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "LDAP provider deleted"
    })))
}

/// Read users from an LDAP provider configuration.
#[endpoint(tags("LDAP"), summary = "Get LDAP users")]
pub async fn get_ldap_users(
    depot: &mut Depot,
    id: QueryParam<String, true>,
) -> AppResult<Json<LdapUsersResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let provider = get_ldap_provider(&pool, id.as_str()).await?;
    let (base_dn, filter) = parse_ldap_metadata(&provider);

    let users = LdapService::sync_users(
        provider.host.as_deref().unwrap_or(""),
        provider.port.unwrap_or(389) as u16,
        provider.client_id.as_deref().unwrap_or(""),
        provider.client_secret.as_deref().unwrap_or(""),
        &base_dn,
        &filter,
    )
    .await?;

    let uids: Vec<String> = users.iter().map(|user| user.uid.clone()).collect();
    let exist_uids = if uids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar::<_, String>(
            r#"
            SELECT name
            FROM users
            WHERE owner = $1 AND is_deleted = FALSE AND (name = ANY($2) OR external_id = ANY($2))
            "#,
        )
        .bind(&provider.owner)
        .bind(&uids)
        .fetch_all(&pool)
        .await?
    };

    Ok(Json(LdapUsersResponse { users, exist_uids }))
}

/// Compatibility alias that returns the public provider shape.
#[endpoint(tags("LDAP"), summary = "Get LDAP provider (raw)")]
pub async fn get_ldap_provider_public(
    depot: &mut Depot,
    id: QueryParam<String, true>,
) -> AppResult<Json<ProviderResponse>> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();
    let provider = get_ldap_provider(&pool, id.as_str()).await?;
    Ok(Json(provider.into()))
}
