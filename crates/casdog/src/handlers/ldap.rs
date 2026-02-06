use crate::error::AppError;
use crate::services::ldap_service::LdapService;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

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

/// Get LDAP users
#[endpoint(
    tags("LDAP"),
    summary = "Sync LDAP users"
)]
pub async fn sync_ldap_users(
    req: salvo::oapi::extract::JsonBody<LdapSyncRequest>,
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
    ).await?;

    Ok(Json(LdapSyncResponse {
        synced_count: users.len(),
        message: "LDAP sync completed".to_string(),
    }))
}

/// Test LDAP connection
#[endpoint(
    tags("LDAP"),
    summary = "Test LDAP connection"
)]
pub async fn test_ldap_connection(
    req: salvo::oapi::extract::JsonBody<LdapSyncRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let req = req.into_inner();
    let success = LdapService::test_connection(
        &req.host,
        req.port,
        &req.bind_dn,
        &req.bind_password,
    ).await?;

    Ok(Json(serde_json::json!({
        "success": success,
        "message": if success { "Connection successful" } else { "Connection failed" }
    })))
}
