use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Syncer {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub organization: String,
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub syncer_type: String, // Database, LDAP, Keycloak, etc.
    pub database_type: Option<String>, // postgres, mysql
    pub ssl_mode: Option<String>,
    pub host: String,
    pub port: i32,
    pub user: String,
    pub password: String,
    pub database: Option<String>,
    #[sqlx(rename = "table")]
    #[serde(rename = "table")]
    pub table_name: Option<String>,
    pub table_columns: Option<String>, // JSON array
    pub affiliation_table: Option<String>,
    pub avatar_base_url: Option<String>,
    pub error_text: Option<String>,
    pub sync_interval: i32, // in minutes
    pub is_read_only: bool,
    pub is_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TableColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
    pub casdoor_name: String,
    pub is_key: bool,
    pub is_hashed: bool,
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSyncerRequest {
    pub owner: String,
    pub name: String,
    pub organization: String,
    #[serde(rename = "type")]
    pub syncer_type: String,
    pub database_type: Option<String>,
    pub host: String,
    pub port: i32,
    pub user: String,
    pub password: String,
    pub database: Option<String>,
    #[serde(rename = "table")]
    pub table_name: Option<String>,
    pub table_columns: Option<Vec<TableColumn>>,
    pub sync_interval: Option<i32>,
    pub is_read_only: Option<bool>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSyncerRequest {
    pub organization: Option<String>,
    #[serde(rename = "type")]
    pub syncer_type: Option<String>,
    pub database_type: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub database: Option<String>,
    #[serde(rename = "table")]
    pub table_name: Option<String>,
    pub table_columns: Option<Vec<TableColumn>>,
    pub sync_interval: Option<i32>,
    pub is_read_only: Option<bool>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncerResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub organization: String,
    #[serde(rename = "type")]
    pub syncer_type: String,
    pub database_type: Option<String>,
    pub host: String,
    pub port: i32,
    pub user: String,
    pub database: Option<String>,
    #[serde(rename = "table")]
    pub table_name: Option<String>,
    pub sync_interval: i32,
    pub is_read_only: bool,
    pub is_enabled: bool,
    pub error_text: Option<String>,
}

impl From<Syncer> for SyncerResponse {
    fn from(s: Syncer) -> Self {
        Self {
            id: s.id,
            owner: s.owner,
            name: s.name,
            created_at: s.created_at,
            organization: s.organization,
            syncer_type: s.syncer_type,
            database_type: s.database_type,
            host: s.host,
            port: s.port,
            user: s.user,
            database: s.database,
            table_name: s.table_name,
            sync_interval: s.sync_interval,
            is_read_only: s.is_read_only,
            is_enabled: s.is_enabled,
            error_text: s.error_text,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TestSyncerDbRequest {
    #[serde(rename = "type")]
    pub syncer_type: String,
    pub database_type: Option<String>,
    pub host: String,
    pub port: i32,
    pub user: String,
    pub password: String,
    pub database: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TestSyncerDbResponse {
    pub success: bool,
    pub message: String,
}
