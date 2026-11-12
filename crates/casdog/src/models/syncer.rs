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
    #[serde(alias = "databaseType")]
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
    #[serde(alias = "tableColumns")]
    pub table_columns: Option<String>, // JSON array
    pub affiliation_table: Option<String>,
    pub avatar_base_url: Option<String>,
    pub error_text: Option<String>,
    #[serde(alias = "syncInterval")]
    pub sync_interval: i32, // in minutes
    #[serde(alias = "isReadOnly")]
    pub is_read_only: bool,
    #[serde(alias = "isEnabled")]
    pub is_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TableColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
    #[serde(alias = "casdoorName")]
    pub casdoor_name: String,
    #[serde(default, alias = "isKey")]
    pub is_key: bool,
    #[serde(default, alias = "isHashed")]
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
    #[serde(alias = "databaseType")]
    pub database_type: Option<String>,
    #[serde(alias = "sslMode")]
    pub ssl_mode: Option<String>,
    pub host: String,
    pub port: i32,
    pub user: String,
    pub password: String,
    pub database: Option<String>,
    #[serde(rename = "table")]
    pub table_name: Option<String>,
    #[serde(alias = "tableColumns")]
    pub table_columns: Option<Vec<TableColumn>>,
    #[serde(alias = "affiliationTable")]
    pub affiliation_table: Option<String>,
    #[serde(alias = "avatarBaseUrl")]
    pub avatar_base_url: Option<String>,
    #[serde(alias = "syncInterval")]
    pub sync_interval: Option<i32>,
    #[serde(alias = "isReadOnly")]
    pub is_read_only: Option<bool>,
    #[serde(alias = "isEnabled")]
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSyncerRequest {
    pub organization: Option<String>,
    #[serde(rename = "type")]
    pub syncer_type: Option<String>,
    #[serde(alias = "databaseType")]
    pub database_type: Option<String>,
    #[serde(alias = "sslMode")]
    pub ssl_mode: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub database: Option<String>,
    #[serde(rename = "table")]
    pub table_name: Option<String>,
    #[serde(alias = "tableColumns")]
    pub table_columns: Option<Vec<TableColumn>>,
    #[serde(alias = "affiliationTable")]
    pub affiliation_table: Option<String>,
    #[serde(alias = "avatarBaseUrl")]
    pub avatar_base_url: Option<String>,
    #[serde(alias = "syncInterval")]
    pub sync_interval: Option<i32>,
    #[serde(alias = "isReadOnly")]
    pub is_read_only: Option<bool>,
    #[serde(alias = "isEnabled")]
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
    #[serde(alias = "databaseType")]
    pub database_type: Option<String>,
    pub ssl_mode: Option<String>,
    pub host: String,
    pub port: i32,
    pub user: String,
    pub database: Option<String>,
    #[serde(rename = "table")]
    pub table_name: Option<String>,
    #[serde(alias = "tableColumns")]
    pub table_columns: Option<Vec<TableColumn>>,
    pub affiliation_table: Option<String>,
    pub avatar_base_url: Option<String>,
    pub password: String,
    #[serde(alias = "syncInterval")]
    pub sync_interval: i32,
    #[serde(alias = "isReadOnly")]
    pub is_read_only: bool,
    #[serde(alias = "isEnabled")]
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
            syncer_type: s.syncer_type.clone(),
            database_type: s.database_type,
            ssl_mode: s.ssl_mode,
            host: s.host,
            port: s.port,
            user: if s.syncer_type == "SCIM" && s.password.is_empty() && !s.user.is_empty() {
                "***".into()
            } else {
                s.user
            },
            database: s.database,
            table_name: s.table_name,
            table_columns: s
                .table_columns
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok()),
            affiliation_table: s.affiliation_table,
            avatar_base_url: s.avatar_base_url,
            password: if s.password.is_empty() {
                String::new()
            } else {
                "***".into()
            },
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
    #[serde(alias = "databaseType")]
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
