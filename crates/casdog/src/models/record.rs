use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Record {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub organization: Option<String>,
    pub client_ip: Option<String>,
    pub user: Option<String>,
    pub method: String,
    pub request_uri: String,
    pub action: String,
    pub object: Option<String>,
    pub is_triggered: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRecordRequest {
    pub owner: String,
    pub name: String,
    pub organization: Option<String>,
    pub client_ip: Option<String>,
    pub user: Option<String>,
    pub method: String,
    pub request_uri: String,
    pub action: String,
    pub object: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRecordRequest {
    pub owner: String,
    pub name: String,
    pub organization: Option<String>,
    pub client_ip: Option<String>,
    pub user: Option<String>,
    pub method: String,
    pub request_uri: String,
    pub action: String,
    pub object: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecordResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub organization: Option<String>,
    pub client_ip: Option<String>,
    pub user: Option<String>,
    pub method: String,
    pub request_uri: String,
    pub action: String,
    pub object: Option<String>,
}

impl From<Record> for RecordResponse {
    fn from(r: Record) -> Self {
        Self {
            id: r.id,
            owner: r.owner,
            name: r.name,
            created_at: r.created_at,
            organization: r.organization,
            client_ip: r.client_ip,
            user: r.user,
            method: r.method,
            request_uri: r.request_uri,
            action: r.action,
            object: r.object,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecordFilterRequest {
    pub organization: Option<String>,
    pub user: Option<String>,
    pub action: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
}
