use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Ticket {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub ticket_type: Option<String>,
    pub subject: String,
    pub content: Option<String>,
    pub status: String,
    pub priority: String,
    pub assignee: Option<String>,
    pub reporter: Option<String>,
    pub comments: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTicketRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub ticket_type: Option<String>,
    pub subject: String,
    pub content: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assignee: Option<String>,
    pub reporter: Option<String>,
    pub comments: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTicketRequest {
    pub display_name: Option<String>,
    pub ticket_type: Option<String>,
    pub subject: Option<String>,
    pub content: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assignee: Option<String>,
    pub reporter: Option<String>,
    pub comments: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TicketResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub ticket_type: Option<String>,
    pub subject: String,
    pub content: Option<String>,
    pub status: String,
    pub priority: String,
    pub assignee: Option<String>,
    pub reporter: Option<String>,
    pub comments: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Ticket> for TicketResponse {
    fn from(t: Ticket) -> Self {
        Self {
            id: t.id,
            owner: t.owner,
            name: t.name,
            display_name: t.display_name,
            ticket_type: t.ticket_type,
            subject: t.subject,
            content: t.content,
            status: t.status,
            priority: t.priority,
            assignee: t.assignee,
            reporter: t.reporter,
            comments: t.comments,
            tags: t.tags,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TicketListResponse {
    pub data: Vec<TicketResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
