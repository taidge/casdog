use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(
    Debug, Clone, Serialize, Deserialize, FromRow, ToSchema, diesel::Queryable, diesel::Selectable,
)]
#[diesel(table_name = crate::schema::sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Session {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub application: String,
    pub created_at: DateTime<Utc>,
    pub user_id: String,
    pub session_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    pub owner: String,
    pub name: String,
    pub application: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSessionRequest {
    pub application: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub application: String,
    pub created_at: DateTime<Utc>,
    pub user_id: String,
    pub session_id: String,
}

impl From<Session> for SessionResponse {
    fn from(s: Session) -> Self {
        Self {
            id: s.id,
            owner: s.owner,
            name: s.name,
            application: s.application,
            created_at: s.created_at,
            user_id: s.user_id,
            session_id: s.session_id,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckSessionDuplicatedRequest {
    pub user_id: String,
    pub session_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionDuplicatedResponse {
    pub is_duplicated: bool,
}
