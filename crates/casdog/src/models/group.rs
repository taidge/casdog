use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Group {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub display_name: String,
    pub manager: Option<String>,
    pub contact_email: Option<String>,
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub group_type: Option<String>,
    pub parent_id: Option<String>,
    pub is_top_group: bool,
    pub is_enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub manager: Option<String>,
    pub contact_email: Option<String>,
    #[serde(rename = "type")]
    pub group_type: Option<String>,
    pub parent_id: Option<String>,
    pub is_top_group: Option<bool>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateGroupRequest {
    pub display_name: Option<String>,
    pub manager: Option<String>,
    pub contact_email: Option<String>,
    #[serde(rename = "type")]
    pub group_type: Option<String>,
    pub parent_id: Option<String>,
    pub is_top_group: Option<bool>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub display_name: String,
    pub manager: Option<String>,
    pub contact_email: Option<String>,
    #[serde(rename = "type")]
    pub group_type: Option<String>,
    pub parent_id: Option<String>,
    pub is_top_group: bool,
    pub is_enabled: bool,
}

impl From<Group> for GroupResponse {
    fn from(g: Group) -> Self {
        Self {
            id: g.id,
            owner: g.owner,
            name: g.name,
            created_at: g.created_at,
            updated_at: g.updated_at,
            display_name: g.display_name,
            manager: g.manager,
            contact_email: g.contact_email,
            group_type: g.group_type,
            parent_id: g.parent_id,
            is_top_group: g.is_top_group,
            is_enabled: g.is_enabled,
        }
    }
}

// User-Group relationship
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct UserGroup {
    pub id: String,
    pub user_id: String,
    pub group_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddUserToGroupRequest {
    pub user_id: String,
    pub group_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RemoveUserFromGroupRequest {
    pub user_id: String,
    pub group_id: String,
}
