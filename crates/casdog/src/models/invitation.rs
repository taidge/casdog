use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Invitation {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub display_name: String,
    pub code: String,
    pub is_regexp: bool,
    pub quota: i32,
    pub used_count: i32,
    pub application: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub signup_group: Option<String>,
    pub default_code: Option<String>,
    pub state: String, // Active, Disabled
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInvitationRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub code: Option<String>, // auto-generate if not provided
    pub is_regexp: Option<bool>,
    pub quota: Option<i32>,
    pub application: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub signup_group: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateInvitationRequest {
    pub display_name: Option<String>,
    pub code: Option<String>,
    pub is_regexp: Option<bool>,
    pub quota: Option<i32>,
    pub application: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub signup_group: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub display_name: String,
    pub code: String,
    pub is_regexp: bool,
    pub quota: i32,
    pub used_count: i32,
    pub application: Option<String>,
    pub signup_group: Option<String>,
    pub state: String,
}

impl From<Invitation> for InvitationResponse {
    fn from(i: Invitation) -> Self {
        Self {
            id: i.id,
            owner: i.owner,
            name: i.name,
            created_at: i.created_at,
            display_name: i.display_name,
            code: i.code,
            is_regexp: i.is_regexp,
            quota: i.quota,
            used_count: i.used_count,
            application: i.application,
            signup_group: i.signup_group,
            state: i.state,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyInvitationRequest {
    pub code: String,
    pub application: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyInvitationResponse {
    pub valid: bool,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendInvitationRequest {
    pub invitation_id: String,
    #[serde(rename = "type")]
    pub send_type: String, // email, sms
    pub receiver: String,
}
