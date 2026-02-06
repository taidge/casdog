use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Full User entity matching Casdoor's user model.
/// Social provider IDs are stored in `provider_ids` JSONB instead of 78 individual columns.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct User {
    pub id: String,
    pub owner: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub password_hash: String,

    // Identity & Authentication
    pub external_id: Option<String>,
    pub user_type: Option<String>,
    pub password_salt: Option<String>,
    pub password_type: Option<String>,
    pub hash: Option<String>,
    pub pre_hash: Option<String>,
    pub register_type: Option<String>,
    pub register_source: Option<String>,
    pub access_key: Option<String>,
    #[serde(skip_serializing)]
    pub access_secret: Option<String>,

    // Profile Information
    pub display_name: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<String>,
    pub avatar_type: Option<String>,
    pub permanent_avatar: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub location: Option<String>,
    pub address: Option<serde_json::Value>,       // JSON array of strings
    pub affiliation: Option<String>,
    pub title: Option<String>,
    pub homepage: Option<String>,
    pub bio: Option<String>,

    // Personal Details
    pub id_card_type: Option<String>,
    pub id_card: Option<String>,
    pub real_name: Option<String>,
    pub is_verified: bool,
    pub tag: Option<String>,
    pub language: Option<String>,
    pub gender: Option<String>,
    pub birthday: Option<String>,
    pub education: Option<String>,
    pub is_default_avatar: bool,
    pub is_online: bool,

    // Gamification & Balance
    pub score: i32,
    pub karma: i32,
    pub ranking: i32,
    pub balance: f64,
    pub balance_credit: f64,
    pub currency: Option<String>,
    pub balance_currency: Option<String>,

    // Status
    pub is_admin: bool,
    pub is_forbidden: bool,
    pub is_deleted: bool,
    pub signup_application: Option<String>,

    // Social Provider IDs (JSONB map: provider_name -> provider_user_id)
    pub provider_ids: Option<serde_json::Value>,

    // Sign-in Tracking
    pub created_ip: Option<String>,
    pub last_signin_time: Option<String>,
    pub last_signin_ip: Option<String>,
    pub last_signin_wrong_time: Option<String>,
    pub signin_wrong_times: i32,

    // MFA
    pub preferred_mfa_type: Option<String>,
    pub mfa_enabled: bool,
    pub mfa_phone_enabled: bool,
    pub mfa_email_enabled: bool,
    pub totp_secret: Option<String>,
    pub recovery_codes: Option<serde_json::Value>, // JSON array of strings

    // Security
    pub last_change_password_time: Option<String>,
    pub need_update_password: bool,
    pub ip_whitelist: Option<String>,

    // Properties & Custom
    pub properties: Option<serde_json::Value>,     // JSON map: key -> value
    pub custom: Option<serde_json::Value>,         // JSON map for custom1-10 fields

    // LDAP
    pub ldap: Option<String>,

    // Invitation
    pub invitation: Option<String>,
    pub invitation_code: Option<String>,

    // Groups (stored as JSON array of group names)
    pub groups: Option<serde_json::Value>,

    // Managed accounts (JSON array of {application, username, password})
    pub managed_accounts: Option<serde_json::Value>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub owner: String,
    pub name: String,
    pub password: Option<String>,
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar: Option<String>,
    pub is_admin: Option<bool>,
    pub user_type: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub location: Option<String>,
    pub affiliation: Option<String>,
    pub tag: Option<String>,
    pub language: Option<String>,
    pub gender: Option<String>,
    pub birthday: Option<String>,
    pub education: Option<String>,
    pub bio: Option<String>,
    pub homepage: Option<String>,
    pub signup_application: Option<String>,
    pub id_card_type: Option<String>,
    pub id_card: Option<String>,
    pub real_name: Option<String>,
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar: Option<String>,
    pub is_admin: Option<bool>,
    pub password: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_type: Option<String>,
    pub permanent_avatar: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub location: Option<String>,
    pub address: Option<serde_json::Value>,
    pub affiliation: Option<String>,
    pub title: Option<String>,
    pub homepage: Option<String>,
    pub bio: Option<String>,
    pub id_card_type: Option<String>,
    pub id_card: Option<String>,
    pub real_name: Option<String>,
    pub tag: Option<String>,
    pub language: Option<String>,
    pub gender: Option<String>,
    pub birthday: Option<String>,
    pub education: Option<String>,
    pub score: Option<i32>,
    pub karma: Option<i32>,
    pub is_forbidden: Option<bool>,
    pub is_verified: Option<bool>,
    pub signup_application: Option<String>,
    pub properties: Option<serde_json::Value>,
    pub custom: Option<serde_json::Value>,
    pub groups: Option<serde_json::Value>,
    pub managed_accounts: Option<serde_json::Value>,
    pub ip_whitelist: Option<String>,
    pub need_update_password: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: String,
    pub owner: String,
    pub name: String,

    // Identity
    pub external_id: Option<String>,
    pub user_type: Option<String>,
    pub register_type: Option<String>,
    pub register_source: Option<String>,

    // Profile
    pub display_name: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<String>,
    pub avatar_type: Option<String>,
    pub permanent_avatar: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub location: Option<String>,
    pub address: Option<serde_json::Value>,
    pub affiliation: Option<String>,
    pub title: Option<String>,
    pub homepage: Option<String>,
    pub bio: Option<String>,

    // Personal
    pub id_card_type: Option<String>,
    pub real_name: Option<String>,
    pub is_verified: bool,
    pub tag: Option<String>,
    pub language: Option<String>,
    pub gender: Option<String>,
    pub birthday: Option<String>,
    pub education: Option<String>,
    pub is_online: bool,

    // Gamification
    pub score: i32,
    pub karma: i32,
    pub ranking: i32,
    pub balance: f64,
    pub currency: Option<String>,

    // Status
    pub is_admin: bool,
    pub is_forbidden: bool,
    pub signup_application: Option<String>,

    // Provider IDs
    pub provider_ids: Option<serde_json::Value>,

    // Signin
    pub created_ip: Option<String>,
    pub last_signin_time: Option<String>,
    pub last_signin_ip: Option<String>,

    // MFA
    pub preferred_mfa_type: Option<String>,
    pub mfa_enabled: bool,
    pub mfa_phone_enabled: bool,
    pub mfa_email_enabled: bool,

    // Properties & Custom
    pub properties: Option<serde_json::Value>,
    pub custom: Option<serde_json::Value>,
    pub groups: Option<serde_json::Value>,

    // Invitation
    pub invitation: Option<String>,
    pub invitation_code: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            owner: u.owner,
            name: u.name,
            external_id: u.external_id,
            user_type: u.user_type,
            register_type: u.register_type,
            register_source: u.register_source,
            display_name: u.display_name,
            first_name: u.first_name,
            last_name: u.last_name,
            avatar: u.avatar,
            avatar_type: u.avatar_type,
            permanent_avatar: u.permanent_avatar,
            email: u.email,
            email_verified: u.email_verified,
            phone: u.phone,
            country_code: u.country_code,
            region: u.region,
            location: u.location,
            address: u.address,
            affiliation: u.affiliation,
            title: u.title,
            homepage: u.homepage,
            bio: u.bio,
            id_card_type: u.id_card_type,
            real_name: u.real_name,
            is_verified: u.is_verified,
            tag: u.tag,
            language: u.language,
            gender: u.gender,
            birthday: u.birthday,
            education: u.education,
            is_online: u.is_online,
            score: u.score,
            karma: u.karma,
            ranking: u.ranking,
            balance: u.balance,
            currency: u.currency,
            is_admin: u.is_admin,
            is_forbidden: u.is_forbidden,
            signup_application: u.signup_application,
            provider_ids: u.provider_ids,
            created_ip: u.created_ip,
            last_signin_time: u.last_signin_time,
            last_signin_ip: u.last_signin_ip,
            preferred_mfa_type: u.preferred_mfa_type,
            mfa_enabled: u.mfa_enabled,
            mfa_phone_enabled: u.mfa_phone_enabled,
            mfa_email_enabled: u.mfa_email_enabled,
            properties: u.properties,
            custom: u.custom,
            groups: u.groups,
            invitation: u.invitation,
            invitation_code: u.invitation_code,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListResponse {
    pub data: Vec<UserResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UserQuery {
    pub owner: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl Default for UserQuery {
    fn default() -> Self {
        Self {
            owner: None,
            page: Some(1),
            page_size: Some(20),
        }
    }
}
