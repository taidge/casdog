use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(
    Debug, Clone, Serialize, Deserialize, FromRow, ToSchema, diesel::Queryable, diesel::Selectable,
)]
#[diesel(table_name = crate::schema::organizations)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Organization {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,

    // Branding
    pub website_url: Option<String>,
    pub logo: Option<String>,
    pub logo_dark: Option<String>,
    pub favicon: Option<String>,
    pub default_avatar: Option<String>,

    // Password Configuration
    pub password_type: String,
    pub password_salt: Option<String>,
    pub password_options: Option<serde_json::Value>, // JSON array of strings
    pub password_obfuscator_type: Option<String>,
    pub password_obfuscator_key: Option<String>,
    pub password_expire_days: i32,
    pub default_password: Option<String>,

    // Master Credentials
    pub master_password: Option<String>,
    pub master_verification_code: Option<String>,

    // User Configuration
    pub user_types: Option<serde_json::Value>, // JSON array of strings
    pub tags: Option<serde_json::Value>,       // JSON array of strings
    pub country_codes: Option<serde_json::Value>, // JSON array of strings
    pub default_application: Option<String>,
    pub init_score: i32,

    // Localization & Theme
    pub languages: Option<serde_json::Value>, // JSON array of strings
    pub theme_data: Option<serde_json::Value>, // JSON object
    pub account_menu: Option<String>,

    // Features & Behavior
    pub enable_soft_deletion: bool,
    pub is_profile_public: bool,
    pub use_email_as_username: bool,
    pub enable_tour: bool,
    pub disable_signin: bool,
    pub ip_restriction: Option<String>,
    pub ip_whitelist: Option<String>,
    pub has_privilege_consent: bool,

    // Account Items (JSON array of {name, visible, viewAtLogin, modifyRule})
    pub account_items: Option<serde_json::Value>,

    // Navigation
    pub nav_items: Option<serde_json::Value>,
    pub user_nav_items: Option<serde_json::Value>,
    pub widget_items: Option<serde_json::Value>,

    // MFA
    pub mfa_items: Option<serde_json::Value>, // JSON array of {name, rule}
    pub mfa_remember_in_hours: i32,

    // Financial
    pub org_balance: f64,
    pub user_balance: f64,
    pub balance_credit: f64,
    pub balance_currency: Option<String>,

    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOrganizationRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub website_url: Option<String>,
    pub logo: Option<String>,
    pub logo_dark: Option<String>,
    pub favicon: Option<String>,
    pub password_type: Option<String>,
    pub default_avatar: Option<String>,
    pub default_application: Option<String>,
    pub country_codes: Option<serde_json::Value>,
    pub languages: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
    pub init_score: Option<i32>,
    pub password_options: Option<serde_json::Value>,
    pub password_expire_days: Option<i32>,
    pub default_password: Option<String>,
    pub account_items: Option<serde_json::Value>,
    pub mfa_items: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOrganizationRequest {
    pub display_name: Option<String>,
    pub website_url: Option<String>,
    pub logo: Option<String>,
    pub logo_dark: Option<String>,
    pub favicon: Option<String>,
    pub password_type: Option<String>,
    pub default_avatar: Option<String>,
    pub password_salt: Option<String>,
    pub password_options: Option<serde_json::Value>,
    pub password_obfuscator_type: Option<String>,
    pub password_obfuscator_key: Option<String>,
    pub password_expire_days: Option<i32>,
    pub default_password: Option<String>,
    pub master_password: Option<String>,
    pub user_types: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
    pub country_codes: Option<serde_json::Value>,
    pub default_application: Option<String>,
    pub init_score: Option<i32>,
    pub languages: Option<serde_json::Value>,
    pub theme_data: Option<serde_json::Value>,
    pub account_menu: Option<String>,
    pub enable_soft_deletion: Option<bool>,
    pub is_profile_public: Option<bool>,
    pub use_email_as_username: Option<bool>,
    pub enable_tour: Option<bool>,
    pub disable_signin: Option<bool>,
    pub ip_restriction: Option<String>,
    pub ip_whitelist: Option<String>,
    pub has_privilege_consent: Option<bool>,
    pub account_items: Option<serde_json::Value>,
    pub nav_items: Option<serde_json::Value>,
    pub mfa_items: Option<serde_json::Value>,
    pub mfa_remember_in_hours: Option<i32>,
    pub balance_currency: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub website_url: Option<String>,
    pub logo: Option<String>,
    pub logo_dark: Option<String>,
    pub favicon: Option<String>,
    pub default_avatar: Option<String>,
    pub password_type: String,
    pub password_options: Option<serde_json::Value>,
    pub password_expire_days: i32,
    pub default_password: Option<String>,
    pub user_types: Option<serde_json::Value>,
    pub tags: Option<serde_json::Value>,
    pub country_codes: Option<serde_json::Value>,
    pub default_application: Option<String>,
    pub init_score: i32,
    pub languages: Option<serde_json::Value>,
    pub theme_data: Option<serde_json::Value>,
    pub account_menu: Option<String>,
    pub enable_soft_deletion: bool,
    pub is_profile_public: bool,
    pub use_email_as_username: bool,
    pub enable_tour: bool,
    pub disable_signin: bool,
    pub ip_restriction: Option<String>,
    pub ip_whitelist: Option<String>,
    pub has_privilege_consent: bool,
    pub account_items: Option<serde_json::Value>,
    pub nav_items: Option<serde_json::Value>,
    pub mfa_items: Option<serde_json::Value>,
    pub mfa_remember_in_hours: i32,
    pub org_balance: f64,
    pub balance_currency: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Organization> for OrganizationResponse {
    fn from(o: Organization) -> Self {
        Self {
            id: o.id,
            owner: o.owner,
            name: o.name,
            display_name: o.display_name,
            website_url: o.website_url,
            logo: o.logo,
            logo_dark: o.logo_dark,
            favicon: o.favicon,
            default_avatar: o.default_avatar,
            password_type: o.password_type,
            password_options: o.password_options,
            password_expire_days: o.password_expire_days,
            default_password: o.default_password,
            user_types: o.user_types,
            tags: o.tags,
            country_codes: o.country_codes,
            default_application: o.default_application,
            init_score: o.init_score,
            languages: o.languages,
            theme_data: o.theme_data,
            account_menu: o.account_menu,
            enable_soft_deletion: o.enable_soft_deletion,
            is_profile_public: o.is_profile_public,
            use_email_as_username: o.use_email_as_username,
            enable_tour: o.enable_tour,
            disable_signin: o.disable_signin,
            ip_restriction: o.ip_restriction,
            ip_whitelist: o.ip_whitelist,
            has_privilege_consent: o.has_privilege_consent,
            account_items: o.account_items,
            nav_items: o.nav_items,
            mfa_items: o.mfa_items,
            mfa_remember_in_hours: o.mfa_remember_in_hours,
            org_balance: o.org_balance,
            balance_currency: o.balance_currency,
            created_at: o.created_at,
            updated_at: o.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationListResponse {
    pub data: Vec<OrganizationResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct OrganizationQuery {
    pub owner: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl Default for OrganizationQuery {
    fn default() -> Self {
        Self {
            owner: None,
            page: Some(1),
            page_size: Some(20),
        }
    }
}
