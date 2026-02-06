use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Application {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub logo: Option<String>,
    pub homepage_url: Option<String>,
    pub description: Option<String>,
    pub organization: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: String,
    pub token_format: String,
    pub expire_in_hours: i32,
    pub refresh_expire_in_hours: i32,
    pub cert: Option<String>,

    // Sign-up configuration
    pub signup_url: Option<String>,
    pub signin_url: Option<String>,
    pub forget_url: Option<String>,
    pub terms_of_use: Option<String>,
    pub signup_html: Option<String>,
    pub signin_html: Option<String>,

    // Items configuration (JSON arrays)
    pub signup_items: Option<serde_json::Value>, // [{name, visible, required, prompted, rule}]
    pub signin_items: Option<serde_json::Value>,
    pub signin_methods: Option<serde_json::Value>, // [{name, displayName, rule}]
    pub grant_types: Option<serde_json::Value>,    // ["authorization_code", "implicit", ...]

    // Providers (JSON array of {name, canSignUp, canSignIn, canUnlink, prompted, ...})
    pub providers: Option<serde_json::Value>,

    // SAML
    pub saml_reply_url: Option<String>,

    // Features
    pub enable_password: bool,
    pub enable_signin_session: bool,
    pub enable_auto_signin: bool,
    pub enable_code_signin: bool,
    pub enable_saml_compress: bool,
    pub enable_saml_c14n10: bool,
    pub enable_web_authn: bool,
    pub enable_link_with_email: bool,
    pub enable_internal_signup: bool,
    pub enable_idp_signup: bool,

    // Form offset for sign-up page
    pub form_offset: i32,
    pub form_side_html: Option<String>,
    pub form_background_url: Option<String>,
    pub form_css: Option<String>,
    pub form_css_mobile: Option<String>,

    // Tags
    pub tags: Option<serde_json::Value>,

    // Invitation
    pub invitation_codes: Option<serde_json::Value>,
    pub default_code_expire_minutes: i32,

    // Footer
    pub footer_text: Option<String>,

    // Logout
    pub logout_url: Option<String>,
    pub logout_redirect_uris: Option<String>,

    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApplicationRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub logo: Option<String>,
    pub homepage_url: Option<String>,
    pub description: Option<String>,
    pub organization: String,
    pub redirect_uris: Option<String>,
    pub token_format: Option<String>,
    pub expire_in_hours: Option<i32>,
    pub cert: Option<String>,
    pub signup_items: Option<serde_json::Value>,
    pub signin_items: Option<serde_json::Value>,
    pub signin_methods: Option<serde_json::Value>,
    pub grant_types: Option<serde_json::Value>,
    pub providers: Option<serde_json::Value>,
    pub enable_password: Option<bool>,
    pub enable_signin_session: Option<bool>,
    pub enable_code_signin: Option<bool>,
    pub enable_web_authn: Option<bool>,
    pub enable_internal_signup: Option<bool>,
    pub enable_idp_signup: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateApplicationRequest {
    pub display_name: Option<String>,
    pub logo: Option<String>,
    pub homepage_url: Option<String>,
    pub description: Option<String>,
    pub redirect_uris: Option<String>,
    pub token_format: Option<String>,
    pub expire_in_hours: Option<i32>,
    pub refresh_expire_in_hours: Option<i32>,
    pub cert: Option<String>,
    pub signup_url: Option<String>,
    pub signin_url: Option<String>,
    pub forget_url: Option<String>,
    pub terms_of_use: Option<String>,
    pub signup_html: Option<String>,
    pub signin_html: Option<String>,
    pub signup_items: Option<serde_json::Value>,
    pub signin_items: Option<serde_json::Value>,
    pub signin_methods: Option<serde_json::Value>,
    pub grant_types: Option<serde_json::Value>,
    pub providers: Option<serde_json::Value>,
    pub saml_reply_url: Option<String>,
    pub enable_password: Option<bool>,
    pub enable_signin_session: Option<bool>,
    pub enable_auto_signin: Option<bool>,
    pub enable_code_signin: Option<bool>,
    pub enable_saml_compress: Option<bool>,
    pub enable_web_authn: Option<bool>,
    pub enable_link_with_email: Option<bool>,
    pub enable_internal_signup: Option<bool>,
    pub enable_idp_signup: Option<bool>,
    pub form_offset: Option<i32>,
    pub form_side_html: Option<String>,
    pub form_background_url: Option<String>,
    pub form_css: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub footer_text: Option<String>,
    pub logout_url: Option<String>,
    pub logout_redirect_uris: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub logo: Option<String>,
    pub homepage_url: Option<String>,
    pub description: Option<String>,
    pub organization: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: String,
    pub token_format: String,
    pub expire_in_hours: i32,
    pub refresh_expire_in_hours: i32,
    pub cert: Option<String>,
    pub signup_url: Option<String>,
    pub signin_url: Option<String>,
    pub forget_url: Option<String>,
    pub terms_of_use: Option<String>,
    pub signup_items: Option<serde_json::Value>,
    pub signin_items: Option<serde_json::Value>,
    pub signin_methods: Option<serde_json::Value>,
    pub grant_types: Option<serde_json::Value>,
    pub providers: Option<serde_json::Value>,
    pub saml_reply_url: Option<String>,
    pub enable_password: bool,
    pub enable_signin_session: bool,
    pub enable_auto_signin: bool,
    pub enable_code_signin: bool,
    pub enable_saml_compress: bool,
    pub enable_web_authn: bool,
    pub enable_link_with_email: bool,
    pub enable_internal_signup: bool,
    pub enable_idp_signup: bool,
    pub form_offset: i32,
    pub form_background_url: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub footer_text: Option<String>,
    pub logout_url: Option<String>,
    pub logout_redirect_uris: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Application> for ApplicationResponse {
    fn from(a: Application) -> Self {
        Self {
            id: a.id,
            owner: a.owner,
            name: a.name,
            display_name: a.display_name,
            logo: a.logo,
            homepage_url: a.homepage_url,
            description: a.description,
            organization: a.organization,
            client_id: a.client_id,
            client_secret: a.client_secret,
            redirect_uris: a.redirect_uris,
            token_format: a.token_format,
            expire_in_hours: a.expire_in_hours,
            refresh_expire_in_hours: a.refresh_expire_in_hours,
            cert: a.cert,
            signup_url: a.signup_url,
            signin_url: a.signin_url,
            forget_url: a.forget_url,
            terms_of_use: a.terms_of_use,
            signup_items: a.signup_items,
            signin_items: a.signin_items,
            signin_methods: a.signin_methods,
            grant_types: a.grant_types,
            providers: a.providers,
            saml_reply_url: a.saml_reply_url,
            enable_password: a.enable_password,
            enable_signin_session: a.enable_signin_session,
            enable_auto_signin: a.enable_auto_signin,
            enable_code_signin: a.enable_code_signin,
            enable_saml_compress: a.enable_saml_compress,
            enable_web_authn: a.enable_web_authn,
            enable_link_with_email: a.enable_link_with_email,
            enable_internal_signup: a.enable_internal_signup,
            enable_idp_signup: a.enable_idp_signup,
            form_offset: a.form_offset,
            form_background_url: a.form_background_url,
            tags: a.tags,
            footer_text: a.footer_text,
            logout_url: a.logout_url,
            logout_redirect_uris: a.logout_redirect_uris,
            created_at: a.created_at,
            updated_at: a.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationListResponse {
    pub data: Vec<ApplicationResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApplicationQuery {
    pub owner: Option<String>,
    pub organization: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

impl Default for ApplicationQuery {
    fn default() -> Self {
        Self {
            owner: None,
            organization: None,
            page: Some(1),
            page_size: Some(20),
        }
    }
}
