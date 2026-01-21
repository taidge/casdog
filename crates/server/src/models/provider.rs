use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Provider {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub display_name: String,
    pub category: String, // OAuth, SAML, LDAP, SMS, Email, Storage, Payment, Captcha
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub provider_type: String, // GitHub, Google, etc.
    pub sub_type: Option<String>,
    pub method: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_id2: Option<String>,
    pub client_secret2: Option<String>,
    pub cert: Option<String>,
    pub custom_auth_url: Option<String>,
    pub custom_token_url: Option<String>,
    pub custom_user_info_url: Option<String>,
    pub custom_logo: Option<String>,
    pub scopes: Option<String>,
    pub user_mapping: Option<String>,
    // Email/SMS specific
    pub host: Option<String>,
    pub port: Option<i32>,
    pub disable_ssl: bool,
    pub title: Option<String>,
    pub content: Option<String>,
    pub receiver: Option<String>,
    // SMS specific
    pub region_id: Option<String>,
    pub sign_name: Option<String>,
    pub template_code: Option<String>,
    pub app_id: Option<String>,
    // Storage specific
    pub endpoint: Option<String>,
    pub intranet_endpoint: Option<String>,
    pub domain: Option<String>,
    pub bucket: Option<String>,
    pub path_prefix: Option<String>,
    // SAML/OIDC specific
    pub metadata: Option<String>,
    pub idp: Option<String>,
    pub issuer_url: Option<String>,
    pub enable_sign_authn_request: bool,
    pub provider_url: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProviderRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub category: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    pub sub_type: Option<String>,
    pub method: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub disable_ssl: Option<bool>,
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub domain: Option<String>,
    pub region_id: Option<String>,
    pub sign_name: Option<String>,
    pub template_code: Option<String>,
    pub app_id: Option<String>,
    pub metadata: Option<String>,
    pub issuer_url: Option<String>,
    pub provider_url: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProviderRequest {
    pub display_name: Option<String>,
    pub category: Option<String>,
    #[serde(rename = "type")]
    pub provider_type: Option<String>,
    pub sub_type: Option<String>,
    pub method: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub disable_ssl: Option<bool>,
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub domain: Option<String>,
    pub region_id: Option<String>,
    pub sign_name: Option<String>,
    pub template_code: Option<String>,
    pub app_id: Option<String>,
    pub metadata: Option<String>,
    pub issuer_url: Option<String>,
    pub provider_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub display_name: String,
    pub category: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    pub sub_type: Option<String>,
    pub client_id: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub endpoint: Option<String>,
    pub domain: Option<String>,
    pub provider_url: Option<String>,
}

impl From<Provider> for ProviderResponse {
    fn from(p: Provider) -> Self {
        Self {
            id: p.id,
            owner: p.owner,
            name: p.name,
            created_at: p.created_at,
            display_name: p.display_name,
            category: p.category,
            provider_type: p.provider_type,
            sub_type: p.sub_type,
            client_id: p.client_id,
            host: p.host,
            port: p.port,
            endpoint: p.endpoint,
            domain: p.domain,
            provider_url: p.provider_url,
        }
    }
}
