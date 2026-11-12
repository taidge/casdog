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
    pub http_headers: Option<String>,
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

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateProviderRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub category: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(alias = "subType")]
    pub sub_type: Option<String>,
    pub content: Option<String>,
    pub scopes: Option<String>,
    pub method: Option<String>,
    #[serde(alias = "clientId")]
    pub client_id: Option<String>,
    #[serde(alias = "clientSecret")]
    pub client_secret: Option<String>,
    #[serde(alias = "clientId2")]
    pub client_id2: Option<String>,
    #[serde(alias = "clientSecret2")]
    pub client_secret2: Option<String>,
    pub cert: Option<String>,
    #[serde(alias = "customAuthUrl")]
    pub custom_auth_url: Option<String>,
    #[serde(alias = "customTokenUrl")]
    pub custom_token_url: Option<String>,
    #[serde(alias = "customUserInfoUrl")]
    pub custom_user_info_url: Option<String>,
    #[serde(alias = "customLogo")]
    pub custom_logo: Option<String>,
    #[serde(alias = "userMapping")]
    #[serde(
        default,
        deserialize_with = "crate::services::provider_configuration_service::deserialize_json_text"
    )]
    pub user_mapping: Option<String>,
    #[serde(alias = "httpHeaders")]
    #[serde(
        default,
        deserialize_with = "crate::services::provider_configuration_service::deserialize_json_text"
    )]
    pub http_headers: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    #[serde(alias = "disableSsl")]
    pub disable_ssl: Option<bool>,
    pub title: Option<String>,
    pub receiver: Option<String>,
    pub endpoint: Option<String>,
    #[serde(alias = "intranetEndpoint")]
    pub intranet_endpoint: Option<String>,
    pub bucket: Option<String>,
    pub domain: Option<String>,
    #[serde(alias = "pathPrefix")]
    pub path_prefix: Option<String>,
    #[serde(alias = "regionId")]
    pub region_id: Option<String>,
    #[serde(alias = "signName")]
    pub sign_name: Option<String>,
    #[serde(alias = "templateCode")]
    pub template_code: Option<String>,
    #[serde(alias = "appId")]
    pub app_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::services::provider_configuration_service::deserialize_json_text"
    )]
    pub metadata: Option<String>,
    pub idp: Option<String>,
    #[serde(alias = "issuerUrl")]
    pub issuer_url: Option<String>,
    #[serde(alias = "enableSignAuthnRequest")]
    pub enable_sign_authn_request: Option<bool>,
    #[serde(alias = "providerUrl")]
    pub provider_url: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateProviderRequest {
    pub display_name: Option<String>,
    pub category: Option<String>,
    #[serde(rename = "type")]
    pub provider_type: Option<String>,
    #[serde(alias = "subType")]
    pub sub_type: Option<String>,
    pub content: Option<String>,
    pub scopes: Option<String>,
    pub method: Option<String>,
    #[serde(alias = "clientId")]
    pub client_id: Option<String>,
    #[serde(alias = "clientSecret")]
    pub client_secret: Option<String>,
    #[serde(alias = "clientId2")]
    pub client_id2: Option<String>,
    #[serde(alias = "clientSecret2")]
    pub client_secret2: Option<String>,
    pub cert: Option<String>,
    #[serde(alias = "customAuthUrl")]
    pub custom_auth_url: Option<String>,
    #[serde(alias = "customTokenUrl")]
    pub custom_token_url: Option<String>,
    #[serde(alias = "customUserInfoUrl")]
    pub custom_user_info_url: Option<String>,
    #[serde(alias = "customLogo")]
    pub custom_logo: Option<String>,
    #[serde(alias = "userMapping")]
    #[serde(
        default,
        deserialize_with = "crate::services::provider_configuration_service::deserialize_json_text"
    )]
    pub user_mapping: Option<String>,
    #[serde(alias = "httpHeaders")]
    #[serde(
        default,
        deserialize_with = "crate::services::provider_configuration_service::deserialize_json_text"
    )]
    pub http_headers: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    #[serde(alias = "disableSsl")]
    pub disable_ssl: Option<bool>,
    pub title: Option<String>,
    pub receiver: Option<String>,
    pub endpoint: Option<String>,
    #[serde(alias = "intranetEndpoint")]
    pub intranet_endpoint: Option<String>,
    pub bucket: Option<String>,
    pub domain: Option<String>,
    #[serde(alias = "pathPrefix")]
    pub path_prefix: Option<String>,
    #[serde(alias = "regionId")]
    pub region_id: Option<String>,
    #[serde(alias = "signName")]
    pub sign_name: Option<String>,
    #[serde(alias = "templateCode")]
    pub template_code: Option<String>,
    #[serde(alias = "appId")]
    pub app_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::services::provider_configuration_service::deserialize_json_text"
    )]
    pub metadata: Option<String>,
    pub idp: Option<String>,
    #[serde(alias = "issuerUrl")]
    pub issuer_url: Option<String>,
    #[serde(alias = "enableSignAuthnRequest")]
    pub enable_sign_authn_request: Option<bool>,
    #[serde(alias = "providerUrl")]
    pub provider_url: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ProviderResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub display_name: String,
    pub category: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    pub sub_type: Option<String>,
    pub content: Option<String>,
    pub scopes: Option<String>,
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
    pub user_mapping: Option<serde_json::Value>,
    pub http_headers: Option<serde_json::Value>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub disable_ssl: Option<bool>,
    pub title: Option<String>,
    pub receiver: Option<String>,
    pub endpoint: Option<String>,
    pub intranet_endpoint: Option<String>,
    pub bucket: Option<String>,
    pub domain: Option<String>,
    pub path_prefix: Option<String>,
    pub region_id: Option<String>,
    pub sign_name: Option<String>,
    pub template_code: Option<String>,
    pub app_id: Option<String>,
    pub metadata: Option<String>,
    pub idp: Option<String>,
    pub issuer_url: Option<String>,
    pub enable_sign_authn_request: Option<bool>,
    pub provider_url: Option<String>,
}

impl From<Provider> for ProviderResponse {
    fn from(provider: Provider) -> Self {
        let value = crate::services::provider_configuration_service::project(
            serde_json::to_value(provider).expect("Provider JSON"),
        );
        serde_json::from_value(value).expect("Provider response uses the same typed fields")
    }
}
