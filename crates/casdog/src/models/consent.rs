use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct ConsentRecord {
    pub id: String,
    pub user_id: String,
    pub application_id: String,
    pub granted_scopes: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConsentRequest {
    pub application: String,
    #[serde(rename = "grantedScopes", default)]
    pub granted_scopes: Vec<String>,
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
    pub provider: Option<String>,
    #[serde(rename = "signinMethod")]
    pub signin_method: Option<String>,
    #[serde(rename = "responseType")]
    pub response_type: Option<String>,
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub challenge: Option<String>,
    #[serde(rename = "codeChallengeMethod")]
    pub code_challenge_method: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentGrantResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    pub application: String,
    pub granted_scopes: Vec<String>,
}
