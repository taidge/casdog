use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Token {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub application: String,
    pub organization: String,
    pub user: String,
    pub code: Option<String>,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub access_token_hash: Option<String>,
    pub refresh_token_hash: Option<String>,
    pub expires_in: i64,
    pub scope: String,
    pub token_type: String,
    pub code_challenge: Option<String>,
    pub code_is_used: bool,
    pub code_expire_in: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    pub owner: String,
    pub name: String,
    pub application: String,
    pub organization: String,
    pub user: String,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTokenRequest {
    pub scope: Option<String>,
    pub expires_in: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub application: String,
    pub organization: String,
    pub user: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub scope: String,
    pub token_type: String,
}

impl From<Token> for TokenResponse {
    fn from(t: Token) -> Self {
        Self {
            id: t.id,
            owner: t.owner,
            name: t.name,
            created_at: t.created_at,
            application: t.application,
            organization: t.organization,
            user: t.user,
            access_token: t.access_token,
            refresh_token: t.refresh_token,
            expires_in: t.expires_in,
            scope: t.scope,
            token_type: t.token_type,
        }
    }
}

// OAuth token request/response
#[derive(Debug, Deserialize, ToSchema)]
pub struct OAuthTokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IntrospectResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
}
