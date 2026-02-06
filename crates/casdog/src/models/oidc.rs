use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

// OpenID Connect Discovery Response
#[derive(Debug, Serialize, ToSchema)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub introspection_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
}

impl OidcDiscovery {
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{}/login/oauth/authorize", issuer),
            token_endpoint: format!("{}/api/login/oauth/access_token", issuer),
            userinfo_endpoint: format!("{}/api/userinfo", issuer),
            jwks_uri: format!("{}/.well-known/jwks", issuer),
            registration_endpoint: None,
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "phone".to_string(),
                "address".to_string(),
                "offline_access".to_string(),
            ],
            response_types_supported: vec![
                "code".to_string(),
                "token".to_string(),
                "id_token".to_string(),
                "code token".to_string(),
                "code id_token".to_string(),
                "token id_token".to_string(),
                "code token id_token".to_string(),
            ],
            response_modes_supported: vec![
                "query".to_string(),
                "fragment".to_string(),
                "form_post".to_string(),
            ],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
                "password".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec![
                "RS256".to_string(),
                "RS384".to_string(),
                "RS512".to_string(),
                "ES256".to_string(),
                "ES384".to_string(),
                "ES512".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "none".to_string(),
            ],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "name".to_string(),
                "preferred_username".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "phone_number".to_string(),
                "phone_number_verified".to_string(),
                "picture".to_string(),
                "groups".to_string(),
            ],
            code_challenge_methods_supported: vec!["plain".to_string(), "S256".to_string()],
            introspection_endpoint: Some(format!("{}/api/login/oauth/introspect", issuer)),
            revocation_endpoint: Some(format!("{}/api/login/oauth/revoke", issuer)),
            end_session_endpoint: Some(format!("{}/api/logout", issuer)),
        }
    }
}

// JSON Web Key Set
#[derive(Debug, Serialize, ToSchema)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Jwk {
    pub kty: String, // Key type (RSA, EC)
    pub alg: String, // Algorithm (RS256, ES256)
    pub use_: String, // public key use (sig)
    pub kid: String, // Key ID
    pub n: Option<String>, // RSA modulus
    pub e: Option<String>, // RSA exponent
    pub x: Option<String>, // EC x coordinate
    pub y: Option<String>, // EC y coordinate
    pub crv: Option<String>, // EC curve
}

// Userinfo response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserinfoResponse {
    pub sub: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub picture: Option<String>,
    pub groups: Option<Vec<String>>,
}

// WebFinger response
#[derive(Debug, Serialize, ToSchema)]
pub struct WebfingerResponse {
    pub subject: String,
    pub links: Vec<WebfingerLink>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebfingerLink {
    pub rel: String,
    pub href: String,
}
