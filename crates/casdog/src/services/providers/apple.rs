use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct AppleProvider {
    client_id: String,
    client_secret: String, // JWT token generated from private key
}

impl AppleProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self { client_id, client_secret }
    }
}

#[derive(Deserialize)]
struct AppleTokenResponse {
    access_token: String,
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct AppleIdTokenClaims {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
}

#[async_trait]
impl OAuthProviderTrait for AppleProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("name email");
        format!(
            "https://appleid.apple.com/auth/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}&response_mode=form_post",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post("https://appleid.apple.com/auth/token")
            .form(&[
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Apple token exchange failed: {}", e)))?;

        let token_resp: AppleTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Apple token parse failed: {}", e)))?;

        // Return id_token if available, otherwise access_token
        Ok(token_resp.id_token.unwrap_or(token_resp.access_token))
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        // Apple returns user info in the ID token (JWT)
        // For simplicity, we'll decode the JWT payload (base64 decode the middle part)
        let parts: Vec<&str> = access_token.split('.').collect();
        if parts.len() != 3 {
            return Err(AppError::Internal("Invalid Apple ID token format".to_string()));
        }

        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])
            .map_err(|e| AppError::Internal(format!("Failed to decode Apple ID token: {}", e)))?;

        let claims: AppleIdTokenClaims = serde_json::from_slice(&payload)
            .map_err(|e| AppError::Internal(format!("Failed to parse Apple ID token claims: {}", e)))?;

        Ok(ProviderUserInfo {
            id: claims.sub.clone(),
            username: claims.email.clone().unwrap_or(claims.sub.clone()),
            display_name: claims.email.clone().unwrap_or_default(),
            email: claims.email,
            avatar_url: None,
            provider_type: "Apple".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Apple"
    }
}
