use async_trait::async_trait;
use serde::Deserialize;

use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use crate::error::{AppError, AppResult};

pub struct GoogleProvider {
    client_id: String,
    client_secret: String,
}

impl GoogleProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUser {
    sub: String,
    name: Option<String>,
    email: Option<String>,
    picture: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for GoogleProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("openid profile email");
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Google token exchange failed: {}", e)))?;

        let token_resp: GoogleTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Google token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://openidconnect.googleapis.com/v1/userinfo")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Google user info failed: {}", e)))?;

        let user: GoogleUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Google user parse failed: {}", e)))?;

        Ok(ProviderUserInfo {
            id: user.sub.clone(),
            username: user.email.clone().unwrap_or(user.sub),
            display_name: user.name.unwrap_or_default(),
            email: user.email,
            avatar_url: user.picture,
            provider_type: "Google".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Google"
    }
}
