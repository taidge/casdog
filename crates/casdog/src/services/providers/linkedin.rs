use async_trait::async_trait;
use serde::Deserialize;

use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use crate::error::{AppError, AppResult};

pub struct LinkedInProvider {
    client_id: String,
    client_secret: String,
}

impl LinkedInProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }
}

#[derive(Deserialize)]
struct LinkedInTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct LinkedInUser {
    sub: String,
    name: Option<String>,
    email: Option<String>,
    picture: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for LinkedInProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("openid profile email");
        format!(
            "https://www.linkedin.com/oauth/v2/authorization?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post("https://www.linkedin.com/oauth/v2/accessToken")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("LinkedIn token exchange failed: {}", e)))?;

        let token_resp: LinkedInTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("LinkedIn token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://api.linkedin.com/v2/userinfo")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("LinkedIn user info failed: {}", e)))?;

        let user: LinkedInUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("LinkedIn user parse failed: {}", e)))?;

        Ok(ProviderUserInfo {
            id: user.sub.clone(),
            username: user.email.clone().unwrap_or(user.sub),
            display_name: user.name.unwrap_or_default(),
            email: user.email,
            avatar_url: user.picture,
            provider_type: "LinkedIn".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "LinkedIn"
    }
}
