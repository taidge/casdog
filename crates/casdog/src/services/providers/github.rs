use async_trait::async_trait;
use serde::Deserialize;

use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use crate::error::{AppError, AppResult};

pub struct GitHubProvider {
    client_id: String,
    client_secret: String,
}

impl GitHubProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for GitHubProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("read:user user:email");
        format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .json(&serde_json::json!({
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
            }))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("GitHub token exchange failed: {}", e)))?;

        let token_resp: GitHubTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("GitHub token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "Casdog-IAM")
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("GitHub user info failed: {}", e)))?;

        let user: GitHubUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("GitHub user parse failed: {}", e)))?;

        Ok(ProviderUserInfo {
            id: user.id.to_string(),
            username: user.login.clone(),
            display_name: user.name.unwrap_or(user.login),
            email: user.email,
            avatar_url: user.avatar_url,
            provider_type: "GitHub".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "GitHub"
    }
}
