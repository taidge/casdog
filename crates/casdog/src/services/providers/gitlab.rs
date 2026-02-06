use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct GitLabProvider {
    client_id: String,
    client_secret: String,
    base_url: String,
}

impl GitLabProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            base_url: "https://gitlab.com".to_string(),
        }
    }

    pub fn with_base_url(client_id: String, client_secret: String, base_url: String) -> Self {
        Self {
            client_id,
            client_secret,
            base_url,
        }
    }
}

#[derive(Deserialize)]
struct GitLabTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GitLabUser {
    id: i64,
    username: String,
    name: String,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for GitLabProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("read_user");
        format!(
            "{}/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            self.base_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post(&format!("{}/oauth/token", self.base_url))
            .json(&serde_json::json!({
                "code": code,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("GitLab token exchange failed: {}", e)))?;

        let token_resp: GitLabTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("GitLab token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get(&format!("{}/api/v4/user", self.base_url))
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("GitLab user info failed: {}", e)))?;

        let user: GitLabUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("GitLab user parse failed: {}", e)))?;

        Ok(ProviderUserInfo {
            id: user.id.to_string(),
            username: user.username,
            display_name: user.name,
            email: user.email,
            avatar_url: user.avatar_url,
            provider_type: "GitLab".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "GitLab"
    }
}
