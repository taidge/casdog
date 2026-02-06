use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct SlackProvider {
    client_id: String,
    client_secret: String,
}

impl SlackProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self { client_id, client_secret }
    }
}

#[derive(Deserialize)]
struct SlackTokenResponse {
    ok: bool,
    access_token: Option<String>,
    authed_user: Option<SlackAuthedUser>,
}

#[derive(Deserialize)]
struct SlackAuthedUser {
    access_token: Option<String>,
}

#[derive(Deserialize)]
struct SlackUserResponse {
    ok: bool,
    user: Option<SlackUser>,
}

#[derive(Deserialize)]
struct SlackUser {
    id: String,
    name: String,
    real_name: Option<String>,
    profile: Option<SlackProfile>,
}

#[derive(Deserialize)]
struct SlackProfile {
    email: Option<String>,
    image_512: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for SlackProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("users:read users:read.email");
        format!(
            "https://slack.com/oauth/v2/authorize?client_id={}&redirect_uri={}&state={}&scope={}&user_scope={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
            urlencoding::encode("identity.basic identity.email identity.avatar"),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post("https://slack.com/api/oauth.v2.access")
            .form(&[
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Slack token exchange failed: {}", e)))?;

        let token_resp: SlackTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Slack token parse failed: {}", e)))?;

        if !token_resp.ok {
            return Err(AppError::Internal("Slack token exchange failed".to_string()));
        }

        // Try to get user access token first, fall back to workspace token
        token_resp.authed_user
            .and_then(|u| u.access_token)
            .or(token_resp.access_token)
            .ok_or_else(|| AppError::Internal("No access token in Slack response".to_string()))
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://slack.com/api/users.identity")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Slack user info failed: {}", e)))?;

        let user_resp: SlackUserResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Slack user parse failed: {}", e)))?;

        if !user_resp.ok {
            return Err(AppError::Internal("Slack user info request failed".to_string()));
        }

        let user = user_resp.user.ok_or_else(|| AppError::Internal("No user in Slack response".to_string()))?;

        let email = user.profile.as_ref().and_then(|p| p.email.clone());
        let avatar_url = user.profile.as_ref().and_then(|p| p.image_512.clone());

        Ok(ProviderUserInfo {
            id: user.id,
            username: user.name.clone(),
            display_name: user.real_name.unwrap_or(user.name),
            email,
            avatar_url,
            provider_type: "Slack".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Slack"
    }
}
