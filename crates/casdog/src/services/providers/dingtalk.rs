use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct DingTalkProvider {
    app_id: String,
    app_secret: String,
}

impl DingTalkProvider {
    pub fn new(app_id: String, app_secret: String) -> Self {
        Self { app_id, app_secret }
    }
}

#[derive(Deserialize)]
struct DingTalkTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct DingTalkUserResponse {
    userid: String,
    name: String,
    avatar: Option<String>,
    email: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for DingTalkProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, _scope: Option<&str>) -> String {
        format!(
            "https://login.dingtalk.com/oauth2/auth?client_id={}&redirect_uri={}&response_type=code&state={}&scope=openid&prompt=consent",
            urlencoding::encode(&self.app_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        )
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();

        // First, get access_token using app credentials
        let token_resp = client
            .post("https://api.dingtalk.com/v1.0/oauth2/userAccessToken")
            .json(&serde_json::json!({
                "clientId": self.app_id,
                "clientSecret": self.app_secret,
                "code": code,
                "grantType": "authorization_code",
            }))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DingTalk token exchange failed: {}", e)))?;

        let token_data: DingTalkTokenResponse = token_resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("DingTalk token parse failed: {}", e)))?;

        Ok(token_data.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();

        // Get user info using access token
        let resp = client
            .get("https://api.dingtalk.com/v1.0/contact/users/me")
            .header("x-acs-dingtalk-access-token", access_token)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DingTalk user info failed: {}", e)))?;

        let user: DingTalkUserResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("DingTalk user parse failed: {}", e)))?;

        Ok(ProviderUserInfo {
            id: user.userid.clone(),
            username: user.email.clone().unwrap_or(user.userid),
            display_name: user.name,
            email: user.email,
            avatar_url: user.avatar,
            provider_type: "DingTalk".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "DingTalk"
    }
}
