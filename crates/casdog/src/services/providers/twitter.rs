use async_trait::async_trait;
use serde::Deserialize;

use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use crate::error::{AppError, AppResult};

pub struct TwitterProvider {
    client_id: String,
    client_secret: String,
}

impl TwitterProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }
}

#[derive(Deserialize)]
struct TwitterTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct TwitterUserResponse {
    data: TwitterUser,
}

#[derive(Deserialize)]
struct TwitterUser {
    id: String,
    username: String,
    name: String,
    profile_image_url: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for TwitterProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("users.read tweet.read");
        format!(
            "https://twitter.com/i/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}&code_challenge=challenge&code_challenge_method=plain",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();

        // Twitter requires Basic Auth with client_id:client_secret
        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", self.client_id, self.client_secret),
        );

        let resp = client
            .post("https://api.twitter.com/2/oauth2/token")
            .header("Authorization", format!("Basic {}", auth))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("code", code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
                ("code_verifier", "challenge"),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Twitter token exchange failed: {}", e)))?;

        let token_resp: TwitterTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Twitter token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://api.twitter.com/2/users/me")
            .query(&[("user.fields", "profile_image_url")])
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Twitter user info failed: {}", e)))?;

        let user_resp: TwitterUserResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Twitter user parse failed: {}", e)))?;

        let user = user_resp.data;

        Ok(ProviderUserInfo {
            id: user.id,
            username: user.username.clone(),
            display_name: user.name,
            email: None, // Twitter OAuth 2.0 doesn't provide email in basic scope
            avatar_url: user.profile_image_url,
            provider_type: "Twitter".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Twitter"
    }
}
