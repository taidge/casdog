use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct FacebookProvider {
    client_id: String,
    client_secret: String,
}

impl FacebookProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self { client_id, client_secret }
    }
}

#[derive(Deserialize)]
struct FacebookTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct FacebookUser {
    id: String,
    name: Option<String>,
    email: Option<String>,
    picture: Option<FacebookPicture>,
}

#[derive(Deserialize)]
struct FacebookPicture {
    data: Option<FacebookPictureData>,
}

#[derive(Deserialize)]
struct FacebookPictureData {
    url: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for FacebookProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("email public_profile");
        format!(
            "https://www.facebook.com/v18.0/dialog/oauth?client_id={}&redirect_uri={}&state={}&scope={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://graph.facebook.com/v18.0/oauth/access_token")
            .query(&[
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Facebook token exchange failed: {}", e)))?;

        let token_resp: FacebookTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Facebook token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://graph.facebook.com/v18.0/me")
            .query(&[
                ("fields", "id,name,email,picture"),
                ("access_token", access_token),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Facebook user info failed: {}", e)))?;

        let user: FacebookUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Facebook user parse failed: {}", e)))?;

        let avatar_url = user.picture
            .and_then(|p| p.data)
            .and_then(|d| d.url);

        Ok(ProviderUserInfo {
            id: user.id.clone(),
            username: user.email.clone().unwrap_or(user.id),
            display_name: user.name.unwrap_or_default(),
            email: user.email,
            avatar_url,
            provider_type: "Facebook".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Facebook"
    }
}
