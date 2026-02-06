use async_trait::async_trait;
use serde::Deserialize;

use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use crate::error::{AppError, AppResult};

pub struct DiscordProvider {
    client_id: String,
    client_secret: String,
}

impl DiscordProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }
}

#[derive(Deserialize)]
struct DiscordTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    discriminator: String,
    avatar: Option<String>,
    email: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for DiscordProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("identify email");
        format!(
            "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post("https://discord.com/api/oauth2/token")
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
            .map_err(|e| AppError::Internal(format!("Discord token exchange failed: {}", e)))?;

        let token_resp: DiscordTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Discord token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://discord.com/api/users/@me")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Discord user info failed: {}", e)))?;

        let user: DiscordUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Discord user parse failed: {}", e)))?;

        let avatar_url = user.avatar.map(|hash| {
            format!(
                "https://cdn.discordapp.com/avatars/{}/{}.png",
                user.id, hash
            )
        });

        let display_name = if user.discriminator == "0" {
            user.username.clone()
        } else {
            format!("{}#{}", user.username, user.discriminator)
        };

        Ok(ProviderUserInfo {
            id: user.id,
            username: user.username,
            display_name,
            email: user.email,
            avatar_url,
            provider_type: "Discord".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Discord"
    }
}
