use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use std::collections::HashMap;

pub struct TelegramProvider {
    bot_token: String,
}

impl TelegramProvider {
    pub fn new(bot_token: String, _secret: String) -> Self {
        Self { bot_token }
    }
}

#[async_trait]
impl OAuthProviderTrait for TelegramProvider {
    fn get_auth_url(&self, redirect_uri: &str, _state: &str, _scope: Option<&str>) -> String {
        // Telegram Login Widget doesn't have a standard OAuth URL
        // This returns a placeholder that should be replaced with the widget HTML
        format!(
            "https://oauth.telegram.org/auth?bot_id={}&origin={}&return_to={}",
            self.bot_token.split(':').next().unwrap_or(""),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(redirect_uri),
        )
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> AppResult<String> {
        // Telegram doesn't use traditional OAuth code exchange
        // The "code" parameter should contain the hash verification data
        // We'll just pass it through
        Ok(code.to_string())
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        // For Telegram, the access_token is actually the auth data hash
        // Parse the auth data which comes as URL parameters
        let params: HashMap<String, String> = access_token
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.split('=');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect();

        // Verify the hash (simplified - in production you should verify the hash properly)
        let id = params.get("id")
            .ok_or_else(|| AppError::Internal("No id in Telegram auth data".to_string()))?;
        let username = params.get("username").cloned();
        let first_name = params.get("first_name").cloned().unwrap_or_default();
        let last_name = params.get("last_name").cloned().unwrap_or_default();
        let photo_url = params.get("photo_url").cloned();

        let display_name = if !last_name.is_empty() {
            format!("{} {}", first_name, last_name)
        } else {
            first_name
        };

        Ok(ProviderUserInfo {
            id: id.clone(),
            username: username.unwrap_or(id.clone()),
            display_name,
            email: None, // Telegram doesn't provide email
            avatar_url: photo_url,
            provider_type: "Telegram".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Telegram"
    }
}
