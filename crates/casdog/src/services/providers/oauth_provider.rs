use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::AppResult;

/// Unified user info returned from all OAuth providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderUserInfo {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub provider_type: String,
}

/// Trait for all OAuth/OIDC social login providers
#[async_trait]
pub trait OAuthProviderTrait: Send + Sync {
    /// Get the authorization URL for redirecting the user
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String;

    /// Exchange authorization code for access token
    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String>;

    /// Get user info from the provider using the access token
    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo>;

    /// Provider type name
    fn provider_type(&self) -> &str;
}

/// Factory function to create a provider from database Provider record fields
pub fn create_oauth_provider(
    provider_type: &str,
    client_id: &str,
    client_secret: &str,
    custom_auth_url: Option<&str>,
    custom_token_url: Option<&str>,
    custom_user_info_url: Option<&str>,
    custom_scope: Option<&str>,
) -> Option<Box<dyn OAuthProviderTrait>> {
    match provider_type {
        "GitHub" => Some(Box::new(super::github::GitHubProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Google" => Some(Box::new(super::google::GoogleProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Facebook" => Some(Box::new(super::facebook::FacebookProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Microsoft" => Some(Box::new(super::microsoft::MicrosoftProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Apple" => Some(Box::new(super::apple::AppleProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "GitLab" => Some(Box::new(super::gitlab::GitLabProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Discord" => Some(Box::new(super::discord::DiscordProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Slack" => Some(Box::new(super::slack::SlackProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Twitter" => Some(Box::new(super::twitter::TwitterProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "LinkedIn" => Some(Box::new(super::linkedin::LinkedInProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Bitbucket" => Some(Box::new(super::bitbucket::BitbucketProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Okta" => {
            // Okta requires a domain, use custom_auth_url if provided or default
            let domain = custom_auth_url
                .and_then(|url| url.strip_prefix("https://"))
                .and_then(|s| s.split('/').next())
                .unwrap_or("your-domain.okta.com");
            Some(Box::new(super::okta::OktaProvider::new(
                client_id.to_string(),
                client_secret.to_string(),
                domain.to_string(),
            )))
        }
        "WeChat" => Some(Box::new(super::wechat::WeChatProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "DingTalk" => Some(Box::new(super::dingtalk::DingTalkProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Lark" | "Feishu" => Some(Box::new(super::lark::LarkProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Telegram" => Some(Box::new(super::telegram::TelegramProvider::new(
            client_id.to_string(),
            client_secret.to_string(),
        ))),
        "Steam" => {
            // Steam requires an API key and realm
            let realm = custom_auth_url.unwrap_or("http://localhost");
            Some(Box::new(super::steam::SteamProvider::new(
                client_id.to_string(), // API key
                realm.to_string(),
            )))
        }
        _ => {
            // Try generic OAuth for custom providers
            if let (Some(auth_url), Some(token_url), Some(user_info_url)) =
                (custom_auth_url, custom_token_url, custom_user_info_url)
            {
                Some(Box::new(super::generic_oauth::GenericOAuthProvider::new(
                    provider_type.to_string(),
                    client_id.to_string(),
                    client_secret.to_string(),
                    auth_url.to_string(),
                    token_url.to_string(),
                    user_info_url.to_string(),
                    custom_scope.unwrap_or("openid profile email").to_string(),
                )))
            } else {
                None
            }
        }
    }
}
