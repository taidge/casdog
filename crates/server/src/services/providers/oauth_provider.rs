use crate::error::AppResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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
