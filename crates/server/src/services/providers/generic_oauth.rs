use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;

pub struct GenericOAuthProvider {
    provider_type_name: String,
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    user_info_url: String,
    scope: String,
}

impl GenericOAuthProvider {
    pub fn new(
        provider_type_name: String,
        client_id: String,
        client_secret: String,
        auth_url: String,
        token_url: String,
        user_info_url: String,
        scope: String,
    ) -> Self {
        Self {
            provider_type_name,
            client_id,
            client_secret,
            auth_url,
            token_url,
            user_info_url,
            scope,
        }
    }
}

#[async_trait]
impl OAuthProviderTrait for GenericOAuthProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or(&self.scope);
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            self.auth_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post(&self.token_url)
            .header("Accept", "application/json")
            .form(&[
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Token exchange failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Token parse failed: {}", e)))?;

        json["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| AppError::Internal("No access_token in response".to_string()))
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get(&self.user_info_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("User info failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("User info parse failed: {}", e)))?;

        Ok(ProviderUserInfo {
            id: json["sub"].as_str()
                .or_else(|| json["id"].as_str())
                .unwrap_or("unknown")
                .to_string(),
            username: json["preferred_username"].as_str()
                .or_else(|| json["login"].as_str())
                .or_else(|| json["email"].as_str())
                .unwrap_or("unknown")
                .to_string(),
            display_name: json["name"].as_str()
                .unwrap_or("Unknown")
                .to_string(),
            email: json["email"].as_str().map(|s| s.to_string()),
            avatar_url: json["picture"].as_str()
                .or_else(|| json["avatar_url"].as_str())
                .map(|s| s.to_string()),
            provider_type: self.provider_type_name.clone(),
        })
    }

    fn provider_type(&self) -> &str {
        &self.provider_type_name
    }
}
