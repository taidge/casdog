use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct MicrosoftProvider {
    client_id: String,
    client_secret: String,
    tenant: String,
}

impl MicrosoftProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            tenant: "common".to_string(),
        }
    }

    pub fn with_tenant(client_id: String, client_secret: String, tenant: String) -> Self {
        Self {
            client_id,
            client_secret,
            tenant,
        }
    }
}

#[derive(Deserialize)]
struct MicrosoftTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct MicrosoftUser {
    id: String,
    #[serde(rename = "userPrincipalName")]
    user_principal_name: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    mail: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for MicrosoftProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("openid profile email User.Read");
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            urlencoding::encode(&self.tenant),
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .post(&format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                self.tenant
            ))
            .form(&[
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Microsoft token exchange failed: {}", e)))?;

        let token_resp: MicrosoftTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Microsoft token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://graph.microsoft.com/v1.0/me")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Microsoft user info failed: {}", e)))?;

        let user: MicrosoftUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Microsoft user parse failed: {}", e)))?;

        Ok(ProviderUserInfo {
            id: user.id.clone(),
            username: user.user_principal_name.clone()
                .or_else(|| user.mail.clone())
                .unwrap_or(user.id),
            display_name: user.display_name.unwrap_or_default(),
            email: user.mail.or(user.user_principal_name),
            avatar_url: None,
            provider_type: "Microsoft".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Microsoft"
    }
}
