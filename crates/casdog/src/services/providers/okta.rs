use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct OktaProvider {
    client_id: String,
    client_secret: String,
    domain: String,
}

impl OktaProvider {
    pub fn new(client_id: String, client_secret: String, domain: String) -> Self {
        Self {
            client_id,
            client_secret,
            domain,
        }
    }
}

#[derive(Deserialize)]
struct OktaTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct OktaUser {
    sub: String,
    name: Option<String>,
    email: Option<String>,
    preferred_username: Option<String>,
    picture: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for OktaProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("openid profile email");
        format!(
            "https://{}/oauth2/v1/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            self.domain,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();

        // Okta requires Basic Auth
        let auth = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{}:{}", self.client_id, self.client_secret));

        let resp = client
            .post(&format!("https://{}/oauth2/v1/token", self.domain))
            .header("Authorization", format!("Basic {}", auth))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("code", code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Okta token exchange failed: {}", e)))?;

        let token_resp: OktaTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Okta token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get(&format!("https://{}/oauth2/v1/userinfo", self.domain))
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Okta user info failed: {}", e)))?;

        let user: OktaUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Okta user parse failed: {}", e)))?;

        Ok(ProviderUserInfo {
            id: user.sub.clone(),
            username: user.preferred_username
                .or_else(|| user.email.clone())
                .unwrap_or(user.sub),
            display_name: user.name.unwrap_or_default(),
            email: user.email,
            avatar_url: user.picture,
            provider_type: "Okta".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Okta"
    }
}
