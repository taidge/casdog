use async_trait::async_trait;
use serde::Deserialize;

use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use crate::error::{AppError, AppResult};

pub struct OktaProvider {
    client_id: String,
    client_secret: String,
    base_url: String,
    allow_private: bool,
}

impl OktaProvider {
    pub fn new(client_id: String, client_secret: String, domain: String) -> Self {
        Self {
            client_id,
            client_secret,
            base_url: format!("https://{domain}/oauth2"),
            allow_private: false,
        }
    }
    pub fn from_issuer_base(
        client_id: String,
        client_secret: String,
        base_url: String,
    ) -> AppResult<Self> {
        let url = super::oauth_provider::validate_url(&base_url)?;
        if url.scheme() != "https" || url.query().is_some() {
            return Err(AppError::Validation(
                "Okta requires an HTTPS issuer base without query".into(),
            ));
        }
        Ok(Self {
            client_id,
            client_secret,
            base_url: url.as_str().trim_end_matches('/').to_owned(),
            allow_private: false,
        })
    }
    pub fn with_network_policy(mut self, allow_private: bool) -> Self {
        self.allow_private = allow_private;
        self
    }
    async fn client(&self, path: &str) -> AppResult<(reqwest::Url, reqwest::Client)> {
        let url = super::oauth_provider::validate_url(&format!("{}/v1/{path}", self.base_url))?;
        let client = crate::services::system_gap_service::client(&url, self.allow_private)
            .await
            .map_err(|_| failed())?;
        Ok((url, client))
    }
}
fn failed() -> AppError {
    AppError::Authentication("Okta provider request failed".into())
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
            "{}/v1/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            self.base_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        if code.is_empty() || code.len() > 8192 {
            return Err(failed());
        }
        let (url, client) = self.client("token").await?;

        // Okta requires Basic Auth
        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", self.client_id, self.client_secret),
        );

        let resp = client
            .post(url)
            .header("Authorization", format!("Basic {}", auth))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("code", code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|_| failed())?;

        let body = crate::services::system_gap_service::limited_bytes(resp, 1024 * 1024)
            .await
            .map_err(|_| failed())?;
        let token_resp: OktaTokenResponse = serde_json::from_slice(&body).map_err(|_| failed())?;
        if token_resp.access_token.is_empty()
            || token_resp.access_token.len() > 16384
            || token_resp.access_token.chars().any(char::is_control)
        {
            return Err(failed());
        }

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        if access_token.is_empty()
            || access_token.len() > 16384
            || access_token.chars().any(char::is_control)
        {
            return Err(failed());
        }
        let (url, client) = self.client("userinfo").await?;
        let resp = client
            .get(url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|_| failed())?;

        let body = crate::services::system_gap_service::limited_bytes(resp, 1024 * 1024)
            .await
            .map_err(|_| failed())?;
        let user: OktaUser = serde_json::from_slice(&body).map_err(|_| failed())?;

        Ok(ProviderUserInfo {
            email_verified: false,
            phone: None,
            phone_verified: false,
            id: user.sub.clone(),
            username: user
                .preferred_username
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
