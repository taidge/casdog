use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;

use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo, map_user_info, validate_url};
use crate::{
    error::{AppError, AppResult},
    services::system_gap_service,
};

pub struct GenericOAuthProvider {
    provider_type_name: String,
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    user_info_url: String,
    scope: String,
    user_mapping: BTreeMap<String, String>,
    allow_private: bool,
}
fn failed() -> AppError {
    AppError::Authentication("OAuth provider request failed".into())
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
            user_mapping: BTreeMap::new(),
            allow_private: false,
        }
    }
    pub fn with_configuration(
        mut self,
        user_mapping: BTreeMap<String, String>,
        allow_private: bool,
    ) -> Self {
        self.user_mapping = user_mapping;
        self.allow_private = allow_private;
        self
    }
    async fn client(&self, value: &str) -> AppResult<(reqwest::Url, reqwest::Client)> {
        let url = validate_url(value)?;
        let client = system_gap_service::client(&url, self.allow_private)
            .await
            .map_err(|_| failed())?;
        Ok((url, client))
    }
    async fn json(response: reqwest::Response) -> AppResult<Value> {
        let bytes = system_gap_service::limited_bytes(response, 1024 * 1024)
            .await
            .map_err(|_| failed())?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| failed())?;
        if !value.is_object() || value.get("error").is_some() {
            return Err(failed());
        }
        Ok(value)
    }
}
#[async_trait]
impl OAuthProviderTrait for GenericOAuthProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let Ok(mut url) = validate_url(&self.auth_url) else {
            return String::new();
        };
        let scope = scope
            .filter(|s| !s.trim().is_empty())
            .or_else(|| (!self.scope.trim().is_empty()).then_some(self.scope.as_str()))
            .unwrap_or("openid profile email");
        let pairs: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| {
                !matches!(
                    key.as_ref(),
                    "client_id" | "redirect_uri" | "response_type" | "state" | "scope"
                )
            })
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        url.query_pairs_mut()
            .clear()
            .extend_pairs(pairs)
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("state", state)
            .append_pair("scope", scope);
        url.into()
    }
    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        if code.is_empty() || code.len() > 8192 {
            return Err(failed());
        }
        let (url, client) = self.client(&self.token_url).await?;
        let response = client
            .post(url)
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
            .map_err(|_| failed())?;
        let value = Self::json(response).await?;
        if value["token_type"]
            .as_str()
            .is_some_and(|v| !v.eq_ignore_ascii_case("bearer"))
        {
            return Err(failed());
        }
        value["access_token"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 16384 && !v.chars().any(char::is_control))
            .map(str::to_owned)
            .ok_or_else(failed)
    }
    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        if access_token.is_empty()
            || access_token.len() > 16384
            || access_token.chars().any(char::is_control)
        {
            return Err(failed());
        }
        let (url, client) = self.client(&self.user_info_url).await?;
        let response = client
            .get(url)
            .header("Accept", "application/json")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|_| failed())?;
        let claims = Self::json(response).await?;
        map_user_info(&claims, &self.user_mapping, &self.provider_type_name)
    }
    fn provider_type(&self) -> &str {
        &self.provider_type_name
    }
}
