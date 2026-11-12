use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use crate::error::{AppError, AppResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WeChatVariant {
    Desktop,
    Micromessenger,
}

pub struct WeChatProvider {
    app_id: String,
    app_secret: String,
    variant: WeChatVariant,
    scope: Option<String>,
    api_origin: reqwest::Url,
    test_client: Option<reqwest::Client>,
    test_authorization_origin: Option<String>,
}
fn denied() -> AppError {
    AppError::Authentication("WeChat authorization response is invalid".into())
}
fn identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}
impl WeChatProvider {
    pub fn new(app_id: String, app_secret: String) -> Self {
        Self::with_variant(app_id, app_secret, WeChatVariant::Desktop)
    }
    pub fn with_variant(app_id: String, app_secret: String, variant: WeChatVariant) -> Self {
        Self {
            app_id,
            app_secret,
            variant,
            scope: None,
            api_origin: reqwest::Url::parse("https://api.weixin.qq.com")
                .expect("official WeChat origin"),
            test_client: None,
            test_authorization_origin: None,
        }
    }
    /// Explicit SDK/fixture transport injection, never populated from Provider
    /// configuration or browser requests.
    pub fn with_test_transport(mut self, origin: &str, client: reqwest::Client) -> AppResult<Self> {
        let url = reqwest::Url::parse(origin).map_err(|_| denied())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(denied());
        }
        self.api_origin = url;
        self.test_client = Some(client);
        Ok(self)
    }
    pub fn variant(&self) -> WeChatVariant {
        self.variant
    }
    /// Used only by the typed, server-injected loopback browser fixture.
    pub(crate) fn with_test_authorization_origin(mut self, origin: String) -> Self {
        self.test_authorization_origin = Some(origin);
        self
    }
    pub fn with_scope(mut self, scope: Option<String>) -> Self {
        self.scope = scope.filter(|s| !s.trim().is_empty());
        self
    }
    async fn request(&self, path: &str, query: &[(&str, &str)]) -> AppResult<serde_json::Value> {
        let url = self.api_origin.join(path).map_err(|_| denied())?;
        let client = if let Some(client) = &self.test_client {
            client.clone()
        } else {
            crate::services::system_gap_service::client(&url, false)
                .await
                .map_err(|_| AppError::Internal("WeChat endpoint unavailable".into()))?
        };
        let mut response = client
            .get(url)
            .query(query)
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .await
            .map_err(|_| AppError::Internal("WeChat request failed".into()))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(denied());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| denied())? {
            if body.len() + chunk.len() > 65536 {
                return Err(denied());
            }
            body.extend_from_slice(&chunk);
        }
        let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| denied())?;
        if !value.is_object()
            || value
                .get("errcode")
                .is_some_and(|code| code.as_i64() != Some(0))
        {
            return Err(denied());
        }
        Ok(value)
    }
}
#[derive(Serialize, Deserialize)]
struct Token {
    access_token: String,
    openid: String,
    #[serde(default)]
    unionid: Option<String>,
    app_id: String,
    variant: WeChatVariant,
}
#[async_trait]
impl OAuthProviderTrait for WeChatProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let (path, scope) = match self.variant {
            WeChatVariant::Desktop => (
                "qrconnect",
                scope
                    .filter(|s| !s.trim().is_empty())
                    .or(self.scope.as_deref())
                    .unwrap_or("snsapi_login"),
            ),
            WeChatVariant::Micromessenger => ("oauth2/authorize", "snsapi_userinfo"),
        };
        let origin = self
            .test_authorization_origin
            .as_deref()
            .unwrap_or("https://open.weixin.qq.com")
            .trim_end_matches('/');
        format!(
            "{origin}/connect/{path}?appid={}&redirect_uri={}&response_type=code&scope={}&state={}#wechat_redirect",
            urlencoding::encode(&self.app_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(scope),
            urlencoding::encode(state)
        )
    }
    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> AppResult<String> {
        if code.is_empty() || code.len() > 2048 || code.chars().any(char::is_control) {
            return Err(denied());
        }
        let value = self
            .request(
                "/sns/oauth2/access_token",
                &[
                    ("appid", &self.app_id),
                    ("secret", &self.app_secret),
                    ("code", code),
                    ("grant_type", "authorization_code"),
                ],
            )
            .await?;
        let access_token = value["access_token"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 8192 && !s.chars().any(char::is_control))
            .ok_or_else(denied)?;
        let openid = value["openid"]
            .as_str()
            .filter(|s| identity(s))
            .ok_or_else(denied)?;
        let unionid = optional_identity(&value, "unionid")?;
        serde_json::to_string(&Token {
            access_token: access_token.into(),
            openid: openid.into(),
            unionid,
            app_id: self.app_id.clone(),
            variant: self.variant,
        })
        .map_err(|_| denied())
    }
    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        if access_token.len() > 16384 {
            return Err(denied());
        }
        let token: Token = serde_json::from_str(access_token).map_err(|_| denied())?;
        if token.app_id != self.app_id
            || token.variant != self.variant
            || !identity(&token.openid)
            || token.access_token.is_empty()
        {
            return Err(denied());
        }
        let value = self
            .request(
                "/sns/userinfo",
                &[
                    ("access_token", &token.access_token),
                    ("openid", &token.openid),
                    ("lang", "zh_CN"),
                ],
            )
            .await?;
        if value["openid"].as_str() != Some(token.openid.as_str()) {
            return Err(denied());
        }
        let unionid = optional_identity(&value, "unionid")?;
        if token.unionid.is_some() && token.unionid != unionid {
            return Err(denied());
        }
        let id = unionid.unwrap_or_else(|| match self.variant {
            WeChatVariant::Desktop => token.openid.clone(),
            WeChatVariant::Micromessenger => format!("openid:{}:{}", self.app_id, token.openid),
        });
        Ok(ProviderUserInfo {
            id,
            username: token.openid,
            display_name: value["nickname"].as_str().unwrap_or_default().to_owned(),
            email: None,
            avatar_url: value["headimgurl"].as_str().map(str::to_string),
            provider_type: "WeChat".into(),
            email_verified: false,
            phone: None,
            phone_verified: false,
        })
    }
    fn provider_type(&self) -> &str {
        "WeChat"
    }
}
fn optional_identity(value: &serde_json::Value, key: &str) -> AppResult<Option<String>> {
    match value.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) if s.is_empty() => Ok(None),
        Some(serde_json::Value::String(s)) if identity(s) => Ok(Some(s.clone())),
        _ => Err(denied()),
    }
}
