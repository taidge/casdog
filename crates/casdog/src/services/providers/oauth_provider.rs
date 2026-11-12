use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, AppResult},
    models::Provider,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Unified user info returned from all OAuth providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderUserInfo {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub provider_type: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub phone_verified: bool,
}

fn invalid() -> AppError {
    AppError::Validation("Invalid OAuth provider configuration".into())
}
pub fn builtin(provider_type: &str) -> bool {
    matches!(
        provider_type,
        "GitHub"
            | "Google"
            | "Facebook"
            | "Microsoft"
            | "Apple"
            | "GitLab"
            | "Discord"
            | "Slack"
            | "Twitter"
            | "LinkedIn"
            | "Bitbucket"
            | "Okta"
            | "WeChat"
            | "DingTalk"
            | "Lark"
            | "Feishu"
            | "Telegram"
            | "Steam"
    )
}
pub fn mapping(encoded: Option<&str>) -> AppResult<BTreeMap<String, String>> {
    let Some(encoded) = encoded.filter(|s| !s.trim().is_empty()) else {
        return Ok(BTreeMap::new());
    };
    if encoded.len() > 8192 {
        return Err(invalid());
    }
    let values: BTreeMap<String, String> = serde_json::from_str(encoded).map_err(|_| invalid())?;
    if values.len() > 8
        || values.iter().any(|(target, path)| {
            !matches!(
                target.as_str(),
                "id" | "username"
                    | "displayName"
                    | "email"
                    | "emailVerified"
                    | "phone"
                    | "phoneVerified"
                    | "avatarUrl"
            ) || path.is_empty()
                || path.len() > 512
                || path.chars().any(char::is_control)
                || path.split('.').count() > 16
                || path.split('.').any(str::is_empty)
        })
    {
        return Err(invalid());
    }
    Ok(values)
}
pub fn validate_oauth_configuration(provider: &Provider) -> AppResult<()> {
    if provider.category != "OAuth" {
        return Ok(());
    }
    let mapped = mapping(provider.user_mapping.as_deref())?;
    let headers = oauth_headers(provider)?;
    if builtin(&provider.provider_type) && provider.method.as_deref().is_some_and(|v| !v.is_empty())
    {
        return Err(invalid());
    }
    if builtin(&provider.provider_type) && !headers.is_empty() {
        return Err(invalid());
    }
    if builtin(&provider.provider_type) && !mapped.is_empty() {
        return Err(invalid());
    }
    if let Some(scope) = provider.scopes.as_deref().filter(|s| !s.trim().is_empty()) {
        if scope.len() > 2048
            || scope.chars().any(char::is_control)
            || matches!(
                provider.provider_type.as_str(),
                "Telegram" | "Steam" | "Lark" | "Feishu"
            )
        {
            return Err(invalid());
        }
    }
    if !builtin(&provider.provider_type) {
        super::generic_oauth::validate_endpoint_configuration(provider)?;
    } else {
        for value in [
            &provider.custom_auth_url,
            &provider.custom_token_url,
            &provider.custom_user_info_url,
        ]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        {
            validate_url(value)?;
        }
        if provider.provider_type == "Okta" {
            okta_base(provider)?;
        }
    }
    Ok(())
}
pub fn oauth_headers(provider: &Provider) -> AppResult<reqwest::header::HeaderMap> {
    let mut result = reqwest::header::HeaderMap::new();
    let Some(raw) = provider.http_headers.as_deref().filter(|v| !v.is_empty()) else {
        return Ok(result);
    };
    if raw.len() > 32768 {
        return Err(invalid());
    }
    let fields: BTreeMap<String, String> = serde_json::from_str(raw).map_err(|_| invalid())?;
    if fields.len() > 64 {
        return Err(invalid());
    }
    for (name, value) in fields {
        if name.len() > 256 || value.len() > 16384 {
            return Err(invalid());
        }
        let name =
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
        if matches!(
            name.as_str(),
            "host"
                | "authorization"
                | "cookie"
                | "set-cookie"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "proxy-connection"
                | "upgrade"
                | "trailer"
                | "te"
                | "content-type"
                | "accept"
                | "origin"
                | "referer"
        ) || name.as_str().starts_with("x-forwarded-")
            || name.as_str().starts_with("sec-")
            || name.as_str() == "forwarded"
            || result.contains_key(&name)
        {
            return Err(invalid());
        }
        let mut value = reqwest::header::HeaderValue::from_str(&value).map_err(|_| invalid())?;
        value.set_sensitive(true);
        result.insert(name, value);
    }
    Ok(result)
}
pub fn validate_url(value: &str) -> AppResult<reqwest::Url> {
    if value.len() > 4096 {
        return Err(invalid());
    }
    let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(url)
}
/// Casdoor's Okta HostUrl comes from Provider.Domain and may include an
/// authorization-server path, e.g. https://tenant.okta.com/oauth2/default.
pub fn okta_base(provider: &Provider) -> AppResult<String> {
    if let Some(base) = provider
        .domain
        .as_deref()
        .filter(|v| !v.is_empty())
        .or_else(|| provider.issuer_url.as_deref().filter(|v| !v.is_empty()))
    {
        let url = validate_url(base)?;
        if url.scheme() != "https" || url.query().is_some() {
            return Err(invalid());
        }
        return Ok(url.as_str().trim_end_matches('/').to_owned());
    }
    if let Some(legacy) = provider
        .custom_auth_url
        .as_deref()
        .filter(|v| !v.is_empty())
    {
        let url = validate_url(legacy)?;
        if url.scheme() != "https" {
            return Err(invalid());
        }
        return Ok(format!("{}/oauth2", url.origin().ascii_serialization()));
    }
    Ok("https://your-domain.okta.com/oauth2".into())
}
/// Identity semantics, including custom claim paths, are part of a browser proof.
pub fn configuration_stamp(provider: &Provider) -> String {
    crate::services::social_state_service::proof_hash(
        &json!([
            "casdog.oauth.configuration.v3",
            provider.id,
            provider.owner,
            provider.name,
            provider.category,
            provider.provider_type,
            provider.client_id,
            provider.client_secret,
            provider.client_id2,
            provider.client_secret2,
            provider.method,
            provider.custom_auth_url,
            provider.custom_token_url,
            provider.custom_user_info_url,
            provider.scopes,
            provider.user_mapping,
            provider.issuer_url,
            provider.domain,
            provider.http_headers
        ])
        .to_string(),
    )
}
pub fn map_user_info(
    claims: &Value,
    fields: &BTreeMap<String, String>,
    provider_type: &str,
) -> AppResult<ProviderUserInfo> {
    let object = claims
        .as_object()
        .ok_or_else(|| AppError::Authentication("Invalid provider profile".into()))?;
    let scalar = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let field = |target: &str, fallbacks: &[&str]| -> Option<String> {
        if let Some(path) = fields.get(target) {
            let value = path
                .split('.')
                .try_fold(claims, |current, key| current.as_object()?.get(key));
            if let Some(value) = value.and_then(&scalar).filter(|s| !s.is_empty()) {
                return Some(value);
            }
            // An explicitly configured identity path is authoritative. Never
            // substitute another claim if its value is absent or malformed.
            if target == "id" {
                return None;
            }
        } else if let Some(value) = object
            .get(target)
            .and_then(&scalar)
            .filter(|s| !s.is_empty())
        {
            return Some(value);
        }
        fallbacks
            .iter()
            .find_map(|key| object.get(*key).and_then(&scalar).filter(|s| !s.is_empty()))
    };
    let id = field("id", &["sub"])
        .filter(|v| {
            !v.trim().is_empty()
                && v != "unknown"
                && v.len() <= 512
                && !v.chars().any(char::is_control)
        })
        .ok_or_else(|| AppError::Authentication("Provider returned no stable subject".into()))?;
    // Floating-point IDs can round two distinct principals to the same value.
    let identity = if let Some(path) = fields.get("id") {
        path.split('.')
            .try_fold(claims, |current, key| current.as_object()?.get(key))
    } else {
        object
            .get("id")
            .filter(|v| !v.is_null())
            .or_else(|| object.get("sub"))
    };
    if matches!(identity, Some(Value::Bool(_)))
        || matches!(identity,Some(Value::Number(n)) if !n.is_i64()&&!n.is_u64())
    {
        return Err(AppError::Authentication(
            "Provider subject must be a string or integer".into(),
        ));
    }
    let username =
        field("username", &["preferred_username", "name", "sub"]).unwrap_or_else(|| id.clone());
    let display_name =
        field("displayName", &["name", "preferred_username"]).unwrap_or_else(|| username.clone());
    let email = field("email", &["email"]);
    let phone = field("phone", &["phone_number"]);
    let email_verified = field("emailVerified", &["email_verified"]).as_deref() == Some("true");
    let phone_verified =
        field("phoneVerified", &["phone_number_verified"]).as_deref() == Some("true");
    if display_name.chars().count() > 255
        || username.len() > 512
        || email.as_ref().is_some_and(|v| v.len() > 255)
        || phone.as_ref().is_some_and(|v| v.len() > 50)
    {
        return Err(AppError::Authentication("Invalid provider profile".into()));
    }
    if email_verified {
        crate::services::CheckService::check_email(email.as_deref().unwrap_or_default())
            .map_err(|_| AppError::Authentication("Invalid verified provider email".into()))?;
    }
    if phone_verified
        && !phone.as_deref().is_some_and(|p| {
            p.starts_with('+')
                && phonenumber::parse(None, p)
                    .is_ok_and(|n| n.is_valid() && n.extension().is_none())
        })
    {
        return Err(AppError::Authentication(
            "Invalid verified provider phone".into(),
        ));
    }
    let avatar_url = field("avatarUrl", &["picture"]);
    if let Some(url) = &avatar_url {
        if url.len() > 512 {
            return Err(AppError::Authentication("Invalid provider avatar".into()));
        }
        validate_url(url)
            .map_err(|_| AppError::Authentication("Invalid provider avatar".into()))?;
    }
    Ok(ProviderUserInfo {
        id,
        username,
        display_name,
        email,
        avatar_url,
        provider_type: provider_type.to_owned(),
        email_verified,
        phone,
        phone_verified,
    })
}

pub fn create_oauth_provider_record(provider: &Provider) -> AppResult<Box<dyn OAuthProviderTrait>> {
    create_oauth_provider_record_with_policy(provider, false)
}
pub fn create_oauth_provider_resolved(
    provider: &Provider,
    allow_private: bool,
    endpoints: Option<&super::generic_oauth::ResolvedOAuthEndpoints>,
) -> AppResult<Box<dyn OAuthProviderTrait>> {
    validate_oauth_configuration(provider)?;
    if !builtin(&provider.provider_type) {
        let endpoints = endpoints.ok_or_else(|| {
            AppError::Authentication("OAuth endpoints missing; restart sign-in".into())
        })?;
        return Ok(Box::new(
            super::generic_oauth::GenericOAuthProvider::from_resolved(
                provider,
                endpoints,
                allow_private,
            )?,
        ));
    }
    create_oauth_provider_record_with_policy(provider, allow_private)
}
/// The caller must derive private access from a persisted global-admin approval,
/// never from provider ownership or request metadata.
pub fn create_oauth_provider_record_with_policy(
    provider: &Provider,
    allow_private: bool,
) -> AppResult<Box<dyn OAuthProviderTrait>> {
    if provider.category != "OAuth" {
        return Err(invalid());
    }
    validate_oauth_configuration(provider)?;
    if provider.provider_type == "Okta" {
        let inner: Box<dyn OAuthProviderTrait> = Box::new(
            super::okta::OktaProvider::from_issuer_base(
                provider.client_id.clone().unwrap_or_default(),
                provider.client_secret.clone().unwrap_or_default(),
                okta_base(provider)?,
            )?
            .with_network_policy(allow_private),
        );
        return Ok(
            match provider.scopes.as_deref().filter(|s| !s.trim().is_empty()) {
                Some(scope) => Box::new(ScopedProvider {
                    inner,
                    scope: scope.to_owned(),
                }) as Box<dyn OAuthProviderTrait>,
                None => inner,
            },
        );
    }
    if !builtin(&provider.provider_type) {
        if super::generic_oauth::oidc_issuer(provider)?.is_some() {
            return Err(AppError::Validation(
                "Resolve OIDC discovery before constructing its provider".into(),
            ));
        }
        let endpoints = super::generic_oauth::ResolvedOAuthEndpoints {
            issuer: None,
            auth_url: provider.custom_auth_url.clone().unwrap_or_default(),
            token_url: provider.custom_token_url.clone().unwrap_or_default(),
            user_info_url: provider.custom_user_info_url.clone().unwrap_or_default(),
            pkce_s256: false,
            jwks_url: None,
            signing_algorithms: Vec::new(),
            client_auth: super::generic_oauth::configured_client_auth(provider)?
                .unwrap_or("client_secret_post")
                .into(),
        };
        return Ok(Box::new(
            super::generic_oauth::GenericOAuthProvider::from_resolved(
                provider,
                &endpoints,
                allow_private,
            )?,
        ));
    }
    create_oauth_provider_with_policy(
        &provider.provider_type,
        provider.client_id.as_deref().unwrap_or_default(),
        provider.client_secret.as_deref().unwrap_or_default(),
        provider.custom_auth_url.as_deref(),
        provider.custom_token_url.as_deref(),
        provider.custom_user_info_url.as_deref(),
        provider.scopes.as_deref(),
        allow_private,
    )
    .ok_or_else(invalid)
}

struct ScopedProvider {
    inner: Box<dyn OAuthProviderTrait>,
    scope: String,
}
#[async_trait]
impl OAuthProviderTrait for ScopedProvider {
    fn get_auth_url(&self, redirect: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope
            .filter(|v| !v.trim().is_empty())
            .unwrap_or(&self.scope);
        let original = self.inner.get_auth_url(redirect, state, Some(scope));
        if let Ok(mut url) = reqwest::Url::parse(&original) {
            // Also honors configured scope for OAuth providers with a fixed
            // default query (DingTalk), without adding it to non-scope protocols.
            if url.query_pairs().any(|(key, _)| key == "scope") {
                let values: Vec<_> = url
                    .query_pairs()
                    .filter(|(key, _)| key != "scope")
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                url.query_pairs_mut()
                    .clear()
                    .extend_pairs(values)
                    .append_pair("scope", scope);
                return url.into();
            }
        }
        original
    }
    async fn exchange_code(&self, code: &str, redirect: &str) -> AppResult<String> {
        self.inner.exchange_code(code, redirect).await
    }
    async fn get_user_info(&self, token: &str) -> AppResult<ProviderUserInfo> {
        self.inner.get_user_info(token).await
    }
    async fn exchange_code_token(
        &self,
        code: &str,
        redirect: &str,
        context: &OAuthExchangeContext,
    ) -> AppResult<OAuthToken> {
        self.inner
            .exchange_code_token(code, redirect, context)
            .await
    }
    async fn get_user_info_token(
        &self,
        token: &OAuthToken,
        context: &OAuthExchangeContext,
    ) -> AppResult<ProviderUserInfo> {
        self.inner.get_user_info_token(token, context).await
    }
    async fn verify_identity(
        &self,
        token: &OAuthToken,
        context: &OAuthExchangeContext,
    ) -> AppResult<Option<Value>> {
        self.inner.verify_identity(token, context).await
    }
    async fn get_user_info_verified(
        &self,
        token: &OAuthToken,
        context: &OAuthExchangeContext,
        identity: Option<Value>,
    ) -> AppResult<ProviderUserInfo> {
        self.inner
            .get_user_info_verified(token, context, identity)
            .await
    }
    fn provider_type(&self) -> &str {
        self.inner.provider_type()
    }
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

    /// Request-local token envelope: never a process-local side cache. Existing
    /// built-in adapters retain their String methods through these defaults.
    async fn exchange_code_token(
        &self,
        code: &str,
        redirect_uri: &str,
        _context: &OAuthExchangeContext,
    ) -> AppResult<OAuthToken> {
        let access_token = self.exchange_code(code, redirect_uri).await?;
        Ok(OAuthToken {
            extra: json!({"access_token":access_token}),
            access_token,
        })
    }
    async fn get_user_info_token(
        &self,
        token: &OAuthToken,
        _context: &OAuthExchangeContext,
    ) -> AppResult<ProviderUserInfo> {
        self.get_user_info(&token.access_token).await
    }
    /// Separate network checkpoint lets HTTP handlers re-read approval between
    /// token, JWKS and UserInfo requests. The verified claims remain request-local.
    async fn verify_identity(
        &self,
        _token: &OAuthToken,
        _context: &OAuthExchangeContext,
    ) -> AppResult<Option<Value>> {
        Ok(None)
    }
    async fn get_user_info_verified(
        &self,
        token: &OAuthToken,
        context: &OAuthExchangeContext,
        _identity: Option<Value>,
    ) -> AppResult<ProviderUserInfo> {
        self.get_user_info_token(token, context).await
    }

    /// Provider type name
    fn provider_type(&self) -> &str;
}

// Deliberately no Debug implementation: provider token extras can contain
// refresh tokens and other credentials that must never enter diagnostics.
pub struct OAuthToken {
    pub access_token: String,
    pub extra: Value,
}
#[derive(Default)]
pub struct OAuthExchangeContext {
    pub state: String,
    pub code_verifier: Option<String>,
    pub nonce: Option<String>,
    pub started_at: Option<i64>,
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
    create_oauth_provider_with_policy(
        provider_type,
        client_id,
        client_secret,
        custom_auth_url,
        custom_token_url,
        custom_user_info_url,
        custom_scope,
        false,
    )
}
fn create_oauth_provider_with_policy(
    provider_type: &str,
    client_id: &str,
    client_secret: &str,
    custom_auth_url: Option<&str>,
    custom_token_url: Option<&str>,
    custom_user_info_url: Option<&str>,
    custom_scope: Option<&str>,
    allow_private: bool,
) -> Option<Box<dyn OAuthProviderTrait>> {
    if custom_scope.is_some_and(|s| !s.trim().is_empty())
        && matches!(provider_type, "Steam" | "Telegram" | "Lark" | "Feishu")
    {
        return None;
    }
    let provider: Option<Box<dyn OAuthProviderTrait>> = match provider_type {
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
                .and_then(|value| reqwest::Url::parse(value).ok())
                .filter(|url| url.scheme() == "https")
                .map(|url| {
                    url.origin()
                        .ascii_serialization()
                        .trim_start_matches("https://")
                        .to_owned()
                })
                .unwrap_or_else(|| "your-domain.okta.com".into());
            Some(Box::new(
                super::okta::OktaProvider::new(
                    client_id.to_string(),
                    client_secret.to_string(),
                    domain.to_string(),
                )
                .with_network_policy(allow_private),
            ))
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
    };
    provider.map(
        |inner| match custom_scope.filter(|s| !s.trim().is_empty()) {
            Some(scope) if !matches!(provider_type, "Steam" | "Telegram" | "Lark" | "Feishu") => {
                Box::new(ScopedProvider {
                    inner,
                    scope: scope.to_owned(),
                }) as Box<dyn OAuthProviderTrait>
            }
            _ => inner,
        },
    )
}
