//! WeChat browser selection is a shared-state fact, never callback User-Agent.
use crate::services::providers::{
    oauth_provider::{OAuthProviderTrait, configuration_stamp},
    wechat::{WeChatProvider, WeChatVariant},
};
use crate::{
    error::{AppError, AppResult},
    models::Provider,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A server-injected, loopback-only integration fixture transport. No Provider,
/// state JSON, query parameter or environment variable can create this value.
#[derive(Clone)]
pub struct WeChatTestTransport {
    origin: String,
    client: reqwest::Client,
    authorization_origin: Option<String>,
}
impl WeChatTestTransport {
    pub fn new(origin: &str) -> AppResult<Self> {
        let url = reqwest::Url::parse(origin).map_err(|_| invalid())?;
        let ip = url
            .host_str()
            .and_then(|s| s.parse::<std::net::IpAddr>().ok());
        if !ip.is_some_and(|ip| ip.is_loopback())
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.scheme(), "http" | "https")
        {
            return Err(invalid());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .map_err(|_| invalid())?;
        Ok(Self {
            origin: origin.into(),
            client,
            authorization_origin: None,
        })
    }
    pub fn with_authorization_origin(mut self, origin: &str) -> AppResult<Self> {
        // Reuse the same loopback-only, no-credentials origin validation.
        let checked = Self::new(origin)?;
        self.authorization_origin = Some(checked.origin);
        Ok(self)
    }
    pub fn apply(&self, adapter: WeChatProvider) -> AppResult<WeChatProvider> {
        let adapter = adapter.with_test_transport(&self.origin, self.client.clone())?;
        Ok(if let Some(origin) = &self.authorization_origin {
            adapter.with_test_authorization_origin(origin.clone())
        } else {
            adapter
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Flow {
    variant: WeChatVariant,
    binding: String,
}
fn invalid() -> AppError {
    AppError::Authentication("WeChat sign-in configuration changed; restart sign-in".into())
}
fn binding(provider: &Provider, variant: WeChatVariant) -> String {
    crate::services::social_state_service::proof_hash(
        &serde_json::json!([
            "wechat.browser.v1",
            configuration_stamp(provider),
            provider.client_id2,
            provider.client_secret2,
            variant
        ])
        .to_string(),
    )
}
fn credentials(provider: &Provider, variant: WeChatVariant) -> AppResult<(String, String)> {
    let (id, secret) = match variant {
        WeChatVariant::Desktop => (&provider.client_id, &provider.client_secret),
        WeChatVariant::Micromessenger => (&provider.client_id2, &provider.client_secret2),
    };
    match (id, secret) {
        (Some(id), Some(secret))
            if !id.trim().is_empty()
                && !secret.trim().is_empty()
                && !id.chars().any(char::is_control)
                && !secret.chars().any(char::is_control) =>
        {
            Ok((id.clone(), secret.clone()))
        }
        _ => Err(invalid()),
    }
}
pub fn prepare(provider: &Provider, user_agent: &str) -> AppResult<Option<Value>> {
    if provider.provider_type != "WeChat" {
        return Ok(None);
    }
    let variant = if user_agent.contains("MicroMessenger") {
        WeChatVariant::Micromessenger
    } else {
        WeChatVariant::Desktop
    };
    credentials(provider, variant)?;
    serde_json::to_value(Flow {
        variant,
        binding: binding(provider, variant),
    })
    .map(Some)
    .map_err(|_| invalid())
}
pub fn provider(
    provider: &Provider,
    context: &Value,
    transport: Option<&WeChatTestTransport>,
) -> AppResult<Option<Box<dyn OAuthProviderTrait>>> {
    if provider.provider_type != "WeChat" {
        return Ok(None);
    }
    let flow: Flow = serde_json::from_value(context.clone()).map_err(|_| invalid())?;
    if flow.binding != binding(provider, flow.variant) {
        return Err(invalid());
    }
    let (id, secret) = credentials(provider, flow.variant)?;
    let adapter =
        WeChatProvider::with_variant(id, secret, flow.variant).with_scope(provider.scopes.clone());
    let adapter = if let Some(transport) = transport {
        transport.apply(adapter)?
    } else {
        adapter
    };
    Ok(Some(Box::new(adapter)))
}
