use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;

use super::oauth_provider::{
    OAuthExchangeContext, OAuthProviderTrait, OAuthToken, ProviderUserInfo, map_user_info,
    validate_url,
};
use crate::models::Provider;
use crate::{
    error::{AppError, AppResult},
    services::system_gap_service,
};
use serde::{Deserialize, Serialize};

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
    private_origins: Option<Vec<String>>,
    headers: reqwest::header::HeaderMap,
    identity: Option<ResolvedOAuthEndpoints>,
    client_auth: String,
}
fn failed() -> AppError {
    AppError::Authentication("OAuth provider request failed".into())
}
fn configuration_error() -> AppError {
    AppError::Validation("Invalid OAuth endpoint configuration".into())
}
fn placeholder_regex() -> &'static regex::Regex {
    static PATTERN: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}").unwrap());
    &PATTERN
}
pub fn is_template(value: &str) -> bool {
    placeholder_regex().is_match(value)
}
pub fn validate_template(value: &str, token: bool) -> AppResult<()> {
    validate_url(value)?;
    let authority_start = value.find("://").ok_or_else(configuration_error)? + 3;
    let authority_end = value[authority_start..]
        .find(['/', '?', '#'])
        .map(|n| n + authority_start)
        .unwrap_or(value.len());
    let query = value.find('?');
    let mut count = 0;
    for capture in placeholder_regex().captures_iter(value) {
        count += 1;
        if count > 32 {
            return Err(configuration_error());
        }
        let item = capture.get(0).unwrap();
        let name = &capture[1];
        if item.start() < authority_end {
            return Err(configuration_error());
        }
        if token
            && !matches!(
                name,
                "clientId" | "clientSecret" | "code" | "redirectUri" | "codeVerifier" | "state"
            )
        {
            return Err(configuration_error());
        }
        if query.is_some_and(|q| item.start() > q) {
            let q = query.unwrap();
            let segment = value[q + 1..item.start()]
                .rfind('&')
                .map(|n| q + 2 + n)
                .unwrap_or(q + 1);
            let equal = value[segment..item.start()].find('=');
            if equal.is_none() {
                return Err(configuration_error());
            }
        } else if token {
            return Err(configuration_error());
        }
    }
    let without = placeholder_regex().replace_all(value, "");
    if without.contains(['{', '}']) {
        return Err(configuration_error());
    }
    Ok(())
}
fn fill_template(
    value: &str,
    mut lookup: impl FnMut(&str) -> AppResult<String>,
    path: bool,
) -> AppResult<String> {
    let mut output = String::new();
    let mut last = 0;
    for capture in placeholder_regex().captures_iter(value) {
        let found = capture.get(0).unwrap();
        let replacement = lookup(&capture[1])?;
        if replacement.is_empty()
            || replacement.len() > 16384
            || replacement.chars().any(char::is_control)
            || (path && matches!(replacement.as_str(), "." | ".."))
        {
            return Err(failed());
        }
        output.push_str(&value[last..found.start()]);
        output.push_str(&urlencoding::encode(&replacement));
        if output.len() > 65536 {
            return Err(failed());
        }
        last = found.end();
    }
    output.push_str(&value[last..]);
    if output.len() > 65536 {
        return Err(failed());
    }
    Ok(output)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedOAuthEndpoints {
    pub issuer: Option<String>,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub pkce_s256: bool,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default)]
    pub signing_algorithms: Vec<String>,
    #[serde(default = "default_post")]
    pub client_auth: String,
}
fn default_post() -> String {
    "client_secret_post".into()
}
fn form_component(value: &str) -> String {
    let mut url = reqwest::Url::parse("https://form.invalid").unwrap();
    url.query_pairs_mut().append_pair("", value);
    url.query().unwrap().strip_prefix('=').unwrap().to_owned()
}
pub fn configured_client_auth(provider: &Provider) -> AppResult<Option<&str>> {
    match provider.method.as_deref().filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some("POST" | "post" | "client_secret_post") => Ok(Some("client_secret_post")),
        Some("client_secret_basic") => Ok(Some("client_secret_basic")),
        Some("none") => Ok(Some("none")),
        _ => Err(configuration_error()),
    }
}
pub fn oidc_issuer(provider: &Provider) -> AppResult<Option<String>> {
    if provider.provider_type != "OIDC" {
        return Ok(None);
    }
    let Some(value) = provider
        .domain
        .as_deref()
        .filter(|v| !v.is_empty())
        .or_else(|| provider.issuer_url.as_deref().filter(|v| !v.is_empty()))
    else {
        return Ok(None);
    };
    let url = validate_url(value)?;
    if url.query().is_some()
        || value.contains(['{', '}'])
        || value.ends_with("/.well-known/openid-configuration")
    {
        return Err(configuration_error());
    }
    if url.scheme() != "https" && !loopback_url(&url) {
        return Err(configuration_error());
    }
    Ok(Some(url.as_str().trim_end_matches('/').to_owned()))
}
fn loopback_url(url: &reqwest::Url) -> bool {
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}
pub fn validate_endpoint_configuration(provider: &Provider) -> AppResult<()> {
    let issuer = oidc_issuer(provider)?;
    let method = configured_client_auth(provider)?;
    let auth = provider
        .custom_auth_url
        .as_deref()
        .filter(|v| !v.is_empty());
    let token = provider
        .custom_token_url
        .as_deref()
        .filter(|v| !v.is_empty());
    let info = provider
        .custom_user_info_url
        .as_deref()
        .filter(|v| !v.is_empty());
    if issuer.is_none() && [auth, token, info].iter().any(Option::is_none) {
        return Err(configuration_error());
    }
    if let Some(auth) = auth {
        validate_url(auth)?;
        if auth.contains(['{', '}']) {
            return Err(configuration_error());
        }
    }
    if let Some(token) = token {
        validate_template(token, true)?;
        if is_template(token) && method.is_some_and(|m| m != "client_secret_post") {
            return Err(configuration_error());
        }
    }
    if let Some(info) = info {
        validate_template(info, false)?;
    }
    Ok(())
}
fn explicit(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}
pub async fn resolve_endpoints(
    provider: &Provider,
    allow_private: bool,
) -> AppResult<ResolvedOAuthEndpoints> {
    validate_endpoint_configuration(provider)?;
    let issuer = oidc_issuer(provider)?;
    let mut document = Value::Null;
    if let Some(issuer) = &issuer {
        let url = validate_url(&format!("{issuer}/.well-known/openid-configuration"))?;
        if url.scheme() == "http" && !(allow_private && loopback_url(&url)) {
            return Err(failed());
        }
        let client = system_gap_service::client(&url, allow_private)
            .await
            .map_err(|_| failed())?;
        let response = client
            .get(url)
            .headers(super::oauth_provider::oauth_headers(provider)?)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|_| failed())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(failed());
        }
        document = GenericOAuthProvider::json(response).await?;
        if document["issuer"].as_str() != Some(issuer.as_str()) {
            return Err(AppError::Authentication(
                "OIDC discovery issuer mismatch".into(),
            ));
        }
    }
    let endpoint = |explicit: Option<&str>, key: &str| -> AppResult<String> {
        if let Some(value) = explicit {
            return Ok(value.to_owned());
        }
        let value = document[key]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                AppError::Authentication(
                    "OIDC discovery requires authorization, token and UserInfo endpoints".into(),
                )
            })?;
        if value.contains(['{', '}']) {
            return Err(failed());
        }
        Ok(value.to_owned())
    };
    let methods: Vec<&str> = if issuer.is_some() {
        match document.get("token_endpoint_auth_methods_supported") {
            None => vec!["client_secret_basic"],
            Some(v) => v
                .as_array()
                .ok_or_else(failed)?
                .iter()
                .map(|v| v.as_str().ok_or_else(failed))
                .collect::<AppResult<_>>()?,
        }
    } else {
        vec!["client_secret_post", "client_secret_basic", "none"]
    };
    let client_auth = if let Some(configured) = configured_client_auth(provider)? {
        if !methods.contains(&configured) {
            return Err(failed());
        }
        configured
    } else if issuer.is_some() {
        ["client_secret_basic", "client_secret_post", "none"]
            .into_iter()
            .find(|m| methods.contains(m))
            .ok_or_else(failed)?
    } else {
        "client_secret_post"
    }
    .to_owned();
    if client_auth != "none" && provider.client_secret.as_deref().is_none_or(str::is_empty) {
        return Err(configuration_error());
    }
    let jwks_url = document
        .get("jwks_uri")
        .map(|v| {
            v.as_str()
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .ok_or_else(failed)
        })
        .transpose()?;
    let signing_algorithms = if jwks_url.is_some() {
        match document.get("id_token_signing_alg_values_supported") {
            None => vec!["RS256".into()],
            Some(v) => {
                let values = v
                    .as_array()
                    .filter(|v| !v.is_empty() && v.len() <= 32)
                    .ok_or_else(failed)?;
                let mut supported = Vec::new();
                for value in values {
                    let name = value.as_str().ok_or_else(failed)?;
                    if super::oidc_identity::supported_alg(name).is_some() {
                        supported.push(name.to_owned())
                    }
                }
                if supported.is_empty() {
                    return Err(failed());
                }
                supported
            }
        }
    } else {
        Vec::new()
    };
    let user_info_url = if explicit(&provider.custom_user_info_url).is_some()
        || document.get("userinfo_endpoint").is_some()
    {
        endpoint(
            explicit(&provider.custom_user_info_url),
            "userinfo_endpoint",
        )?
    } else if jwks_url.is_some() {
        String::new()
    } else {
        return Err(failed());
    };
    let result = ResolvedOAuthEndpoints {
        issuer,
        auth_url: endpoint(
            explicit(&provider.custom_auth_url),
            "authorization_endpoint",
        )?,
        token_url: endpoint(explicit(&provider.custom_token_url), "token_endpoint")?,
        user_info_url,
        jwks_url,
        signing_algorithms,
        client_auth,
        pkce_s256: document["code_challenge_methods_supported"]
            .as_array()
            .is_some_and(|v| v.iter().any(|v| v.as_str() == Some("S256")))
            || explicit(&provider.custom_token_url).is_some_and(|s| {
                placeholder_regex()
                    .captures_iter(s)
                    .any(|c| &c[1] == "codeVerifier")
            }),
    };
    validate_resolved(provider, &result)?;
    Ok(result)
}
pub fn validate_resolved(provider: &Provider, resolved: &ResolvedOAuthEndpoints) -> AppResult<()> {
    if resolved.issuer != oidc_issuer(provider)? {
        return Err(failed());
    }
    if !matches!(
        resolved.client_auth.as_str(),
        "client_secret_basic" | "client_secret_post" | "none"
    ) || configured_client_auth(provider)?.is_some_and(|v| v != resolved.client_auth)
        || (is_template(&resolved.token_url) && resolved.client_auth != "client_secret_post")
    {
        return Err(failed());
    }
    if resolved.jwks_url.is_some()
        && (resolved.issuer.is_none()
            || resolved.signing_algorithms.is_empty()
            || resolved
                .signing_algorithms
                .iter()
                .any(|a| super::oidc_identity::supported_alg(a).is_none()))
    {
        return Err(failed());
    }
    let header_origins = if let Some(issuer) = &resolved.issuer {
        let mut origins = vec![validate_url(issuer)?.origin()];
        for endpoint in [&provider.custom_token_url, &provider.custom_user_info_url]
            .into_iter()
            .flatten()
            .filter(|v| !v.is_empty())
        {
            origins.push(validate_url(endpoint)?.origin());
        }
        Some(origins)
    } else {
        None
    };
    for (configured, selected, token) in [
        (&provider.custom_auth_url, &resolved.auth_url, None),
        (&provider.custom_token_url, &resolved.token_url, Some(true)),
        (
            &provider.custom_user_info_url,
            &resolved.user_info_url,
            Some(false),
        ),
    ] {
        if explicit(configured).is_some_and(|v| v != selected) {
            return Err(failed());
        }
        if selected.is_empty() && token == Some(false) && resolved.jwks_url.is_some() {
            continue;
        }
        if let Some(token) = token {
            validate_template(selected, token)?;
            if !super::oauth_provider::oauth_headers(provider)?.is_empty()
                && header_origins.as_ref().is_some_and(|origins| {
                    validate_url(selected).is_ok_and(|url| !origins.contains(&url.origin()))
                })
            {
                return Err(failed());
            }
        } else {
            validate_url(selected)?;
            if selected.contains(['{', '}']) {
                return Err(failed());
            }
        }
        if let Some(issuer) = &resolved.issuer {
            let url = validate_url(selected)?;
            if url.scheme() != "https"
                && !(loopback_url(&url) && url.origin() == validate_url(issuer)?.origin())
            {
                return Err(failed());
            }
        }
    }
    if let Some(jwks) = &resolved.jwks_url {
        let url = validate_url(jwks)?;
        let issuer = validate_url(resolved.issuer.as_deref().ok_or_else(failed)?)?;
        if jwks.contains(['{', '}'])
            || (url.scheme() != "https" && !(loopback_url(&url) && url.origin() == issuer.origin()))
            || (!super::oauth_provider::oauth_headers(provider)?.is_empty()
                && url.origin() != issuer.origin())
        {
            return Err(failed());
        }
    }
    Ok(())
}
impl GenericOAuthProvider {
    pub fn from_resolved(
        provider: &Provider,
        endpoints: &ResolvedOAuthEndpoints,
        allow_private: bool,
    ) -> AppResult<Self> {
        validate_resolved(provider, endpoints)?;
        let mut value = Self::new(
            provider.provider_type.clone(),
            provider.client_id.clone().unwrap_or_default(),
            provider.client_secret.clone().unwrap_or_default(),
            endpoints.auth_url.clone(),
            endpoints.token_url.clone(),
            endpoints.user_info_url.clone(),
            provider
                .scopes
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "openid profile email".into()),
        )
        .with_configuration(
            super::oauth_provider::mapping(provider.user_mapping.as_deref())?,
            allow_private,
        );
        value.headers = super::oauth_provider::oauth_headers(provider)?;
        value.client_auth = endpoints.client_auth.clone();
        value.identity = endpoints.jwks_url.as_ref().map(|_| endpoints.clone());
        if let Some(issuer) = &endpoints.issuer {
            let mut origins = vec![validate_url(issuer)?.origin().ascii_serialization()];
            for endpoint in [&provider.custom_token_url, &provider.custom_user_info_url]
                .into_iter()
                .flatten()
                .filter(|v| !v.is_empty())
            {
                origins.push(validate_url(endpoint)?.origin().ascii_serialization());
            }
            value.private_origins = Some(origins);
        }
        Ok(value)
    }
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
            private_origins: None,
            headers: reqwest::header::HeaderMap::new(),
            identity: None,
            client_auth: default_post(),
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
        if value.len() > 65536 {
            return Err(failed());
        }
        let url = reqwest::Url::parse(value).map_err(|_| failed())?;
        let private = self.allow_private
            && self
                .private_origins
                .as_ref()
                .is_none_or(|origins| origins.contains(&url.origin().ascii_serialization()));
        let client = system_gap_service::client(&url, private)
            .await
            .map_err(|_| failed())?;
        Ok((url, client))
    }
    async fn json(response: reqwest::Response) -> AppResult<Value> {
        let bytes = system_gap_service::limited_bytes(response, 1024 * 1024)
            .await
            .map_err(|_| failed())?;
        let value = super::oidc_identity::strict_json(&bytes)?;
        if !value.is_object() || value.get("error").is_some() {
            return Err(failed());
        }
        Ok(value)
    }
    async fn exchange_token(
        &self,
        code: &str,
        redirect_uri: &str,
        context: &OAuthExchangeContext,
    ) -> AppResult<OAuthToken> {
        validate_template(&self.token_url, true)?;
        if code.is_empty() || code.len() > 8192 {
            return Err(failed());
        }
        let response = if is_template(&self.token_url) {
            let (endpoint, query) = self.token_url.split_once('?').ok_or_else(failed)?;
            let body = fill_template(
                query,
                |name| {
                    Ok(match name {
                        "clientId" => self.client_id.clone(),
                        "clientSecret" => self.client_secret.clone(),
                        "code" => code.to_owned(),
                        "redirectUri" => redirect_uri.to_owned(),
                        "state" => context.state.clone(),
                        "codeVerifier" => context.code_verifier.clone().ok_or_else(failed)?,
                        _ => return Err(failed()),
                    })
                },
                false,
            )?;
            let (url, client) = self.client(endpoint).await?;
            client
                .post(url)
                .headers(self.headers.clone())
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
                .map_err(|_| failed())?
        } else {
            let (url, client) = self.client(&self.token_url).await?;
            let mut fields = vec![
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ];
            if self.client_auth != "client_secret_basic" {
                fields.push(("client_id", self.client_id.as_str()))
            }
            if self.client_auth == "client_secret_post" {
                fields.push(("client_secret", self.client_secret.as_str()))
            }
            if let Some(verifier) = &context.code_verifier {
                fields.push(("code_verifier", verifier));
            }
            let request = client
                .post(url)
                .headers(self.headers.clone())
                .header("Accept", "application/json");
            let request = if self.client_auth == "client_secret_basic" {
                request.basic_auth(
                    form_component(&self.client_id),
                    Some(form_component(&self.client_secret)),
                )
            } else {
                request
            };
            request.form(&fields).send().await.map_err(|_| failed())?
        };
        let extra = Self::json(response).await?;
        if extra["token_type"]
            .as_str()
            .is_some_and(|v| !v.eq_ignore_ascii_case("bearer"))
        {
            return Err(failed());
        }
        let access_token = extra["access_token"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 16384 && !v.chars().any(char::is_control))
            .or_else(|| {
                (self.identity.is_some()
                    && self.user_info_url.is_empty()
                    && extra["id_token"].is_string())
                .then_some("")
            })
            .ok_or_else(failed)?
            .to_owned();
        Ok(OAuthToken {
            access_token,
            extra,
        })
    }
    async fn checked_identity(
        &self,
        token: &OAuthToken,
        context: &OAuthExchangeContext,
    ) -> AppResult<Option<Value>> {
        if let Some(identity) = &self.identity {
            let raw = token.extra["id_token"].as_str().ok_or_else(failed)?;
            if raw.len() > 65536 {
                return Err(failed());
            }
            let (url, client) = self
                .client(identity.jwks_url.as_deref().ok_or_else(failed)?)
                .await?;
            let response = client
                .get(url)
                .headers(self.headers.clone())
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|_| failed())?;
            let jwks = Self::json(response).await?;
            Ok(Some(super::oidc_identity::verify(
                raw,
                &jwks,
                identity.issuer.as_deref().ok_or_else(failed)?,
                &self.client_id,
                context.nonce.as_deref().ok_or_else(failed)?,
                context.started_at.ok_or_else(failed)?,
                &identity.signing_algorithms,
                &token.access_token,
            )?))
        } else {
            Ok(None)
        }
    }
    async fn user_info(
        &self,
        token: &OAuthToken,
        context: &OAuthExchangeContext,
        identity: Option<Value>,
    ) -> AppResult<ProviderUserInfo> {
        if self.identity.is_some() && identity.is_none() {
            return Err(failed());
        }
        if self.user_info_url.is_empty() {
            return map_user_info(
                identity.as_ref().ok_or_else(failed)?,
                &self.user_mapping,
                &self.provider_type_name,
            );
        }
        if token.access_token.is_empty()
            || token.access_token.len() > 16384
            || token.access_token.chars().any(char::is_control)
        {
            return Err(failed());
        }
        validate_template(&self.user_info_url, false)?;
        let template = is_template(&self.user_info_url);
        let target = if template {
            fill_template(
                &self.user_info_url,
                |name| match name {
                    "clientId" => Ok(self.client_id.clone()),
                    "state" => Ok(context.state.clone()),
                    "access_token" => Ok(token.access_token.clone()),
                    _ => match token.extra.get(name) {
                        Some(Value::String(v)) => Ok(v.clone()),
                        Some(Value::Number(v)) if v.is_i64() || v.is_u64() => Ok(v.to_string()),
                        Some(Value::Bool(v)) => Ok(v.to_string()),
                        _ => Err(failed()),
                    },
                },
                true,
            )?
        } else {
            self.user_info_url.clone()
        };
        let (url, client) = self.client(&target).await?;
        let request = client
            .get(url)
            .headers(self.headers.clone())
            .header("Accept", "application/json");
        // Custom template protocols explicitly carry their credential fields;
        // ordinary OAuth/OIDC UserInfo uses the standard Bearer header.
        let request = if template {
            request
        } else {
            request.bearer_auth(&token.access_token)
        };
        let response = request.send().await.map_err(|_| failed())?;
        let mut claims = Self::json(response).await?;
        if let Some(mut identity) = identity {
            if claims["sub"].as_str() != identity["sub"].as_str() {
                return Err(failed());
            }
            let target = identity.as_object_mut().ok_or_else(failed)?;
            for (key, value) in claims.as_object().ok_or_else(failed)? {
                target.insert(key.clone(), value.clone());
            }
            claims = identity;
        }
        map_user_info(&claims, &self.user_mapping, &self.provider_type_name)
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
        Ok(self
            .exchange_token(code, redirect_uri, &OAuthExchangeContext::default())
            .await?
            .access_token)
    }
    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        self.user_info(
            &OAuthToken {
                access_token: access_token.to_owned(),
                extra: serde_json::json!({"access_token":access_token}),
            },
            &OAuthExchangeContext::default(),
            None,
        )
        .await
    }
    async fn exchange_code_token(
        &self,
        code: &str,
        redirect: &str,
        context: &OAuthExchangeContext,
    ) -> AppResult<OAuthToken> {
        self.exchange_token(code, redirect, context).await
    }
    async fn get_user_info_token(
        &self,
        token: &OAuthToken,
        context: &OAuthExchangeContext,
    ) -> AppResult<ProviderUserInfo> {
        let identity = self.checked_identity(token, context).await?;
        self.user_info(token, context, identity).await
    }
    async fn verify_identity(
        &self,
        token: &OAuthToken,
        context: &OAuthExchangeContext,
    ) -> AppResult<Option<Value>> {
        self.checked_identity(token, context).await
    }
    async fn get_user_info_verified(
        &self,
        token: &OAuthToken,
        context: &OAuthExchangeContext,
        identity: Option<Value>,
    ) -> AppResult<ProviderUserInfo> {
        self.user_info(token, context, identity).await
    }
    fn provider_type(&self) -> &str {
        &self.provider_type_name
    }
}
