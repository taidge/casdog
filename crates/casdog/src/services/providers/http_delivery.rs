//! Explicit Casdoor Custom HTTP protocols, with the preexisting JSON protocol
//! retained only when method is empty. Provider data never bypasses DNS policy.
use crate::{
    error::{AppError, AppResult},
    models::Provider,
};
use reqwest::{
    Method, Url,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

const RESPONSE_LIMIT: usize = 64 * 1024;
fn invalid(message: &str) -> AppError {
    AppError::Validation(message.into())
}
fn normalized(provider: &Provider) -> String {
    provider
        .provider_type
        .to_ascii_lowercase()
        .replace([' ', '-', '_'], "")
}
pub fn is_custom_http(provider: &Provider) -> bool {
    match provider.category.to_ascii_lowercase().as_str() {
        "email" | "notification" => normalized(provider).starts_with("customhttp"),
        // Preserve the existing generic SMS fallback without leaving a second,
        // ungoverned Client::new path for arbitrary type labels.
        "sms" => {
            !normalized(provider).contains("twilio")
                && [
                    provider.endpoint.as_deref(),
                    provider.provider_url.as_deref(),
                ]
                .into_iter()
                .flatten()
                .any(|url| !url.is_empty())
        }
        _ => false,
    }
}
pub fn notification_endpoint(provider: &Provider) -> AppResult<&str> {
    [
        provider.endpoint.as_deref(),
        provider.provider_url.as_deref(),
        provider.client_id.as_deref(),
        provider.receiver.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|s| !s.is_empty())
    .ok_or_else(|| invalid("Custom HTTP notification requires a target URL"))
}
pub fn notification_receiver_is_endpoint(provider: &Provider) -> bool {
    [
        provider.endpoint.as_deref(),
        provider.provider_url.as_deref(),
        provider.client_id.as_deref(),
    ]
    .iter()
    .all(|v| v.is_none_or(str::is_empty))
}
fn endpoint(provider: &Provider) -> AppResult<&str> {
    if provider.category.eq_ignore_ascii_case("Notification") {
        return notification_endpoint(provider);
    }
    [
        provider.endpoint.as_deref(),
        provider.provider_url.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|s| !s.is_empty())
    .ok_or_else(|| invalid("Custom HTTP provider requires an endpoint URL"))
}
fn object_mapping(provider: &Provider) -> AppResult<BTreeMap<String, String>> {
    let mapping = provider
        .user_mapping
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(s).map_err(|_| invalid("Invalid HTTP body mapping")))
        .transpose()?
        .unwrap_or_default();
    Ok(mapping)
}
fn add_header(headers: &mut HeaderMap, name: &str, value: &str) -> AppResult<()> {
    if name.len() > 256
        || value.len() > 16384
        || matches!(
            name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection" | "proxy-authorization"
        )
    {
        return Err(invalid("Unsupported HTTP delivery header"));
    }
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| invalid("Invalid HTTP delivery header name"))?;
    let value =
        HeaderValue::from_str(value).map_err(|_| invalid("Invalid HTTP delivery header value"))?;
    headers.insert(name, value);
    Ok(())
}
fn headers(provider: &Provider) -> AppResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    if provider.category == "Notification" {
        if let Some(raw) = provider
            .client_secret2
            .as_deref()
            .or(provider.metadata.as_deref())
            .filter(|s| !s.is_empty())
        {
            let pairs: Vec<(String, String)> = serde_json::from_str(raw).map_err(|_| {
                invalid("Notification header configuration must contain name/value pairs")
            })?;
            if pairs.len() > 64 {
                return Err(invalid("Too many HTTP delivery headers"));
            }
            let mut seen = HashSet::new();
            for (name, value) in pairs {
                if !seen.insert(name.to_ascii_lowercase()) {
                    return Err(invalid("Duplicate legacy delivery header"));
                }
                add_header(&mut headers, &name, &value)?;
            }
        }
    }
    if let Some(raw) = provider.http_headers.as_deref().filter(|s| !s.is_empty()) {
        let fields: BTreeMap<String, String> =
            serde_json::from_str(raw).map_err(|_| invalid("HTTP headers must be a JSON object"))?;
        let mut seen = HashSet::new();
        for (name, value) in fields {
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err(invalid("Duplicate HTTP delivery header"));
            }
            add_header(&mut headers, &name, &value)?;
        }
    }
    if let Some(secret) = provider.client_secret.as_deref().filter(|s| !s.is_empty()) {
        let bearer = format!("Bearer {secret}");
        if headers
            .get(AUTHORIZATION)
            .is_some_and(|old| old.as_bytes() != bearer.as_bytes())
        {
            return Err(invalid(
                "HTTP Authorization conflicts with the configured bearer secret",
            ));
        }
        add_header(&mut headers, "Authorization", &bearer)?;
    }
    if headers.len() > 64 {
        return Err(invalid("Too many HTTP delivery headers"));
    }
    Ok(headers)
}
fn parsed_url(value: &str) -> AppResult<Url> {
    if value.len() > 16384 || value.chars().any(char::is_control) {
        return Err(invalid("Invalid HTTP delivery URL"));
    }
    let url = Url::parse(value).map_err(|_| invalid("Invalid HTTP delivery URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "HTTP delivery requires an HTTP(S) URL without credentials or fragment",
        ));
    }
    Ok(url)
}
fn media(value: &str) -> AppResult<&'static str> {
    if value.split(';').skip(1).any(|parameter| {
        !parameter
            .trim()
            .replace(' ', "")
            .eq_ignore_ascii_case("charset=utf-8")
    }) {
        return Err(invalid(
            "HTTP delivery supports only UTF-8 content encoding",
        ));
    }
    match value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "application/json" => Ok("application/json"),
        "application/x-www-form-urlencoded" => Ok("application/x-www-form-urlencoded"),
        _ => Err(invalid(
            "HTTP delivery content type must be JSON or form-urlencoded",
        )),
    }
}
pub fn validate_record(provider: &Provider) -> AppResult<()> {
    if !is_custom_http(provider) {
        return Ok(());
    }
    HttpDelivery::from_record(provider, false).map(|_| ())
}
pub async fn current_private_access(pool: &sqlx::PgPool, record: &Provider) -> AppResult<bool> {
    let mut tx = pool.begin().await?;
    let current: Provider = sqlx::query_as("SELECT * FROM providers WHERE id=$1 FOR SHARE")
        .bind(&record.id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            AppError::Authorization("Delivery provider is no longer available".into())
        })?;
    if crate::services::provider_network_service::configuration_stamp(&current)
        != crate::services::provider_network_service::configuration_stamp(record)
    {
        return Err(AppError::Authorization(
            "Delivery provider configuration changed; resolve it again".into(),
        ));
    }
    let allowed =
        crate::services::provider_network_service::allowed_conn(&mut tx, &current).await?;
    tx.commit().await?;
    Ok(allowed)
}

pub struct HttpDelivery {
    record: Provider,
    method: Method,
    explicit: bool,
    json: bool,
    headers: HeaderMap,
    mapping: BTreeMap<String, String>,
    allow_private: bool,
    pool: Option<sqlx::PgPool>,
}
impl HttpDelivery {
    pub fn legacy(
        category: &str,
        url: &str,
        api_key: Option<&str>,
        extra_headers: Option<&str>,
        allow_private: bool,
    ) -> AppResult<Self> {
        let now = chrono::Utc::now();
        let record:Provider=serde_json::from_value(json!({"id":"standalone-http","owner":"standalone","name":"standalone-http","display_name":"HTTP delivery","created_at":now,"updated_at":now,"category":category,"type":"Custom HTTP","disable_ssl":false,"enable_sign_authn_request":false,"endpoint":url,"client_secret":api_key,"client_secret2":extra_headers}))
            .map_err(|_|invalid("Invalid standalone HTTP delivery configuration"))?;
        Self::from_record(&record, allow_private)
    }
    pub fn from_record(provider: &Provider, allow_private: bool) -> AppResult<Self> {
        let saved_record = provider.clone();
        let mut canonical = provider.clone();
        canonical.category = match provider.category.to_ascii_lowercase().as_str() {
            "email" => "Email",
            "sms" => "SMS",
            "notification" => "Notification",
            _ => return Err(invalid("Unsupported HTTP delivery category")),
        }
        .into();
        let provider = &canonical;
        let raw_method = provider.method.as_deref().unwrap_or("").trim();
        let explicit = !raw_method.is_empty();
        let method = if explicit {
            Method::from_bytes(raw_method.to_ascii_uppercase().as_bytes())
                .map_err(|_| invalid("Invalid HTTP delivery method"))?
        } else {
            Method::POST
        };
        if !matches!(
            method,
            Method::GET | Method::POST | Method::PUT | Method::DELETE
        ) || provider.category == "Notification" && !matches!(method, Method::GET | Method::POST)
        {
            return Err(invalid("Unsupported Custom HTTP method"));
        }
        let mapping = object_mapping(provider)?;
        let allowed: &[&str] = match provider.category.as_str() {
            "Email" => &[
                "fromAddress",
                "fromName",
                "toAddress",
                "toAddresses",
                "subject",
                "content",
            ],
            "SMS" => &["phoneNumber", "content"],
            "Notification" => &[],
            _ => return Err(invalid("Unsupported HTTP delivery category")),
        };
        if mapping.keys().any(|key| !allowed.contains(&key.as_str()))
            || mapping.values().any(|value| {
                value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
            })
        {
            return Err(invalid("Invalid Custom HTTP output mapping"));
        }
        if !explicit && !mapping.is_empty() {
            return Err(invalid(
                "Set an explicit method before configuring HTTP body mappings",
            ));
        }
        let mut effective = allowed
            .iter()
            .map(|source| {
                mapping
                    .get(*source)
                    .map_or((*source).to_string(), Clone::clone)
            })
            .collect::<Vec<_>>();
        if explicit && provider.category == "SMS" {
            effective[1] = provider
                .title
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(mapping.get("content").map(String::as_str))
                .ok_or_else(|| invalid("Custom HTTP SMS requires Title or a content mapping"))?
                .into();
        }
        if effective.iter().collect::<HashSet<_>>().len() != effective.len() {
            return Err(invalid(
                "Custom HTTP effective output fields must be unique",
            ));
        }
        if effective
            .iter()
            .any(|name| name.is_empty() || name.len() > 128 || name.chars().any(char::is_control))
        {
            return Err(invalid("Invalid Custom HTTP effective field name"));
        }
        if explicit
            && provider.category == "Notification"
            && provider.title.as_deref().is_none_or(|s| {
                s.is_empty() || s.len() > 128 || s.chars().any(char::is_control) || s == "recipient"
            })
        {
            return Err(invalid(
                "Notification Title must name a unique content parameter",
            ));
        }
        if !explicit
            && provider.category == "Notification"
            && provider.title.as_deref().is_some_and(|s| !s.is_empty())
        {
            return Err(invalid(
                "Set an explicit method before configuring a notification parameter name",
            ));
        }
        let template = endpoint(provider)?;
        if provider.category == "SMS" {
            let authority = template
                .split_once("://")
                .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(rest))
                .unwrap_or("");
            if authority.contains('{') || authority.contains('}') {
                return Err(invalid(
                    "SMS endpoint substitutions are limited to the path and query",
                ));
            }
            if explicit {
                if let Some(template) = provider.template_code.as_deref().filter(|s| !s.is_empty())
                {
                    if template.matches("%s").count() != 1
                        || template.replace("%s", "").contains('%')
                    {
                        return Err(invalid(
                            "SMS template must contain exactly one %s placeholder",
                        ));
                    }
                }
            }
        }
        parsed_url(
            &template
                .replace("{mobile}", "recipient")
                .replace("{code}", "code"),
        )?;
        let mut headers = headers(provider)?;
        let configured = provider.issuer_url.as_deref().filter(|s| !s.is_empty());
        let supplied = headers
            .get(CONTENT_TYPE)
            .map(|v| {
                v.to_str()
                    .map_err(|_| invalid("Invalid delivery Content-Type"))
            })
            .transpose()?;
        let default = if !explicit {
            "application/json"
        } else {
            "application/x-www-form-urlencoded"
        };
        let content_type = configured.or(supplied).unwrap_or(default).to_string();
        let encoding = media(&content_type)?;
        if supplied.is_some_and(|v| media(v).ok() != Some(encoding)) {
            return Err(invalid(
                "HTTP Content-Type conflicts with the configured encoding",
            ));
        }
        if !explicit && encoding != "application/json"
            || explicit
                && provider.category == "Notification"
                && encoding != "application/x-www-form-urlencoded"
        {
            return Err(invalid(
                "HTTP content type does not match the selected protocol",
            ));
        }
        let json = encoding == "application/json";
        if method != Method::GET || supplied.is_some() || configured.is_some() {
            add_header(&mut headers, "Content-Type", &content_type)?;
        }
        Ok(Self {
            record: saved_record,
            method,
            explicit,
            json,
            headers,
            mapping,
            allow_private,
            pool: None,
        })
    }
    pub fn with_pool(mut self, pool: sqlx::PgPool) -> Self {
        self.pool = Some(pool);
        self
    }
    pub fn explicit(&self) -> bool {
        self.explicit
    }
    fn name(&self, source: &str) -> String {
        self.mapping
            .get(source)
            .cloned()
            .unwrap_or_else(|| source.into())
    }
    async fn send(
        &self,
        mut url: Url,
        fields: Vec<(String, Value)>,
        omit_get_fields: bool,
    ) -> AppResult<()> {
        let as_form = || -> Vec<(String, String)> {
            fields
                .iter()
                .flat_map(|(key, value)| match value {
                    Value::Array(items) => items
                        .iter()
                        .map(|v| (key.clone(), v.as_str().unwrap_or_default().to_string()))
                        .collect(),
                    _ => vec![(
                        key.clone(),
                        value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_string),
                    )],
                })
                .collect()
        };
        if self.method == Method::GET && !omit_get_fields {
            url.query_pairs_mut().extend_pairs(as_form());
        }
        if url.as_str().len() > 16384 {
            return Err(invalid("HTTP delivery URL exceeds the request limit"));
        }
        let allow_private = if let Some(pool) = &self.pool {
            current_private_access(pool, &self.record).await?
        } else {
            self.allow_private
        };
        let client = crate::services::system_gap_service::client(&url, allow_private)
            .await
            .map_err(|error| match error {
                AppError::Authorization(_) => error,
                _ => AppError::Internal("HTTP delivery endpoint unavailable".into()),
            })?;
        let mut request = client
            .request(self.method.clone(), url)
            .headers(self.headers.clone());
        if self.method != Method::GET {
            let body = if self.json {
                Value::Object(fields.iter().cloned().collect()).to_string()
            } else {
                let mut encoder = Url::parse("http://form.invalid").expect("static URL");
                encoder.query_pairs_mut().extend_pairs(as_form());
                encoder.query().unwrap_or_default().to_string()
            };
            if body.len() > 1024 * 1024 {
                return Err(invalid("HTTP delivery body exceeds 1 MiB"));
            }
            request = request.body(body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| AppError::Internal("HTTP delivery request failed".into()))?;
        if !response.status().is_success()
            || self.explicit && response.status() != reqwest::StatusCode::OK
        {
            return Err(AppError::Internal(format!(
                "HTTP delivery returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let mut length = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AppError::Internal("HTTP delivery response interrupted".into()))?
        {
            length += chunk.len();
            if length > RESPONSE_LIMIT {
                return Err(AppError::Internal(
                    "HTTP delivery response exceeds 64 KiB".into(),
                ));
            }
        }
        Ok(())
    }
    pub async fn email(
        &self,
        to: &[String],
        subject: &str,
        body: &str,
        sender_name: Option<&str>,
    ) -> AppResult<()> {
        if !self.explicit {
            for address in to {
                self.send(
                    parsed_url(endpoint(&self.record)?)?,
                    vec![
                        ("to".into(), json!(address)),
                        ("subject".into(), json!(subject)),
                        ("body".into(), json!(body)),
                        ("timestamp".into(), json!(chrono::Utc::now().to_rfc3339())),
                    ],
                    false,
                )
                .await?;
            }
            return Ok(());
        }
        let address = self
            .record
            .client_id2
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(self.record.client_id.as_deref())
            .unwrap_or("");
        let name = self
            .record
            .client_secret2
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(sender_name)
            .unwrap_or("");
        let mut fields = vec![
            (self.name("fromAddress"), json!(address)),
            (self.name("fromName"), json!(name)),
            (self.name("subject"), json!(subject)),
            (self.name("content"), json!(body)),
        ];
        if to.len() == 1 {
            fields.push((self.name("toAddress"), json!(&to[0])));
        } else {
            fields.push((self.name("toAddresses"), json!(to)));
        }
        self.send(parsed_url(endpoint(&self.record)?)?, fields, false)
            .await
    }
    pub async fn notification(&self, title: &str, content: &str, receiver: &str) -> AppResult<()> {
        let fields = if self.explicit {
            let mut fields = vec![(
                self.record.title.clone().unwrap_or_default(),
                json!(content),
            )];
            if !receiver.is_empty() {
                fields.push(("recipient".into(), json!(receiver)));
            }
            fields
        } else {
            vec![
                ("title".into(), json!(title)),
                ("content".into(), json!(content)),
                ("receiver".into(), json!(receiver)),
                ("timestamp".into(), json!(chrono::Utc::now().timestamp())),
            ]
        };
        self.send(parsed_url(endpoint(&self.record)?)?, fields, false)
            .await
    }
    pub async fn sms(&self, to: &str, code: &str) -> AppResult<()> {
        if !self.explicit {
            let from = self
                .record
                .app_id
                .as_deref()
                .or(self.record.sign_name.as_deref())
                .or(self.record.receiver.as_deref())
                .unwrap_or("");
            return self
                .send(
                    parsed_url(endpoint(&self.record)?)?,
                    vec![
                        ("to".into(), json!(to)),
                        ("from".into(), json!(from)),
                        ("body".into(), json!(code)),
                    ],
                    false,
                )
                .await;
        }
        let template = endpoint(&self.record)?;
        let omit = template.contains("{mobile}") || template.contains("{code}");
        let url = template
            .replace("{mobile}", &super::storage_provider::encode_component(to))
            .replace("{code}", &super::storage_provider::encode_component(code));
        let body = self
            .record
            .template_code
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("%s")
            .replacen("%s", code, 1);
        let name = self
            .record
            .title
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| self.name("content"));
        self.send(
            parsed_url(&url)?,
            vec![(self.name("phoneNumber"), json!(to)), (name, json!(body))],
            omit,
        )
        .await
    }
}

pub struct CustomHttpSmsProvider {
    delivery: HttpDelivery,
}
impl CustomHttpSmsProvider {
    pub fn with_pool(mut self, pool: sqlx::PgPool) -> Self {
        self.delivery = self.delivery.with_pool(pool);
        self
    }
    pub fn from_record(record: &Provider, allow_private: bool) -> AppResult<Self> {
        Ok(Self {
            delivery: HttpDelivery::from_record(record, allow_private)?,
        })
    }
}
#[async_trait::async_trait]
impl super::sms_provider::SmsProviderTrait for CustomHttpSmsProvider {
    async fn send_sms(&self, to: &str, content: &str) -> AppResult<()> {
        self.delivery.sms(to, content).await
    }
}
