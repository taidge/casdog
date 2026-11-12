//! Shared native/compatibility Provider configuration policy. Masked values are
//! references to the currently locked row, never new credentials.
use crate::{
    error::{AppError, AppResult},
    models::Provider,
};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashSet};

fn invalid(message: &str) -> AppError {
    AppError::Validation(message.into())
}
pub fn deserialize_json_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(value.map(|value| match value {
        Value::String(text) => text,
        other => other.to_string(),
    }))
}
fn kind(object: &Map<String, Value>) -> String {
    object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase()
        .replace([' ', '-', '_'], "")
}
fn secret_fields(object: &Map<String, Value>) -> Vec<&'static str> {
    let mut fields = vec!["client_secret"];
    if object.get("category").and_then(Value::as_str) != Some("Email") {
        fields.push("client_secret2");
    }
    if kind(object) == "wechat" {
        fields.push("content");
    }
    let configured = |key: &str| object.get(key).is_some_and(|value| !value.is_null());
    if object.get("category").and_then(Value::as_str) == Some("Email")
        && kind(object).contains("sendgrid")
        && !configured("client_secret")
    {
        fields.push("client_id");
    }
    if object.get("category").and_then(Value::as_str) == Some("Notification") {
        let provider_kind = kind(object);
        if provider_kind == "telegram" {
            if !configured("client_secret") {
                fields.push("client_id");
            }
        } else if matches!(
            provider_kind.as_str(),
            "slack" | "discord" | "dingtalk" | "lark" | "teams"
        ) {
            if let Some(field) = ["endpoint", "provider_url", "client_id"]
                .into_iter()
                .find(|field| configured(field))
            {
                fields.push(field);
            }
        } else if provider_kind.starts_with("customhttp")
            && !configured("endpoint")
            && !configured("provider_url")
        {
            fields.push("client_id");
        }
    }
    fields
}
fn mask(raw: &Value) -> Value {
    if raw.as_str().is_some_and(|s| !s.is_empty()) {
        json!("***")
    } else {
        raw.clone()
    }
}
fn metadata_public(object: &Map<String, Value>, key: &str) -> bool {
    match object.get("category").and_then(Value::as_str) {
        Some("Storage") => {
            matches!(kind(object).as_str(), "azureblob" | "googlecloudstorage")
                && key == "storageApiEndpoint"
        }
        Some("LDAP") => matches!(
            key,
            "base_dn" | "baseDn" | "filter" | "search_filter" | "ssl_mode"
        ),
        _ => false,
    }
}
fn payment_key(object: &Map<String, Value>, key: &str) -> bool {
    match kind(object).as_str() {
        "stripe" => matches!(
            key,
            "webhookSecret" | "webhook_secret" | "signingSecret" | "signing_secret"
        ),
        "paypal" => matches!(key, "webhookId" | "webhook_id"),
        _ => false,
    }
}
fn canonical_metadata(object: &Map<String, Value>, value: &mut Value) -> AppResult<()> {
    let Some(fields) = value.as_object_mut() else {
        return Ok(());
    };
    let aliases: &[&str] = match kind(object).as_str() {
        "stripe" => &[
            "webhook_secret",
            "webhookSecret",
            "signing_secret",
            "signingSecret",
        ],
        "paypal" => &["webhook_id", "webhookId"],
        _ => &[],
    };
    let mut found = None;
    for alias in aliases {
        if let Some(value) = fields.remove(*alias) {
            if found.as_ref().is_some_and(|old| old != &value) {
                return Err(invalid("Conflicting provider metadata aliases"));
            }
            found = Some(value);
        }
    }
    if let (Some(canonical), Some(value)) = (aliases.first(), found) {
        fields.insert((*canonical).into(), value);
    }
    Ok(())
}
fn header_pairs(raw: &str) -> AppResult<Vec<(String, String)>> {
    let pairs: Vec<(String, String)> = serde_json::from_str(raw)
        .map_err(|_| invalid("Notification headers must be JSON [name,value] pairs"))?;
    if pairs.len() > 64 {
        return Err(invalid("Too many notification headers"));
    }
    let mut names = HashSet::new();
    for (name, value) in &pairs {
        if name.len() > 256
            || value.len() > 16384
            || reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            || reqwest::header::HeaderValue::from_str(value).is_err()
            || !names.insert(name.to_ascii_lowercase())
        {
            return Err(invalid("Invalid or duplicate notification header"));
        }
    }
    Ok(pairs)
}
fn project_metadata(object: &Map<String, Value>, raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    if let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(raw) {
        let visible: Map<String, Value> = fields
            .into_iter()
            .filter_map(|(key, value)| {
                if metadata_public(object, &key) {
                    Some((key, value))
                } else if payment_key(object, &key) {
                    Some((key, mask(&value)))
                } else {
                    None
                }
            })
            .collect();
        if !visible.is_empty() {
            return Value::Object(visible).to_string();
        }
    }
    if object.get("category").and_then(Value::as_str) == Some("Notification")
        && kind(object).starts_with("customhttp")
    {
        if let Ok(pairs) = header_pairs(raw) {
            return json!(
                pairs
                    .into_iter()
                    .map(|(name, value)| (
                        name,
                        if value.is_empty() {
                            value
                        } else {
                            "***".into()
                        }
                    ))
                    .collect::<Vec<_>>()
            )
            .to_string();
        }
    }
    "***".into()
}

/// Receives snake_case DB/native JSON. Legacy camelCase conversion happens
/// after this policy; arbitrary unknown metadata is never assumed public.
pub fn project(mut value: Value) -> Value {
    if let Value::Array(items) = &mut value {
        for item in items {
            *item = project(item.take());
        }
        return value;
    }
    let Some(object) = value.as_object_mut() else {
        return value;
    };
    for field in secret_fields(object) {
        if let Some(raw) = object.get_mut(field) {
            *raw = mask(raw);
        }
    }
    if let Some(Value::String(raw)) = object.get("metadata") {
        object.insert("metadata".into(), json!(project_metadata(object, raw)));
    }
    if let Some(Value::String(raw)) = object.get("http_headers") {
        if raw.is_empty() {
            object.insert("http_headers".into(), json!({}));
        } else {
            let masked = serde_json::from_str::<BTreeMap<String, String>>(raw)
                .ok()
                .map(|fields| {
                    fields
                        .into_iter()
                        .map(|(k, v)| (k, if v.is_empty() { v } else { "***".into() }))
                        .collect::<BTreeMap<_, _>>()
                });
            object.insert(
                "http_headers".into(),
                masked.map_or_else(|| json!("***"), |v| json!(v)),
            );
        }
    }
    if let Some(Value::String(raw)) = object.get("user_mapping") {
        object.insert(
            "user_mapping".into(),
            if raw.is_empty() {
                json!({})
            } else {
                serde_json::from_str(raw).unwrap_or_else(|_| json!(raw))
            },
        );
    }
    value
}

fn original<'a>(old: Option<&'a Value>) -> AppResult<&'a Value> {
    old.filter(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.is_empty() && s != "***"))
        .ok_or_else(|| invalid("Masked configuration has no saved original value"))
}
fn contains_marker(value: &Value) -> bool {
    match value {
        Value::String(s) => s == "***",
        Value::Array(a) => a.iter().any(contains_marker),
        Value::Object(m) => m.values().any(contains_marker),
        _ => false,
    }
}
fn merge_json(old: Option<&Value>, patch: Value) -> AppResult<Value> {
    if patch.as_str() == Some("***") {
        return Ok(original(old)?.clone());
    }
    match patch {
        Value::Object(fields) => {
            let mut result = old.and_then(Value::as_object).cloned().unwrap_or_default();
            for (key, value) in fields {
                let merged = merge_json(result.get(&key), value)?;
                result.insert(key, merged);
            }
            Ok(Value::Object(result))
        }
        Value::Array(items) => {
            // Configuration arrays containing a marker must retain a complete
            // original array; headers have their own name-based merger below.
            if items.iter().any(contains_marker) {
                return Err(invalid(
                    "Masked arrays require a supported header configuration",
                ));
            }
            Ok(Value::Array(items))
        }
        other => Ok(other),
    }
}
fn merge_pairs(old: Option<&str>, patch: &str) -> AppResult<String> {
    let old = old
        .and_then(|s| header_pairs(s).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect::<BTreeMap<_, _>>();
    let mut pairs = header_pairs(patch)?;
    for (name, value) in &mut pairs {
        if value == "***" {
            *value = original(
                old.get(&name.to_ascii_lowercase())
                    .map(|s| json!(s))
                    .as_ref(),
            )?
            .as_str()
            .unwrap_or_default()
            .to_string();
        }
    }
    Ok(json!(pairs).to_string())
}

/// Merge only after acquiring the provider row FOR UPDATE. Omitted/null fields
/// preserve current data; an explicit empty string clears a text credential.
pub fn prepare_patch(current: Option<&Provider>, patch: &mut Map<String, Value>) -> AppResult<()> {
    patch.retain(|_, v| !v.is_null());
    let old = current.map(|p| serde_json::to_value(p).expect("Provider JSON"));
    let mut target = old
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    target.extend(patch.clone());
    let descriptor_changed = old
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|before| {
            before.get("category") != target.get("category") || kind(before) != kind(&target)
        });
    if let Some(before) = old.as_ref().and_then(Value::as_object) {
        for field in secret_fields(before) {
            if !secret_fields(&target).contains(&field)
                && before
                    .get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
                && patch
                    .get(field)
                    .and_then(Value::as_str)
                    .is_none_or(|s| s == "***")
            {
                return Err(invalid(
                    "Changing provider type/category requires explicitly replacing or clearing fields that would become public",
                ));
            }
        }
        if descriptor_changed
            && before
                .get("metadata")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            && patch
                .get("metadata")
                .is_none_or(|value| value.as_str() == Some("***"))
        {
            return Err(invalid(
                "Changing provider type/category requires explicitly replacing or clearing metadata",
            ));
        }
    }
    for field in secret_fields(&target) {
        if patch.get(field).and_then(Value::as_str) == Some("***") {
            patch.insert(
                field.into(),
                original(old.as_ref().and_then(|o| o.get(field)))?.clone(),
            );
        }
    }
    for field in ["user_mapping", "http_headers"] {
        if let Some(value) = patch.get(field).cloned() {
            let raw = match value {
                Value::String(s) => s,
                other => other.to_string(),
            };
            if raw.is_empty() {
                patch.insert(field.into(), json!(""));
                continue;
            }
            if field == "http_headers" && raw == "***" {
                patch.insert(
                    field.into(),
                    original(old.as_ref().and_then(|o| o.get(field)))?.clone(),
                );
                continue;
            }
            let mut parsed: Value = if raw.is_empty() {
                json!({})
            } else {
                serde_json::from_str(&raw).map_err(|_| {
                    invalid("Provider mapping/header configuration must be a JSON object")
                })?
            };
            if !parsed.is_object() {
                return Err(invalid(
                    "Provider mapping/header configuration must be a JSON object",
                ));
            }
            if field == "http_headers" {
                let previous = old
                    .as_ref()
                    .and_then(|o| o[field].as_str())
                    .and_then(|s| serde_json::from_str::<Value>(s).ok());
                let mut merged = previous
                    .as_ref()
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                for (key, value) in parsed.as_object().expect("validated object") {
                    let existing = merged
                        .keys()
                        .find(|old| old.eq_ignore_ascii_case(key))
                        .cloned();
                    let replacement = if value.as_str() == Some("***") {
                        original(existing.as_ref().and_then(|name| merged.get(name)))?.clone()
                    } else {
                        value.clone()
                    };
                    if let Some(existing) = existing {
                        merged.remove(&existing);
                    }
                    merged.insert(key.clone(), replacement);
                }
                parsed = Value::Object(merged);
                let fields: BTreeMap<String, String> = serde_json::from_value(parsed.clone())
                    .map_err(|_| invalid("Provider header values must be strings"))?;
                header_pairs(&json!(fields.into_iter().collect::<Vec<_>>()).to_string())?;
            } else {
                validate_mapping(&parsed)?;
            }
            patch.insert(field.into(), json!(parsed.to_string()));
        }
    }
    if let Some(value) = patch.get("metadata").cloned() {
        let raw = match value {
            Value::String(s) => s,
            other => other.to_string(),
        };
        let previous = if descriptor_changed {
            None
        } else {
            old.as_ref().and_then(|o| o["metadata"].as_str())
        };
        let merged = if raw == "***" {
            original(old.as_ref().and_then(|o| o.get("metadata")))?
                .as_str()
                .unwrap_or_default()
                .to_string()
        } else if raw.is_empty() {
            String::new()
        } else if target.get("category").and_then(Value::as_str) == Some("Notification")
            && matches!(kind(&target).as_str(), "dingtalk" | "lark")
        {
            serde_json::from_str::<String>(&raw).unwrap_or(raw)
        } else if target.get("category").and_then(Value::as_str) == Some("Notification")
            && kind(&target).starts_with("customhttp")
        {
            merge_pairs(previous, &raw)?
        } else if let Ok(mut parsed) = serde_json::from_str::<Value>(&raw) {
            canonical_metadata(&target, &mut parsed)?;
            let mut previous = previous.and_then(|s| serde_json::from_str::<Value>(s).ok());
            if let Some(previous) = previous.as_mut() {
                canonical_metadata(&target, previous)?;
            }
            merge_json(previous.as_ref(), parsed)?.to_string()
        } else {
            raw
        };
        patch.insert("metadata".into(), json!(merged));
    }
    // client_secret2 is a JSON header-pair list for Custom HTTP notifications;
    // otherwise it is an opaque secret (Email uses a public From display name).
    if target.get("category").and_then(Value::as_str) == Some("Notification")
        && kind(&target).starts_with("customhttp")
    {
        if let Some(raw) = patch
            .get("client_secret2")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            let merged = merge_pairs(current.and_then(|p| p.client_secret2.as_deref()), raw)?;
            patch.insert("client_secret2".into(), json!(merged));
        }
    }
    for field in [
        "client_secret",
        "client_secret2",
        "content",
        "metadata",
        "http_headers",
        "client_id",
        "endpoint",
        "provider_url",
    ] {
        if patch.get(field).and_then(Value::as_str) == Some("***") {
            return Err(invalid("A mask cannot be stored as provider configuration"));
        }
    }
    Ok(())
}

pub fn validate_mapping(value: &Value) -> AppResult<()> {
    let fields = value
        .as_object()
        .ok_or_else(|| invalid("User mapping must be an object"))?;
    const TARGETS: [&str; 8] = [
        "id",
        "username",
        "displayName",
        "email",
        "emailVerified",
        "phone",
        "phoneVerified",
        "avatarUrl",
    ];
    if fields.len() > 8 {
        return Err(invalid("Too many user mapping fields"));
    }
    for (target, path) in fields {
        let path = path
            .as_str()
            .ok_or_else(|| invalid("User mapping paths must be strings"))?;
        if !TARGETS.contains(&target.as_str())
            || path.is_empty()
            || path.len() > 512
            || path.chars().any(char::is_control)
            || path.split('.').count() > 16
            || path.split('.').any(str::is_empty)
        {
            return Err(invalid("Invalid user mapping target or object path"));
        }
    }
    Ok(())
}

pub fn email_sender(
    provider: &Provider,
    override_sender: Option<&str>,
) -> AppResult<lettre::message::Mailbox> {
    let address = [
        override_sender,
        provider.client_id2.as_deref(),
        provider.receiver.as_deref(),
        provider.client_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|s| !s.is_empty())
    .ok_or_else(|| invalid("Email provider requires a From address"))?;
    let name = provider.client_secret2.as_deref().filter(|s| !s.is_empty());
    if address.contains(['\r', '\n']) || name.is_some_and(|s| s.contains(['\r', '\n'])) {
        return Err(invalid("Invalid Email From address or name"));
    }
    let mut sender: lettre::message::Mailbox = address
        .parse()
        .map_err(|_| invalid("Invalid Email From address"))?;
    if let Some(name) = name {
        sender.name = Some(name.to_string());
    }
    Ok(sender)
}

pub fn validate(provider: &Provider) -> AppResult<()> {
    for value in [
        provider.client_secret.as_deref(),
        provider.client_secret2.as_deref(),
        provider.metadata.as_deref(),
        provider.http_headers.as_deref(),
        provider.user_mapping.as_deref(),
    ] {
        if value.is_some_and(|s| s.len() > 64 * 1024 || s == "***") {
            return Err(invalid("Invalid or oversized provider configuration"));
        }
    }
    if let Some(mapping) = provider.user_mapping.as_deref().filter(|s| !s.is_empty()) {
        validate_mapping(
            &serde_json::from_str(mapping).map_err(|_| invalid("Invalid user mapping JSON"))?,
        )?;
    }
    if let Some(headers) = provider.http_headers.as_deref().filter(|s| !s.is_empty()) {
        let fields: BTreeMap<String, String> =
            serde_json::from_str(headers).map_err(|_| invalid("Invalid provider header JSON"))?;
        header_pairs(&json!(fields.into_iter().collect::<Vec<_>>()).to_string())?;
    }
    if provider.category == "Payment"
        && matches!(
            provider.provider_type.to_ascii_lowercase().as_str(),
            "stripe" | "paypal"
        )
    {
        if let Some(raw) = provider.metadata.as_deref().filter(|s| !s.is_empty()) {
            let fields: Value = serde_json::from_str(raw)
                .map_err(|_| invalid("Payment metadata must be a JSON object"))?;
            let fields = fields
                .as_object()
                .ok_or_else(|| invalid("Payment metadata must be a JSON object"))?;
            let provider_object = serde_json::to_value(provider).expect("Provider JSON");
            for (key, value) in fields {
                if payment_key(provider_object.as_object().unwrap(), key)
                    && !value.is_null()
                    && !value.is_string()
                {
                    return Err(invalid("Payment webhook configuration must be a string"));
                }
            }
        }
    }
    if provider.category == "Email"
        && !kind(&serde_json::to_value(provider).unwrap().as_object().unwrap())
            .contains("customhttp")
    {
        email_sender(provider, None)?;
        if !provider
            .provider_type
            .to_ascii_lowercase()
            .contains("sendgrid")
        {
            if !provider
                .host
                .as_deref()
                .is_some_and(|host| !host.is_empty() && !host.chars().any(char::is_control))
                || !(1..=65535).contains(&provider.port.unwrap_or(587))
            {
                return Err(invalid(
                    "SMTP requires a host and a port between 1 and 65535",
                ));
            }
        }
    }
    if provider.category == "Notification"
        && provider
            .provider_type
            .to_ascii_lowercase()
            .replace([' ', '-', '_'], "")
            .starts_with("customhttp")
    {
        if let Some(headers) = provider
            .client_secret2
            .as_deref()
            .or(provider.metadata.as_deref())
            .filter(|s| !s.is_empty())
        {
            header_pairs(headers)?;
        }
    }
    crate::services::protocol_gap_service::validate_storage_configuration(provider)?;
    crate::services::providers::oauth_provider::validate_oauth_configuration(provider)?;
    Ok(())
}
