//! Read-only SCIM 2.0 Users source. Complete, validated pagination is collected
//! before the executor applies any local account changes or missing-user rules.
use crate::{
    error::{AppError, AppResult},
    models::{Syncer, TableColumn},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{collections::HashSet, time::Duration};
pub struct ScimSource;
const MAX_USERS: usize = 100_000;
const MAX_PAGE: usize = 8 * 1024 * 1024;
fn invalid(message: &str) -> AppError {
    AppError::Validation(message.into())
}
fn mappings() -> Vec<(&'static str, &'static str)> {
    vec![
        ("id", "Id"),
        ("userName", "Name"),
        ("displayName", "DisplayName"),
        ("givenName", "FirstName"),
        ("familyName", "LastName"),
        ("mail", "Email"),
        ("phone", "Phone"),
        ("isForbidden", "IsForbidden"),
        ("externalId", "ExternalId"),
        ("title", "Title"),
        ("language", "Language"),
        ("address", "Address"),
        ("location", "Location"),
        ("region", "Region"),
    ]
}
#[derive(Deserialize)]
struct List {
    schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    total: usize,
    #[serde(rename = "startIndex")]
    start: Option<usize>,
    #[serde(rename = "itemsPerPage")]
    per_page: Option<usize>,
    #[serde(default, rename = "Resources")]
    resources: Vec<Value>,
}
impl ScimSource {
    pub fn validate(s: &Syncer) -> AppResult<()> {
        Self::endpoint(s)?;
        if !s.is_read_only {
            return Err(invalid(
                "SCIM sources support read-only synchronization only",
            ));
        }
        if s.user.is_empty() && s.password.is_empty() {
            return Err(invalid("SCIM authentication credentials are required"));
        }
        if s.user.len() > 16384
            || s.password.len() > 16384
            || s.user.chars().any(char::is_control)
            || s.password.chars().any(char::is_control)
        {
            return Err(invalid("Invalid SCIM credential format or length"));
        }
        if s.user == "***" || s.password == "***" {
            return Err(invalid(
                "SCIM requires real credentials, not a redacted placeholder",
            ));
        }
        Self::columns(s)?;
        Ok(())
    }
    fn endpoint(s: &Syncer) -> AppResult<reqwest::Url> {
        let mut url = reqwest::Url::parse(&s.host)
            .map_err(|_| invalid("SCIM host must be a valid base URL"))?;
        let loopback = url.host_str().is_some_and(|h| {
            h == "localhost"
                || h.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                "SCIM requires HTTPS (or loopback HTTP), without URL credentials, query or fragment",
            ));
        }
        url.set_path(&format!("{}/Users", url.path().trim_end_matches('/')));
        Ok(url)
    }
    pub fn columns(s: &Syncer) -> AppResult<Vec<TableColumn>> {
        let allowed = mappings();
        let columns = if let Some(raw) = s
            .table_columns
            .as_deref()
            .filter(|s| !s.trim().is_empty() && s.trim() != "[]")
        {
            serde_json::from_str::<Vec<TableColumn>>(raw)
                .map_err(|_| invalid("Invalid SCIM tableColumns"))?
        } else {
            allowed
                .iter()
                .map(|(source, target)| TableColumn {
                    name: (*source).into(),
                    casdoor_name: (*target).into(),
                    column_type: if *source == "isForbidden" {
                        "Boolean"
                    } else {
                        "String"
                    }
                    .into(),
                    is_key: *source == "id",
                    is_hashed: false,
                    values: None,
                })
                .collect()
        };
        let normalize = |s: &str| s.to_ascii_lowercase().replace(['_', '-', ' '], "");
        let mut seen = HashSet::new();
        let mut keys = 0;
        for c in &columns {
            if !allowed.iter().any(|(source, target)| {
                c.name == *source && normalize(&c.casdoor_name) == normalize(target)
            }) || !seen.insert(c.name.clone())
                || c.is_hashed
                || c.values.as_ref().is_some_and(|v| !v.is_empty())
            {
                return Err(invalid(
                    "SCIM mappings must use supported standard fields without credential or value conversions",
                ));
            }
            if c.is_key {
                keys += 1;
                if c.name != "id" {
                    return Err(invalid("SCIM stable key must be id mapped to Id"));
                }
            }
        }
        if keys != 1 || !columns.iter().any(|c| c.name == "userName") {
            return Err(invalid("SCIM mappings require stable id and userName"));
        }
        Ok(columns)
    }
    pub async fn snapshot(s: &Syncer) -> AppResult<Vec<Map<String, Value>>> {
        Self::validate(s)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| invalid("Cannot initialize SCIM HTTP transport"))?;
        let endpoint = Self::endpoint(s)?;
        let mut start = 1usize;
        let mut total = None;
        let mut rows = Vec::new();
        let mut received_bytes = 0usize;
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        loop {
            let mut url = endpoint.clone();
            url.query_pairs_mut()
                .append_pair("startIndex", &start.to_string())
                .append_pair("count", "100");
            let request = client
                .get(url)
                .header("Accept", "application/scim+json")
                .header("Content-Type", "application/scim+json");
            let request = if !s.user.is_empty() && !s.password.is_empty() {
                request.basic_auth(&s.user, Some(&s.password))
            } else {
                request.bearer_auth(if s.password.is_empty() {
                    &s.user
                } else {
                    &s.password
                })
            };
            let mut response = request.send().await.map_err(|_| {
                AppError::Internal("SCIM source request failed; no accounts were imported".into())
            })?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(invalid(&format!(
                    "SCIM source returned HTTP {}; no accounts were imported",
                    response.status().as_u16()
                )));
            }
            if response
                .content_length()
                .is_some_and(|n| n > MAX_PAGE as u64)
            {
                return Err(invalid("SCIM response exceeds the page size limit"));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| invalid("SCIM response was interrupted"))?
            {
                if body.len() + chunk.len() > MAX_PAGE {
                    return Err(invalid("SCIM response exceeds the page size limit"));
                }
                body.extend_from_slice(&chunk);
            }
            received_bytes += body.len();
            if received_bytes > 64 * 1024 * 1024 {
                return Err(invalid(
                    "SCIM snapshot exceeds the total response size limit",
                ));
            }
            let page: List = serde_json::from_slice(&body)
                .map_err(|_| invalid("Invalid SCIM ListResponse; no accounts were imported"))?;
            if !page
                .schemas
                .iter()
                .any(|s| s == "urn:ietf:params:scim:api:messages:2.0:ListResponse")
                || page.total > MAX_USERS
                || total.is_some_and(|old| old != page.total)
                || page.start.is_some_and(|v| v != start)
                || page.per_page.is_some_and(|v| v != page.resources.len())
                || page.resources.len() > 100
                || rows.len() + page.resources.len() > page.total
            {
                return Err(invalid(
                    "SCIM pagination metadata is inconsistent; no accounts were imported",
                ));
            }
            if page.start.is_none() && (start != 1 || page.total > page.resources.len()) {
                return Err(invalid("SCIM paged responses require startIndex"));
            }
            total = Some(page.total);
            if page.resources.is_empty() && rows.len() != page.total {
                return Err(invalid(
                    "SCIM snapshot is truncated; no accounts were imported",
                ));
            }
            for resource in page.resources {
                let row = Self::user(&resource)?;
                let id = row["id"].as_str().unwrap();
                let name = row["userName"].as_str().unwrap();
                if !ids.insert(id.to_owned()) || !names.insert(name.to_ascii_lowercase()) {
                    return Err(invalid("SCIM snapshot contains duplicate identities"));
                }
                rows.push(row);
            }
            if rows.len() == page.total {
                return Ok(rows);
            }
            start = rows.len() + 1;
        }
    }
    fn user(value: &Value) -> AppResult<Map<String, Value>> {
        let obj = value
            .as_object()
            .ok_or_else(|| invalid("SCIM resource must be an object"))?;
        let text = |key: &str| -> AppResult<String> {
            match obj.get(key) {
                None | Some(Value::Null) => Ok(String::new()),
                Some(Value::String(s)) if s.len() <= 65536 => Ok(s.clone()),
                _ => Err(invalid("SCIM user attribute has an invalid type or length")),
            }
        };
        let id = text("id")?;
        let name = text("userName")?;
        if id.trim().is_empty()
            || id.len() > 8192
            || name.trim().is_empty()
            || name.len() > 100
            || id.chars().any(char::is_control)
            || name.chars().any(char::is_control)
        {
            return Err(invalid("SCIM user requires valid stable id and userName"));
        }
        let forbidden = match obj.get("active") {
            None => Value::String(String::new()), // omitted attributes preserve existing local state
            Some(Value::Bool(v)) => json!(!v),
            _ => return Err(invalid("SCIM active must be Boolean")),
        };
        let nested = value.get("name").filter(|v| !v.is_null());
        if nested.is_some_and(|v| !v.is_object()) {
            return Err(invalid("SCIM name must be an object"));
        }
        let nested_text = |key: &str| -> AppResult<String> {
            match nested.and_then(|v| v.get(key)) {
                None | Some(Value::Null) => Ok(String::new()),
                Some(Value::String(s)) if s.len() <= 65536 => Ok(s.clone()),
                _ => Err(invalid("Invalid SCIM name attribute")),
            }
        };
        let given = nested_text("givenName")?;
        let family = nested_text("familyName")?;
        let mut display = text("displayName")?;
        if display.is_empty() {
            display = nested_text("formatted")?;
        }
        if display.is_empty() {
            display = format!("{given} {family}").trim().to_owned();
        }
        if display.is_empty() {
            display = name.clone();
        }
        let select = |field: &str| -> AppResult<Option<&Value>> {
            match obj.get(field) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Array(values)) => {
                    if values.iter().any(|v| {
                        !v.is_object() || v.get("primary").is_some_and(|p| !p.is_boolean())
                    }) {
                        return Err(invalid("Invalid SCIM multi-valued attribute"));
                    }
                    Ok(values
                        .iter()
                        .find(|v| v["primary"] == true)
                        .or_else(|| values.first()))
                }
                _ => Err(invalid("Invalid SCIM multi-valued attribute")),
            }
        };
        let contact = |field: &str| -> AppResult<String> {
            match select(field)?.and_then(|v| v.get("value")) {
                None => Ok(String::new()),
                Some(Value::String(s)) => Ok(s.clone()),
                _ => Err(invalid("Invalid SCIM contact value")),
            }
        };
        let address = select("addresses")?;
        let attr = |key: &str| -> AppResult<String> {
            match address.and_then(|v| v.get(key)) {
                None | Some(Value::Null) => Ok(String::new()),
                Some(Value::String(s)) => Ok(s.clone()),
                _ => Err(invalid("Invalid SCIM address")),
            }
        };
        let formatted = attr("formatted")?;
        let addresses = if address.is_none() {
            vec![]
        } else if !formatted.is_empty() {
            vec![formatted]
        } else {
            [
                "streetAddress",
                "locality",
                "region",
                "postalCode",
                "country",
            ]
            .into_iter()
            .map(attr)
            .collect::<AppResult<Vec<_>>>()?
        };
        let mut row = Map::new();
        for (key, value) in [
            ("id", id),
            ("userName", name),
            ("displayName", display),
            ("givenName", given),
            ("familyName", family),
            ("mail", contact("emails")?),
            ("phone", contact("phoneNumbers")?),
            ("externalId", text("externalId")?),
            ("title", text("title")?),
            ("language", text("preferredLanguage")?),
            ("location", attr("locality")?),
            ("region", attr("region")?),
        ] {
            row.insert(key.into(), Value::String(value));
        }
        row.insert("isForbidden".into(), forbidden);
        row.insert(
            "address".into(),
            Value::String(if obj.get("addresses").is_none_or(Value::is_null) {
                String::new()
            } else {
                serde_json::to_string(&addresses).unwrap()
            }),
        );
        Ok(row)
    }
}
