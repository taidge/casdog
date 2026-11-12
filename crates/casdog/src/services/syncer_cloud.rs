//! Credential-authenticated complete directory snapshots. Transport exceptions
//! are durable, administrator-reviewed and rechecked before every request.
use crate::{
    error::{AppError, AppResult},
    models::{Syncer, TableColumn},
};
use reqwest::{Method, Url};
use rsa::{
    RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use std::collections::{HashMap, HashSet};

const USERS: usize = 100_000;
const GROUPS: usize = 10_000;
const MEMBERS: usize = 200_000;
const PAGE: usize = 8 * 1024 * 1024;
const TOTAL: usize = 64 * 1024 * 1024;
const SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly";
fn invalid(message: &str) -> AppError {
    AppError::Validation(message.into())
}
pub struct CloudSource;
pub struct CloudSnapshot {
    pub rows: Vec<Map<String, Value>>,
    pub groups: Vec<CloudGroup>,
    pub used_binding: Option<String>,
}
pub struct CloudGroup {
    pub id: String,
    pub email: String,
    pub name: String,
    pub members: HashSet<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    token_endpoint: Option<String>,
    api_base: Option<String>,
    customer: Option<String>,
}
#[derive(Deserialize)]
struct Account {
    #[serde(rename = "type")]
    kind: String,
    client_email: String,
    private_key: String,
    private_key_id: Option<String>,
    token_uri: Option<String>,
}
struct Settings {
    token: Url,
    api: Url,
    customer: String,
    account: Option<Account>,
}
fn endpoint(raw: &str) -> AppResult<Url> {
    let url = Url::parse(raw).map_err(|_| invalid("Invalid cloud directory endpoint"))?;
    let loopback = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if raw.len() > 8192
        || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "Cloud directory endpoints require HTTPS (or approved loopback HTTP), without credentials, query or fragment",
        ));
    }
    Ok(url)
}
fn text(value: &Value, key: &str) -> AppResult<String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) if s.len() <= 65536 => Ok(s.clone()),
        _ => Err(invalid("Invalid cloud directory profile field")),
    }
}
fn identity(raw: String) -> AppResult<String> {
    if raw.is_empty()
        || raw.len() > 256
        || matches!(raw.as_str(), "." | "..")
        || raw.chars().any(|c| {
            c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '%' | '?' | '#')
        })
    {
        return Err(invalid(
            "Missing or invalid immutable cloud directory identity",
        ));
    }
    Ok(raw)
}
fn email(raw: &str) -> bool {
    raw.len() <= 320
        && raw.contains('@')
        && !raw.chars().any(|c| c.is_control() || c.is_whitespace())
}
fn pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("id", "Id"),
        ("userName", "Name"),
        ("displayName", "DisplayName"),
        ("givenName", "FirstName"),
        ("familyName", "LastName"),
        ("email", "Email"),
        ("phone", "Phone"),
        ("avatar", "Avatar"),
        ("title", "Title"),
        ("language", "Language"),
        ("location", "Location"),
        ("isForbidden", "IsForbidden"),
        ("properties", "Properties"),
        ("createdTime", "CreatedTime"),
    ]
}
impl CloudSource {
    fn settings(s: &Syncer) -> AppResult<Settings> {
        if !matches!(s.syncer_type.as_str(), "Azure AD" | "Google Workspace") || !s.is_read_only {
            return Err(invalid(
                "Cloud directory sources are read-only; writeback is unsupported",
            ));
        }
        if s.database_type.as_deref().is_some_and(|v| !v.is_empty())
            || s.ssl_mode.as_deref().is_some_and(|v| !v.is_empty())
            || s.table_name.as_deref().is_some_and(|v| !v.is_empty())
            || s.affiliation_table
                .as_deref()
                .is_some_and(|v| !v.is_empty())
        {
            return Err(invalid(
                "SQL, LDAP TLS and affiliation-table options are unsupported for cloud directories",
            ));
        }
        if s.password.is_empty()
            || s.password == "***"
            || s.password.len() > 65536
            || s.user == "***"
            || s.user.len() > 320
            || s.user.chars().any(char::is_control)
        {
            return Err(invalid(
                "Cloud directory requires real credentials in Password",
            ));
        }
        let raw = s.database.as_deref().unwrap_or("");
        if raw.len() > 16384 {
            return Err(invalid("Cloud directory options exceed 16 KiB"));
        }
        let options: Options = if raw.trim().is_empty() {
            Options::default()
        } else {
            serde_json::from_str(raw)
                .map_err(|_| invalid("Cloud directory Database must be public options JSON"))?
        };
        if s.syncer_type == "Azure AD" {
            if s.host.is_empty()
                || s.host.len() > 253
                || !s
                    .host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
                || s.user.is_empty()
                || s.user.chars().any(char::is_whitespace)
                || s.password.chars().any(char::is_control)
                || options.customer.is_some()
            {
                return Err(invalid(
                    "Azure AD requires tenant ID/domain in Host, client ID in User and client secret in Password",
                ));
            }
            let token = endpoint(options.token_endpoint.as_deref().unwrap_or(&format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                s.host
            )))?;
            let api = endpoint(
                options
                    .api_base
                    .as_deref()
                    .unwrap_or("https://graph.microsoft.com/v1.0"),
            )?;
            Ok(Settings {
                token,
                api,
                customer: String::new(),
                account: None,
            })
        } else {
            if !email(&s.host) || options.token_endpoint.is_some() {
                return Err(invalid(
                    "Google Workspace Host must be the delegated administrator email; token_uri belongs in the secret JSON",
                ));
            }
            let a: Account = serde_json::from_str(&s.password)
                .map_err(|_| invalid("Invalid Google Workspace service-account JSON"))?;
            if a.kind != "service_account"
                || !email(&a.client_email)
                || !s.user.is_empty() && s.user != a.client_email
                || a.private_key_id
                    .as_ref()
                    .is_some_and(|v| v.len() > 256 || v.chars().any(char::is_control))
            {
                return Err(invalid(
                    "Google service-account identity does not match User",
                ));
            }
            let key = RsaPrivateKey::from_pkcs8_pem(&a.private_key)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&a.private_key))
                .map_err(|_| invalid("Invalid Google service-account RSA private key"))?;
            if !(2048..=8192).contains(&key.n().bits()) {
                return Err(invalid(
                    "Google service-account RSA key must be 2048–8192 bits",
                ));
            }
            let token = endpoint(
                a.token_uri
                    .as_deref()
                    .unwrap_or("https://oauth2.googleapis.com/token"),
            )?;
            let api = endpoint(
                options
                    .api_base
                    .as_deref()
                    .unwrap_or("https://admin.googleapis.com/admin/directory/v1"),
            )?;
            let customer = options.customer.unwrap_or_else(|| "my_customer".into());
            if customer.is_empty()
                || customer.len() > 128
                || !customer
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            {
                return Err(invalid("Invalid Google Workspace customer identifier"));
            }
            Ok(Settings {
                token,
                api,
                customer,
                account: Some(a),
            })
        }
    }
    pub fn validate(s: &Syncer) -> AppResult<()> {
        Self::settings(s)?;
        Self::columns(s)?;
        Ok(())
    }
    /// Safe, credential-free origins for the global administrator's review.
    pub fn network_origins(s: &Syncer) -> AppResult<Vec<String>> {
        let settings = Self::settings(s)?;
        let mut origins = vec![
            settings.token.origin().ascii_serialization(),
            settings.api.origin().ascii_serialization(),
        ];
        origins.sort();
        origins.dedup();
        Ok(origins)
    }
    pub fn columns(s: &Syncer) -> AppResult<Vec<TableColumn>> {
        let allowed = pairs();
        let columns = if let Some(raw) = s
            .table_columns
            .as_deref()
            .filter(|v| !v.trim().is_empty() && v.trim() != "[]")
        {
            serde_json::from_str::<Vec<TableColumn>>(raw)
                .map_err(|_| invalid("Invalid cloud tableColumns"))?
        } else {
            allowed
                .iter()
                .map(|(a, b)| TableColumn {
                    name: (*a).into(),
                    casdoor_name: (*b).into(),
                    column_type: if *a == "isForbidden" {
                        "Boolean"
                    } else {
                        "String"
                    }
                    .into(),
                    is_key: *a == "id",
                    is_hashed: false,
                    values: None,
                })
                .collect()
        };
        let normalize = |v: &str| v.to_ascii_lowercase().replace(['_', '-', ' '], "");
        let mut seen = HashSet::new();
        let mut keys = 0;
        for c in &columns {
            if !allowed
                .iter()
                .any(|(a, b)| c.name == *a && normalize(&c.casdoor_name) == normalize(b))
                || !seen.insert(c.name.clone())
                || c.is_hashed
                || c.values.as_ref().is_some_and(|v| !v.is_empty())
            {
                return Err(invalid(
                    "Cloud mappings permit only supported profile fields; credentials, roles and value conversions are unsupported",
                ));
            }
            if c.is_key {
                keys += 1;
                if c.name != "id" {
                    return Err(invalid("Cloud stable key must be id mapped to Id"));
                }
            }
        }
        if keys != 1 || !columns.iter().any(|c| c.name == "userName") {
            return Err(invalid("Cloud mappings require immutable id and userName"));
        }
        Ok(columns)
    }
    pub async fn snapshot(conn: &mut PgConnection, s: &Syncer) -> AppResult<CloudSnapshot> {
        Self::validate(s)?;
        let settings = Self::settings(s)?;
        let binding = super::syncer_network_service::network_binding_conn(conn, s).await?;
        let mut reader = Reader {
            conn,
            s,
            bytes: 0,
            requests: 0,
            binding,
        };
        let form = if let Some(a) = &settings.account {
            let now = chrono::Utc::now().timestamp();
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = a.private_key_id.clone();
            let key = jsonwebtoken::EncodingKey::from_rsa_pem(a.private_key.as_bytes())
                .map_err(|_| invalid("Invalid service-account signing key"))?;
            let assertion=jsonwebtoken::encode(&header,&json!({"iss":a.client_email,"sub":s.host,"aud":settings.token.as_str(),"scope":SCOPE,"iat":now,"exp":now+3600}),&key).map_err(|_|invalid("Unable to sign Google domain-wide delegation assertion"))?;
            vec![
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
                ),
                ("assertion", assertion),
            ]
        } else {
            vec![
                ("client_id", s.user.clone()),
                ("client_secret", s.password.clone()),
                ("scope", "https://graph.microsoft.com/.default".into()),
                ("grant_type", "client_credentials".into()),
            ]
        };
        let response = reader
            .request(Method::POST, settings.token.clone(), None, Some(&form))
            .await?;
        let token = text(&response, "access_token")?;
        if token.is_empty()
            || token.len() > 16384
            || token.chars().any(char::is_control)
            || response.get("error").is_some()
            || response
                .get("token_type")
                .is_some_and(|v| !v.as_str().is_some_and(|v| v.eq_ignore_ascii_case("Bearer")))
        {
            return Err(invalid(
                "Cloud token endpoint returned an invalid access token",
            ));
        }
        let mut rows = Vec::new();
        let mut groups = Vec::new();
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        if s.syncer_type == "Azure AD" {
            let mut next = join(&settings.api, "users")?;
            next.query_pairs_mut().append_pair("$top","999").append_pair("$select","id,userPrincipalName,displayName,givenName,surname,mail,mobilePhone,jobTitle,officeLocation,preferredLanguage,accountEnabled");
            let base = next.clone();
            for page in 0..200 {
                let value = reader
                    .request(Method::GET, next, Some(&token), None)
                    .await?;
                let users = value
                    .get("value")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("Invalid Microsoft Graph users page"))?;
                for user in users {
                    let row = azure_user(user)?;
                    unique(&row, &mut ids, &mut names)?;
                    rows.push(row);
                    if rows.len() > USERS {
                        return Err(invalid("Cloud directory exceeds 100000 users"));
                    }
                }
                let link = optional_cursor(&value, "@odata.nextLink")?;
                if link.is_empty() {
                    break;
                }
                if page == 199 {
                    return Err(invalid("Microsoft Graph pagination exceeds 200 pages"));
                }
                next = Url::parse(&link).map_err(|_| invalid("Invalid Graph nextLink"))?;
                if next.origin() != base.origin()
                    || next.path() != base.path()
                    || !next.username().is_empty()
                    || next.password().is_some()
                    || next.fragment().is_some()
                {
                    return Err(invalid("Graph nextLink left the approved users endpoint"));
                }
            }
        } else {
            let mut users = join(&settings.api, "users")?;
            users
                .query_pairs_mut()
                .append_pair("customer", &settings.customer)
                .append_pair("maxResults", "500")
                .append_pair("projection", "full");
            for user in reader
                .google_list(users, "users", "admin#directory#users", USERS, &token)
                .await?
            {
                let row = google_user(&user)?;
                unique(&row, &mut ids, &mut names)?;
                rows.push(row);
            }
            let mut endpoint = join(&settings.api, "groups")?;
            endpoint
                .query_pairs_mut()
                .append_pair("customer", &settings.customer)
                .append_pair("maxResults", "200");
            let mut group_ids = HashSet::new();
            let mut group_emails = HashSet::new();
            let mut memberships = 0;
            for group in reader
                .google_list(endpoint, "groups", "admin#directory#groups", GROUPS, &token)
                .await?
            {
                let id = identity(text(&group, "id")?)?;
                if !group_ids.insert(id.clone()) {
                    return Err(invalid("Duplicate Google group identity"));
                }
                let mail = text(&group, "email")?;
                if !email(&mail) || !group_emails.insert(mail.to_ascii_lowercase()) {
                    return Err(invalid("Google group requires a unique valid email"));
                }
                let mut members_url = settings.api.clone();
                members_url
                    .path_segments_mut()
                    .map_err(|_| invalid("Invalid directory API base"))?
                    .pop_if_empty()
                    .push("groups")
                    .push(&id)
                    .push("members");
                members_url
                    .query_pairs_mut()
                    .append_pair("maxResults", "200");
                let mut members = HashSet::new();
                let mut member_ids = HashSet::new();
                for member in reader
                    .google_list(
                        members_url,
                        "members",
                        "admin#directory#members",
                        MEMBERS,
                        &token,
                    )
                    .await?
                {
                    memberships += 1;
                    if memberships > MEMBERS {
                        return Err(invalid("Google directory exceeds 200000 memberships"));
                    }
                    let kind = text(&member, "type")?;
                    if !matches!(kind.as_str(), "USER" | "GROUP" | "CUSTOMER" | "EXTERNAL") {
                        return Err(invalid("Unsupported Google group member type"));
                    }
                    let mid = identity(text(&member, "id")?)?;
                    if !member_ids.insert((kind.clone(), mid.clone())) {
                        return Err(invalid("Duplicate Google group member identity"));
                    }
                    if kind == "USER" && ids.contains(&mid) {
                        members.insert(mid);
                    }
                }
                let mut name = text(&group, "name")?;
                if name.is_empty() {
                    name = mail.clone();
                }
                groups.push(CloudGroup {
                    id,
                    email: mail,
                    name,
                    members,
                });
            }
            let membership_by_user: HashMap<String, Vec<String>> =
                groups.iter().fold(HashMap::new(), |mut map, g| {
                    for id in &g.members {
                        map.entry(id.clone()).or_default().push(g.email.clone());
                    }
                    map
                });
            for row in &mut rows {
                let id = row["id"].as_str().unwrap();
                let mut values = membership_by_user.get(id).cloned().unwrap_or_default();
                values.sort();
                row.get_mut("properties").unwrap()["cloud_directory"]["groups"] = json!(values);
            }
        }
        reader.final_check().await?;
        Ok(CloudSnapshot {
            rows,
            groups,
            used_binding: reader.binding,
        })
    }
}
fn unique(
    row: &Map<String, Value>,
    ids: &mut HashSet<String>,
    names: &mut HashSet<String>,
) -> AppResult<()> {
    if !ids.insert(row["id"].as_str().unwrap().into())
        || !names.insert(row["userName"].as_str().unwrap().to_ascii_lowercase())
    {
        return Err(invalid("Duplicate cloud directory user identity"));
    }
    Ok(())
}
fn join(base: &Url, path: &str) -> AppResult<Url> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| invalid("Invalid directory API base"))?
        .pop_if_empty()
        .push(path);
    Ok(url)
}
fn optional_cursor(value: &Value, key: &str) -> AppResult<String> {
    let token = text(value, key)?;
    if token.len() > 8192 || token.chars().any(char::is_control) {
        return Err(invalid("Invalid cloud pagination cursor"));
    }
    Ok(token)
}
struct Reader<'a> {
    conn: &'a mut PgConnection,
    s: &'a Syncer,
    bytes: usize,
    requests: usize,
    binding: Option<String>,
}
impl Reader<'_> {
    async fn final_check(&mut self) -> AppResult<()> {
        let binding =
            super::syncer_network_service::network_binding_conn(self.conn, self.s).await?;
        if self.binding != binding {
            return Err(AppError::Authorization(
                "Cloud directory network approval changed; start a new synchronization".into(),
            ));
        }
        Ok(())
    }
    async fn request(
        &mut self,
        method: Method,
        url: Url,
        token: Option<&str>,
        form: Option<&Vec<(&str, String)>>,
    ) -> AppResult<Value> {
        self.requests += 1;
        if self.requests > 4096 {
            return Err(invalid("Cloud directory exceeds 4096 requests"));
        }
        let binding =
            super::syncer_network_service::network_binding_conn(self.conn, self.s).await?;
        if self.binding != binding {
            return Err(AppError::Authorization(
                "Cloud directory network approval changed; start a new synchronization".into(),
            ));
        }
        let allowed = self.binding.is_some();
        let client = super::system_gap_service::client(&url, allowed).await?;
        let mut request = client
            .request(method, url)
            .header("Accept", "application/json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(form) = form {
            request = request.form(form);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| invalid("Cloud directory HTTP request failed; no changes imported"))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(invalid(&format!(
                "Cloud directory returned HTTP {}; no changes imported",
                response.status().as_u16()
            )));
        }
        if response
            .content_length()
            .is_some_and(|size| size > PAGE as u64)
        {
            return Err(invalid("Cloud directory page exceeds 8 MiB"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| invalid("Interrupted cloud directory response"))?
        {
            if bytes.len() + chunk.len() > PAGE {
                return Err(invalid("Cloud directory page exceeds 8 MiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        self.bytes += bytes.len();
        if self.bytes > TOTAL {
            return Err(invalid("Cloud directory snapshot exceeds 64 MiB"));
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("Malformed cloud directory JSON; no changes imported"))?;
        if !value.is_object() || value.get("error").is_some() {
            return Err(invalid("Cloud directory returned an error document"));
        }
        Ok(value)
    }
    async fn google_list(
        &mut self,
        base: Url,
        field: &str,
        kind: &str,
        limit: usize,
        token: &str,
    ) -> AppResult<Vec<Value>> {
        let mut rows = Vec::new();
        let mut cursor = String::new();
        for page in 0..200 {
            let mut url = base.clone();
            if !cursor.is_empty() {
                url.query_pairs_mut().append_pair("pageToken", &cursor);
            }
            let value = self.request(Method::GET, url, Some(token), None).await?;
            if value.get("kind").is_some_and(|v| v.as_str() != Some(kind))
                || value.get(field).is_none() && value.get("kind").is_none()
            {
                return Err(invalid("Invalid Google directory collection page"));
            }
            match value.get(field) {
                None => {}
                Some(Value::Array(items)) => rows.extend(items.clone()),
                _ => return Err(invalid("Invalid Google directory resource list")),
            }
            if rows.len() > limit {
                return Err(invalid(
                    "Google directory collection exceeds its resource bound",
                ));
            }
            cursor = optional_cursor(&value, "nextPageToken")?;
            if cursor.is_empty() {
                return Ok(rows);
            }
            if page == 199 {
                return Err(invalid("Google directory pagination exceeds 200 pages"));
            }
        }
        Err(invalid("Incomplete Google directory pagination"))
    }
}
fn common(
    id: String,
    name: String,
    display: String,
    first: String,
    last: String,
    mail: String,
    forbidden: Option<bool>,
    properties: Value,
) -> AppResult<Map<String, Value>> {
    if !email(&name) {
        return Err(invalid(
            "Cloud directory username must be a principal email",
        ));
    }
    if !mail.is_empty() && !email(&mail) {
        return Err(invalid("Invalid cloud directory email"));
    }
    let display = if display.is_empty() {
        format!("{first} {last}").trim().to_string()
    } else {
        display
    };
    let mut row = Map::new();
    for (key, value) in [
        ("id", identity(id)?),
        ("userName", name),
        ("displayName", display),
        ("givenName", first),
        ("familyName", last),
        ("email", mail),
    ] {
        row.insert(key.into(), json!(value));
    }
    row.insert(
        "isForbidden".into(),
        forbidden.map_or(json!(""), |v| json!(v)),
    );
    row.insert("properties".into(), properties);
    Ok(row)
}
fn azure_user(user: &Value) -> AppResult<Map<String, Value>> {
    let name = text(user, "userPrincipalName")?;
    let mut mail = text(user, "mail")?;
    if mail.is_empty() {
        mail = name.clone();
    }
    let enabled = user
        .get("accountEnabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("Graph accountEnabled must be explicitly selected and boolean"))?;
    let mut row = common(
        text(user, "id")?,
        name.clone(),
        text(user, "displayName")?,
        text(user, "givenName")?,
        text(user, "surname")?,
        mail,
        Some(!enabled),
        json!({"cloud_directory":{"type":"Azure AD","principal":name}}),
    )?;
    for (key, source) in [
        ("phone", "mobilePhone"),
        ("title", "jobTitle"),
        ("location", "officeLocation"),
        ("language", "preferredLanguage"),
    ] {
        row.insert(key.into(), json!(text(user, source)?));
    }
    Ok(row)
}
fn google_user(user: &Value) -> AppResult<Map<String, Value>> {
    let name = text(user, "primaryEmail")?;
    let n = user
        .get("name")
        .filter(|v| !v.is_null())
        .unwrap_or(&Value::Null);
    if !n.is_null() && !n.is_object() {
        return Err(invalid("Invalid Google user name object"));
    }
    let suspended = match user.get("suspended") {
        None => None,
        Some(Value::Bool(v)) => Some(*v),
        _ => return Err(invalid("Invalid Google suspended status")),
    };
    let admin = match user.get("isAdmin") {
        None => false,
        Some(Value::Bool(v)) => *v,
        _ => return Err(invalid("Invalid Google admin claim")),
    };
    let mut row = common(
        text(user, "id")?,
        name.clone(),
        text(n, "fullName")?,
        text(n, "givenName")?,
        text(n, "familyName")?,
        name.clone(),
        suspended,
        json!({"cloud_directory":{"type":"Google Workspace","principal":name,"remote_is_admin":admin,"groups":[]}}),
    )?;
    row.insert("avatar".into(), json!(text(user, "thumbnailPhotoUrl")?));
    let created = text(user, "creationTime")?;
    if !created.is_empty() {
        chrono::DateTime::parse_from_rfc3339(&created)
            .map_err(|_| invalid("Invalid Google creationTime"))?;
        row.insert("createdTime".into(), json!(created));
    }
    Ok(row)
}

#[derive(sqlx::FromRow)]
struct GroupLink {
    source_key: String,
    organization: String,
    group_id: String,
    group_name: String,
}
#[derive(sqlx::FromRow)]
struct Membership {
    source_group_key: String,
    user_id: String,
    group_id: String,
    user_group_id: Option<String>,
    group_value: String,
    owns_user_group: bool,
    owns_user_group_value: bool,
    manual_preserved: bool,
}
fn group_values(value: Option<Value>) -> AppResult<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("Existing user groups must be a string array"))
            })
            .collect(),
        _ => Err(invalid("Existing user groups must be a string array")),
    }
}
impl CloudSource {
    /// Reconcile only groups and edges owned by this connector. Imported groups
    /// use an unguessable namespace and never adopt a local same-name group.
    pub async fn apply_groups(
        conn: &mut PgConnection,
        s: &Syncer,
        snapshot: &CloudSnapshot,
    ) -> AppResult<()> {
        let links:Vec<GroupLink>=sqlx::query_as("SELECT source_key,organization,group_id,group_name FROM syncer_group_links WHERE syncer_id=$1").bind(&s.id).fetch_all(&mut *conn).await?;
        let mut local: HashMap<String, (String, String)> = HashMap::new();
        for link in links {
            let current: Option<(String, String)> =
                sqlx::query_as("SELECT owner,name FROM groups WHERE id=$1")
                    .bind(&link.group_id)
                    .fetch_optional(&mut *conn)
                    .await?;
            if link.organization != s.organization
                || current != Some((s.organization.clone(), link.group_name.clone()))
            {
                return Err(invalid(
                    "Managed cloud group was moved or renamed locally; repair its binding explicitly",
                ));
            }
            local.insert(link.source_key, (link.group_id, link.group_name));
        }
        let users:Vec<(String,String)>=sqlx::query_as("SELECT l.source_key,u.id FROM syncer_user_links l JOIN users u ON u.id=l.user_id WHERE l.syncer_id=$1 AND u.owner=$2 AND NOT u.is_deleted").bind(&s.id).bind(&s.organization).fetch_all(&mut *conn).await?;
        let users: HashMap<String, String> = users.into_iter().collect();
        let source_users: HashSet<&str> = snapshot
            .rows
            .iter()
            .filter_map(|row| row.get("id").and_then(Value::as_str))
            .collect();
        let mut desired = HashSet::new();
        for group in &snapshot.groups {
            let (id, name) = if let Some(pair) = local.get(&group.id) {
                pair.clone()
            } else {
                let id = uuid::Uuid::new_v4().to_string();
                let name = format!(
                    "cloud-{}-{}",
                    s.id.chars().take(8).collect::<String>(),
                    uuid::Uuid::new_v4().simple()
                );
                sqlx::query("INSERT INTO groups(id,owner,name,display_name,contact_email,type,is_top_group,is_enabled) VALUES($1,$2,$3,$4,$5,'CloudDirectory',false,true)").bind(&id).bind(&s.organization).bind(&name).bind(&group.name).bind(&group.email).execute(&mut *conn).await?;
                sqlx::query("INSERT INTO syncer_group_links(syncer_id,source_key,organization,group_id,group_name,remote_email) VALUES($1,$2,$3,$4,$5,$6)").bind(&s.id).bind(&group.id).bind(&s.organization).bind(&id).bind(&name).bind(&group.email).execute(&mut *conn).await?;
                local.insert(group.id.clone(), (id.clone(), name.clone()));
                (id, name)
            };
            sqlx::query("UPDATE groups SET display_name=$3,contact_email=$4,updated_at=clock_timestamp() WHERE id=$1 AND owner=$2").bind(&id).bind(&s.organization).bind(&group.name).bind(&group.email).execute(&mut *conn).await?;
            sqlx::query("UPDATE syncer_group_links SET active=true,remote_email=$3 WHERE syncer_id=$1 AND source_key=$2").bind(&s.id).bind(&group.id).bind(&group.email).execute(&mut *conn).await?;
            let group_value = format!("{}/{}", s.organization, name);
            let mut members = group.members.iter().collect::<Vec<_>>();
            members.sort();
            for source_id in members {
                if !source_users.contains(source_id.as_str()) {
                    continue;
                }
                let user_id = users
                    .get(source_id)
                    .ok_or_else(|| invalid("Cloud membership has no imported user binding"))?;
                let profile: Option<(String, Option<Value>)> =
                    sqlx::query_as("SELECT owner,groups FROM users WHERE id=$1 FOR UPDATE")
                        .bind(user_id)
                        .fetch_optional(&mut *conn)
                        .await?;
                let Some((owner, values)) = profile else {
                    return Err(invalid("Managed cloud member disappeared"));
                };
                if owner != s.organization {
                    return Err(invalid("Cloud member moved to a different tenant"));
                }
                let mut values = group_values(values)?;
                let had_value = values.contains(&group_value);
                let existing:Option<Membership>=sqlx::query_as("SELECT source_group_key,user_id,group_id,user_group_id,group_value,owns_user_group,owns_user_group_value,manual_preserved FROM syncer_group_memberships WHERE syncer_id=$1 AND source_group_key=$2 AND user_id=$3 FOR UPDATE").bind(&s.id).bind(&group.id).bind(user_id).fetch_optional(&mut *conn).await?;
                let inserted:Option<String>=sqlx::query_scalar("INSERT INTO user_groups(id,user_id,group_id) VALUES($1,$2,$3) ON CONFLICT(user_id,group_id) DO NOTHING RETURNING id").bind(uuid::Uuid::new_v4().to_string()).bind(user_id).bind(&id).fetch_optional(&mut *conn).await?;
                let row_id: String = sqlx::query_scalar(
                    "SELECT id FROM user_groups WHERE user_id=$1 AND group_id=$2",
                )
                .bind(user_id)
                .bind(&id)
                .fetch_one(&mut *conn)
                .await?;
                if !had_value {
                    values.push(group_value.clone());
                    sqlx::query("UPDATE users SET groups=$3 WHERE id=$1 AND owner=$2")
                        .bind(user_id)
                        .bind(&s.organization)
                        .bind(json!(values))
                        .execute(&mut *conn)
                        .await?;
                }
                if let Some(old) = existing {
                    if old.group_id != id || old.group_value != group_value {
                        return Err(invalid("Cloud membership binding changed unexpectedly"));
                    }
                    let replaced =
                        old.user_group_id.as_deref() != Some(row_id.as_str()) && inserted.is_none();
                    sqlx::query("UPDATE syncer_group_memberships SET user_group_id=$4,owns_user_group=CASE WHEN $5 THEN false WHEN $6 THEN true ELSE owns_user_group END,owns_user_group_value=CASE WHEN $5 THEN false ELSE owns_user_group_value END,manual_preserved=manual_preserved OR $5 WHERE syncer_id=$1 AND source_group_key=$2 AND user_id=$3")
                        .bind(&s.id).bind(&group.id).bind(user_id).bind(&row_id).bind(replaced).bind(inserted.is_some()).execute(&mut *conn).await?;
                } else {
                    let manual = inserted.is_none() || had_value;
                    sqlx::query("INSERT INTO syncer_group_memberships(syncer_id,source_group_key,source_user_key,user_id,group_id,user_group_id,group_value,owns_user_group,owns_user_group_value,manual_preserved) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                        .bind(&s.id).bind(&group.id).bind(source_id).bind(user_id).bind(&id).bind(&row_id).bind(&group_value).bind(inserted.is_some()).bind(!had_value&&!manual).bind(manual).execute(&mut *conn).await?;
                }
                desired.insert((group.id.clone(), user_id.clone()));
            }
        }
        let previous:Vec<(String,String)>=sqlx::query_as("SELECT source_group_key,user_id FROM syncer_group_memberships WHERE syncer_id=$1 ORDER BY user_id,source_group_key").bind(&s.id).fetch_all(&mut *conn).await?;
        for (group, user) in previous {
            if !desired.contains(&(group.clone(), user.clone())) {
                Self::retract_membership(conn, s, &group, &user).await?;
            }
        }
        let active: Vec<String> = snapshot
            .groups
            .iter()
            .map(|group| group.id.clone())
            .collect();
        sqlx::query("UPDATE syncer_group_links SET active=(source_key=ANY($2)) WHERE syncer_id=$1")
            .bind(&s.id)
            .bind(active)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
    async fn retract_membership(
        conn: &mut PgConnection,
        s: &Syncer,
        source_group: &str,
        user_id: &str,
    ) -> AppResult<()> {
        // Same lock order as explicit manual add: user, then managed ledger,
        // then the concrete pair. The ledger flag is read only after locking it.
        let profile: Option<(String, Option<Value>)> =
            sqlx::query_as("SELECT owner,groups FROM users WHERE id=$1 FOR UPDATE")
                .bind(user_id)
                .fetch_optional(&mut *conn)
                .await?;
        let Some((owner, values)) = profile else {
            return Ok(());
        };
        if owner != s.organization {
            return Err(invalid("Managed cloud member moved to a different tenant"));
        }
        let old:Option<Membership>=sqlx::query_as("SELECT source_group_key,user_id,group_id,user_group_id,group_value,owns_user_group,owns_user_group_value,manual_preserved FROM syncer_group_memberships WHERE syncer_id=$1 AND source_group_key=$2 AND user_id=$3 FOR UPDATE").bind(&s.id).bind(source_group).bind(user_id).fetch_optional(&mut *conn).await?;
        let Some(old) = old else {
            return Ok(());
        };
        let current: Option<String> =
            sqlx::query_scalar("SELECT id FROM user_groups WHERE user_id=$1 AND group_id=$2")
                .bind(user_id)
                .bind(&old.group_id)
                .fetch_optional(&mut *conn)
                .await?;
        let other:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM syncer_group_memberships WHERE user_id=$1 AND group_id=$2 AND syncer_id<>$3)").bind(user_id).bind(&old.group_id).bind(&s.id).fetch_one(&mut *conn).await?;
        let replaced = current.is_some() && current != old.user_group_id;
        if !old.manual_preserved && !other && !replaced {
            if old.owns_user_group {
                if let Some(id) = old.user_group_id {
                    sqlx::query(
                        "DELETE FROM user_groups WHERE id=$1 AND user_id=$2 AND group_id=$3",
                    )
                    .bind(id)
                    .bind(user_id)
                    .bind(&old.group_id)
                    .execute(&mut *conn)
                    .await?;
                }
            }
            if old.owns_user_group_value {
                let mut values = group_values(values)?;
                values.retain(|value| value != &old.group_value);
                sqlx::query("UPDATE users SET groups=$3 WHERE id=$1 AND owner=$2")
                    .bind(user_id)
                    .bind(&s.organization)
                    .bind(json!(values))
                    .execute(&mut *conn)
                    .await?;
            }
        }
        sqlx::query("DELETE FROM syncer_group_memberships WHERE syncer_id=$1 AND source_group_key=$2 AND user_id=$3").bind(&s.id).bind(source_group).bind(user_id).execute(&mut *conn).await?;
        Ok(())
    }
    /// Detaching a connector retracts only its managed authority, retaining group
    /// records and explicit manual memberships for local policy references.
    pub async fn detach(conn: &mut PgConnection, s: &Syncer) -> AppResult<()> {
        let rows:Vec<(String,String)>=sqlx::query_as("SELECT source_group_key,user_id FROM syncer_group_memberships WHERE syncer_id=$1 ORDER BY user_id,source_group_key").bind(&s.id).fetch_all(&mut *conn).await?;
        for (group, user) in rows {
            Self::retract_membership(conn, s, &group, &user).await?;
        }
        sqlx::query("UPDATE syncer_group_links SET active=false WHERE syncer_id=$1")
            .bind(&s.id)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}
