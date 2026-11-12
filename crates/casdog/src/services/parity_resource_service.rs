use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};

use crate::error::{AppError, AppResult};
use crate::hoops::authz::Principal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Agent,
    Entry,
    Key,
    Server,
    Integration,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Entry => "entry",
            Self::Key => "key",
            Self::Server => "server",
            Self::Integration => "integration",
        }
    }
    pub fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Agent => &["url", "token", "application"],
            Self::Entry => &[
                "provider",
                "application",
                "type",
                "clientIp",
                "userAgent",
                "message",
            ],
            Self::Key => &[
                "type",
                "organization",
                "application",
                "user",
                "accessKey",
                "accessSecret",
                "expireTime",
                "state",
            ],
            Self::Server => &["url", "token", "application", "tools"],
            Self::Integration => &[
                "integrationId",
                "type",
                "version",
                "logo",
                "variables",
                "application",
                "provider",
                "backup",
                "bundle",
                "resourceId",
            ],
        }
    }
    pub fn field_allowed(self, field: &str) -> bool {
        ["owner", "name", "createdTime", "updatedTime", "displayName"].contains(&field)
            || self.fields().contains(&field)
    }
}

pub fn denied() -> AppError {
    AppError::Authorization("Organization administrator permission required".into())
}
pub fn authorize(principal: &Principal, owner: &str) -> AppResult<()> {
    if principal.global_admin() || (principal.admin && principal.owner == owner) {
        Ok(())
    } else {
        Err(denied())
    }
}
pub fn identity(owner: &str, name: &str) -> AppResult<()> {
    if [owner, name].iter().any(|s| {
        s.is_empty() || s.len() > 100 || s.contains('/') || s.chars().any(char::is_control)
    }) {
        return Err(AppError::Validation("owner and name must be nonempty, at most 100 bytes and contain no slash/control characters".into()));
    }
    Ok(())
}
pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}
pub fn random_secret() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Revalidate the authenticated session after acquiring the same account locks as
/// logout/password changes. All reads and token insertion use the caller's transaction.
pub async fn validate_mcp_session_conn(
    conn: &mut PgConnection,
    principal: &Principal,
    claims: &crate::services::auth_service::Claims,
    bearer: &str,
) -> AppResult<()> {
    let invalid = || AppError::Authentication("Session changed or expired; sign in again".into());
    if claims.sub != principal.id
        || claims.owner != principal.owner
        || claims.name != principal.name
    {
        return Err(invalid());
    }
    let mut ids = vec![principal.id.clone()];
    if let Some(id) = &claims.impersonator_user_id {
        ids.push(id.clone());
    }
    ids.sort();
    ids.dedup();
    let rows:Vec<(String,String,String,bool,Option<String>)>=sqlx::query_as("SELECT id,owner,name,is_admin,last_change_password_time FROM users WHERE id=ANY($1) AND NOT is_deleted AND NOT is_forbidden ORDER BY id FOR UPDATE")
        .bind(&ids).fetch_all(&mut *conn).await?;
    if rows.len() != ids.len() || claims.exp <= Utc::now().timestamp() {
        return Err(invalid());
    }
    let stale = |cutoff: chrono::DateTime<Utc>| match claims.issued_at_ms {
        Some(ms) => ms <= cutoff.timestamp_millis(),
        None => claims.iat <= cutoff.timestamp(),
    };
    for (id, owner, name, admin, changed) in rows {
        if id == principal.id {
            if owner != principal.owner || name != principal.name || (principal.admin && !admin) {
                return Err(invalid());
            }
        } else if !admin || claims.impersonator_owner.as_deref() != Some(owner.as_str()) {
            return Err(invalid());
        }
        if let Some(changed) = changed.filter(|value| !value.is_empty()) {
            let cutoff = chrono::DateTime::parse_from_rfc3339(&changed)
                .map_err(|_| invalid())?
                .with_timezone(&Utc);
            if stale(cutoff) {
                return Err(invalid());
            }
        }
        let cutoff: Option<chrono::DateTime<Utc>> =
            sqlx::query_scalar("SELECT invalid_before FROM user_session_epochs WHERE user_id=$1")
                .bind(&id)
                .fetch_optional(&mut *conn)
                .await?;
        if cutoff.is_some_and(stale) {
            return Err(invalid());
        }
    }
    let revoked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM revoked_session_tokens WHERE token_hash=$1 AND expires_at>clock_timestamp())")
        .bind(crate::hoops::auth::session_fingerprint(bearer)).fetch_one(&mut *conn).await?;
    if revoked {
        return Err(invalid());
    }
    if claims.impersonator_user_id.is_some() {
        let session = claims
            .impersonation_session_id
            .as_deref()
            .ok_or_else(invalid)?;
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id=$1 AND session_id=$2)",
        )
        .bind(&principal.id)
        .bind(session)
        .fetch_one(&mut *conn)
        .await?;
        if !active {
            return Err(invalid());
        }
    }
    Ok(())
}
pub fn masked(kind: Kind, mut document: Value, list: bool) -> Value {
    if matches!(kind, Kind::Server | Kind::Agent) {
        document["token"] = json!("");
    }
    if kind == Kind::Key && list {
        document["accessSecret"] = json!("***");
    }
    if kind == Kind::Integration {
        document.as_object_mut().unwrap().remove("backup");
        document.as_object_mut().unwrap().remove("bundle");
        document.as_object_mut().unwrap().remove("resourceId");
    }
    document
}

pub async fn get(pool: &PgPool, kind: Kind, owner: &str, name: &str) -> AppResult<Option<Value>> {
    Ok(sqlx::query_scalar(
        "SELECT document FROM casdoor_objects WHERE kind=$1 AND owner=$2 AND name=$3",
    )
    .bind(kind.name())
    .bind(owner)
    .bind(name)
    .fetch_optional(pool)
    .await?)
}

pub async fn application(pool: &PgPool, owner: &str, name: &str) -> AppResult<Value> {
    application_conn(&mut *pool.acquire().await?, owner, name).await
}
async fn application_conn(conn: &mut PgConnection, owner: &str, name: &str) -> AppResult<Value> {
    let (qualified_owner, name) = name
        .split_once('/')
        .map(|(o, n)| (Some(o), n))
        .unwrap_or((None, name));
    sqlx::query_scalar("SELECT to_jsonb(a) FROM applications a WHERE organization=$1 AND name=$2 AND ($3::text IS NULL OR owner=$3) AND NOT is_deleted")
        .bind(owner).bind(name).bind(qualified_owner).fetch_optional(conn).await?
        .ok_or_else(|| AppError::Validation("Application does not exist in this organization".into()))
}

async fn validate(conn: &mut PgConnection, kind: Kind, document: &Value) -> AppResult<()> {
    let owner = text(document, "owner");
    identity(owner, text(document, "name"))?;
    for (key, value) in document
        .as_object()
        .ok_or_else(|| AppError::Validation("Object body required".into()))?
    {
        if !kind.field_allowed(key) {
            return Err(AppError::Validation(format!(
                "Unsupported {} field: {key}",
                kind.name()
            )));
        }
        if key == "tools" {
            if !value.is_array() {
                return Err(AppError::Validation("tools must be an array".into()));
            }
            for tool in value.as_array().unwrap() {
                if text(tool, "name").is_empty()
                    || !tool.get("inputSchema").is_some_and(Value::is_object)
                    || tool.get("isAllowed").is_some_and(|v| !v.is_boolean())
                {
                    return Err(AppError::Validation(
                        "Each tool needs a name, object inputSchema and optional boolean isAllowed"
                            .into(),
                    ));
                }
            }
        } else if !matches!(key.as_str(), "variables") && !value.is_string() {
            return Err(AppError::Validation(format!("{key} must be a string")));
        }
        if value.as_str().is_some_and(|v| {
            v.len()
                > if key == "message" {
                    2 * 1024 * 1024
                } else {
                    65536
                }
        }) {
            return Err(AppError::Validation(format!("{key} exceeds size limit")));
        }
    }
    if matches!(kind, Kind::Agent | Kind::Server) {
        let url = reqwest::Url::parse(text(document, "url"))
            .map_err(|_| AppError::Validation("A valid HTTP(S) URL is required".into()))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(AppError::Validation(
                "A valid HTTP(S) URL without credentials is required".into(),
            ));
        }
    }
    let app = text(document, "application");
    if !app.is_empty() {
        application_conn(conn, owner, app).await?;
    }
    if kind == Kind::Entry && !text(document, "provider").is_empty() {
        let provider = text(document, "provider");
        let (provider_owner, name) = provider.split_once('/').unwrap_or((owner, provider));
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM providers WHERE owner=$1 AND name=$2)")
                .bind(owner)
                .bind(name)
                .fetch_one(&mut *conn)
                .await?;
        if provider_owner != owner || !exists {
            return Err(AppError::Validation(
                "Provider does not exist in this organization".into(),
            ));
        }
    }
    if kind == Kind::Key {
        let scope = text(document, "type");
        if !["Organization", "Application", "User", "General"].contains(&scope) {
            return Err(AppError::Validation("Invalid key type".into()));
        }
        if !["Active", "Inactive"].contains(&text(document, "state")) {
            return Err(AppError::Validation(
                "Key state must be Active or Inactive".into(),
            ));
        }
        let org = text(document, "organization");
        if !org.is_empty() && org != owner {
            return Err(AppError::Validation(
                "Key organization must equal owner".into(),
            ));
        }
        if scope != "General" && org.is_empty() {
            return Err(AppError::Validation("Scoped key needs organization".into()));
        }
        if !app.is_empty() || !text(document, "user").is_empty() {
            if org != owner {
                return Err(AppError::Validation(
                    "Subject-bound key needs its owner's organization".into(),
                ));
            }
            let active: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin)",
            ).bind(org).fetch_one(&mut *conn).await?;
            if !active {
                return Err(AppError::Validation(
                    "Key organization is unavailable".into(),
                ));
            }
        }
        if scope == "Application" && app.is_empty() {
            return Err(AppError::Validation(
                "Application key needs application".into(),
            ));
        }
        if scope == "User" && text(document, "user").is_empty() {
            return Err(AppError::Validation("User key needs user".into()));
        }
        if !text(document, "user").is_empty() {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE owner=$1 AND name=$2 AND NOT is_deleted AND NOT is_forbidden)")
                .bind(owner).bind(text(document,"user")).fetch_one(&mut *conn).await?;
            if !exists {
                return Err(AppError::Validation(
                    "Key user is not active in this organization".into(),
                ));
            }
        }
        let expiry = text(document, "expireTime");
        if !expiry.is_empty() {
            chrono::DateTime::parse_from_rfc3339(expiry)
                .map_err(|_| AppError::Validation("expireTime must be RFC3339".into()))?;
        }
    }
    Ok(())
}

pub async fn save(
    pool: &PgPool,
    principal: &Principal,
    kind: Kind,
    owner: &str,
    name: &str,
    input: Value,
    update: bool,
) -> AppResult<Option<Value>> {
    authorize(principal, owner)?;
    identity(owner, name)?;
    let input = input
        .as_object()
        .ok_or_else(|| AppError::Validation("Object body required".into()))?;
    for (field, expected) in [("owner", owner), ("name", name)] {
        if input
            .get(field)
            .is_some_and(|v| v.as_str() != Some(expected))
        {
            return Err(AppError::Validation(
                "Resource identity cannot be changed".into(),
            ));
        }
    }
    let mut tx = pool.begin().await?;
    // Lock updates so concurrent field edits and masked secret roundtrips cannot lose data.
    let old: Option<Value> = sqlx::query_scalar(
        "SELECT document FROM casdoor_objects WHERE kind=$1 AND owner=$2 AND name=$3 FOR UPDATE",
    )
    .bind(kind.name())
    .bind(owner)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    if update && old.is_none() {
        return Ok(None);
    }
    if !update && old.is_some() {
        return Err(AppError::Conflict("Resource already exists".into()));
    }
    let mut document = old.clone().unwrap_or_else(|| json!({"owner":owner,"name":name,"createdTime":Utc::now().to_rfc3339(),"displayName":name}));
    for (key, value) in input {
        if matches!(
            key.as_str(),
            "createdTime" | "updatedTime" | "accessKey" | "accessSecret"
        ) {
            continue;
        }
        if update
            && matches!(kind, Kind::Server | Kind::Agent)
            && key == "token"
            && matches!(value.as_str(), Some("" | "***"))
        {
            continue;
        }
        document[key] = value.clone();
    }
    document["updatedTime"] = json!(Utc::now().to_rfc3339());
    if !update && kind == Kind::Key {
        document["accessKey"] = json!(random_secret());
        document["accessSecret"] = json!(random_secret());
        if document.get("type").is_none() {
            document["type"] = json!("General");
        }
        if document.get("state").is_none() {
            document["state"] = json!("Active");
        }
    }
    validate(&mut *tx, kind, &document).await?;
    if update {
        sqlx::query("UPDATE casdoor_objects SET document=$4,updated_at=NOW() WHERE kind=$1 AND owner=$2 AND name=$3")
            .bind(kind.name()).bind(owner).bind(name).bind(&document).execute(&mut *tx).await?;
    } else {
        sqlx::query("INSERT INTO casdoor_objects(kind,owner,name,document) VALUES($1,$2,$3,$4)")
            .bind(kind.name())
            .bind(owner)
            .bind(name)
            .bind(&document)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Some(document))
}

pub async fn delete(
    pool: &PgPool,
    principal: &Principal,
    kind: Kind,
    owner: &str,
    name: &str,
) -> AppResult<bool> {
    authorize(principal, owner)?;
    Ok(
        sqlx::query("DELETE FROM casdoor_objects WHERE kind=$1 AND owner=$2 AND name=$3")
            .bind(kind.name())
            .bind(owner)
            .bind(name)
            .execute(pool)
            .await?
            .rows_affected()
            > 0,
    )
}

pub struct ListOptions {
    pub owner: Option<String>,
    pub field: Option<String>,
    pub value: String,
    pub sort: String,
    pub descending: bool,
    pub limit: Option<i64>,
    pub offset: i64,
}
pub async fn list(
    pool: &PgPool,
    principal: &Principal,
    kind: Kind,
    options: ListOptions,
) -> AppResult<(Vec<Value>, i64)> {
    if let Some(owner) = &options.owner {
        authorize(principal, owner)?;
    } else if !principal.global_admin() {
        return Err(denied());
    }
    for field in options.field.iter().chain(std::iter::once(&options.sort)) {
        if !kind.field_allowed(field)
            || matches!(
                field.as_str(),
                "token" | "accessSecret" | "bundle" | "backup" | "variables" | "tools" | "message"
            )
        {
            return Err(AppError::Validation("Unsupported search/sort field".into()));
        }
    }
    let filter = "kind=$1 AND ($2::text IS NULL OR owner=$2) AND ($3::text IS NULL OR document->>$3 ILIKE $4)";
    let search = format!("%{}%", options.value);
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM casdoor_objects WHERE {filter}"
    ))
    .bind(kind.name())
    .bind(&options.owner)
    .bind(&options.field)
    .bind(&search)
    .fetch_one(pool)
    .await?;
    let direction = if options.descending { "DESC" } else { "ASC" };
    let rows: Vec<Value>=sqlx::query_scalar(&format!("SELECT document FROM casdoor_objects WHERE {filter} ORDER BY document->>$5 {direction},name ASC LIMIT $6 OFFSET $7"))
        .bind(kind.name()).bind(&options.owner).bind(&options.field).bind(&search).bind(&options.sort).bind(options.limit).bind(options.offset).fetch_all(pool).await?;
    let data = rows
        .into_iter()
        .map(|doc| masked(kind, doc, true))
        .collect();
    Ok((data, total))
}
