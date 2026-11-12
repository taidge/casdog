use chrono::{DateTime, Utc};
use rand::{Rng, RngCore};
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use std::{
    collections::HashSet,
    path::{Component, Path},
};

use crate::handlers::parity_resources::service::{self as resources, Kind, text};
use crate::{
    diesel_pool::DieselPool,
    error::{AppError, AppResult},
    hoops::authz::Principal,
    models::{Application, Provider, Resource, User, UserResponse},
    services::{
        AuthService, CheckService, UserService, id_token_service::IdTokenService,
        social_state_service::proof_hash,
    },
};

/// Tenant-controlled Local providers can choose only directories in the
/// operator-controlled owner namespace, including when reading existing rows.
pub async fn local_storage_root(
    principal: &Principal,
    owner: &str,
    bucket: Option<&str>,
    create: bool,
) -> AppResult<std::path::PathBuf> {
    use std::path::PathBuf;
    let bucket = bucket.filter(|value| !value.trim().is_empty());
    if !principal.global_admin() && principal.owner != owner {
        return Err(AppError::Authorization("Storage owner mismatch".into()));
    }
    resources::identity(owner, "storage")?;
    if owner.contains(['\\', ':']) || matches!(owner, "." | "..") {
        return Err(AppError::Validation("Invalid storage owner".into()));
    }
    let base = PathBuf::from(
        std::env::var_os("CASDOG_LOCAL_STORAGE_ROOT").unwrap_or_else(|| "./uploads".into()),
    );
    if principal.global_admin() && bucket.is_some() {
        let path = PathBuf::from(bucket.unwrap());
        if create {
            tokio::fs::create_dir_all(&path)
                .await
                .map_err(|_| AppError::Internal("Cannot create storage directory".into()))?;
        }
        return tokio::fs::canonicalize(path)
            .await
            .map_err(|_| AppError::NotFound("Storage directory unavailable".into()));
    }
    if create {
        tokio::fs::create_dir_all(&base)
            .await
            .map_err(|_| AppError::Internal("Cannot create local storage root".into()))?;
    }
    let base = tokio::fs::canonicalize(&base)
        .await
        .map_err(|_| AppError::NotFound("Local storage root unavailable".into()))?;
    let namespace = base.join(proof_hash(owner));
    if let Ok(metadata) = tokio::fs::symlink_metadata(&namespace).await {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(AppError::Authorization(
                    "Storage namespace cannot be a link".into(),
                ));
            }
        }
        if metadata.file_type().is_symlink() {
            return Err(AppError::Authorization(
                "Storage namespace cannot be a link".into(),
            ));
        }
    }
    if create {
        tokio::fs::create_dir_all(&namespace)
            .await
            .map_err(|_| AppError::Internal("Cannot create storage namespace".into()))?;
    }
    let namespace = tokio::fs::canonicalize(namespace)
        .await
        .map_err(|_| AppError::NotFound("Storage namespace unavailable".into()))?;
    if !namespace.starts_with(&base) {
        return Err(AppError::Authorization(
            "Storage namespace escapes root".into(),
        ));
    }
    let Some(bucket) = bucket.filter(|bucket| !bucket.is_empty()) else {
        return Ok(namespace);
    };
    // Reject outside paths before canonicalization, which could otherwise contact
    // an attacker-controlled UNC share on Windows.
    let requested = PathBuf::from(bucket);
    let requested = if requested.is_absolute() {
        requested
    } else {
        std::env::current_dir()
            .map_err(|_| AppError::Internal("Working directory unavailable".into()))?
            .join(requested)
    };
    let normalize = |path: &Path| {
        let value = path
            .components()
            .filter(|part| !matches!(part, Component::CurDir))
            .collect::<PathBuf>();
        #[cfg(windows)]
        {
            let value = value.to_string_lossy().replace('\\', "/");
            value
                .strip_prefix("//?/UNC/")
                .map(|tail| format!("//{tail}"))
                .unwrap_or_else(|| value.strip_prefix("//?/").unwrap_or(&value).to_string())
                .to_ascii_lowercase()
        }
        #[cfg(not(windows))]
        {
            value.to_string_lossy().to_string()
        }
    };
    let requested_text = normalize(&requested);
    let allowed_text = normalize(&namespace);
    if requested_text != allowed_text && !requested_text.starts_with(&format!("{allowed_text}/")) {
        return Err(AppError::Authorization(
            "Local bucket is outside this tenant's storage namespace".into(),
        ));
    }
    let mut existing = PathBuf::from(bucket);
    if existing
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(AppError::Authorization(
            "Storage bucket cannot contain parent traversal".into(),
        ));
    }
    let mut missing = Vec::new();
    let canonical = loop {
        match tokio::fs::canonicalize(&existing).await {
            Ok(path) => break path,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    existing
                        .file_name()
                        .ok_or_else(|| AppError::Authorization("Invalid storage bucket".into()))?
                        .to_os_string(),
                );
                if !existing.pop() {
                    return Err(AppError::Authorization(
                        "Storage bucket is outside namespace".into(),
                    ));
                }
            }
            Err(_) => return Err(AppError::NotFound("Storage bucket unavailable".into())),
        }
    };
    if !canonical.starts_with(&namespace) {
        return Err(AppError::Authorization(
            "Local bucket is outside this tenant's storage namespace".into(),
        ));
    }
    let path = missing
        .into_iter()
        .rev()
        .fold(canonical, |path, part| path.join(part));
    if create {
        tokio::fs::create_dir_all(&path)
            .await
            .map_err(|_| AppError::Internal("Cannot create storage bucket".into()))?;
    }
    Ok(path)
}

pub async fn storage_for_owner(
    principal: &Principal,
    owner: &str,
    provider: Option<&Provider>,
    create: bool,
) -> AppResult<(
    Box<dyn crate::services::providers::StorageProvider>,
    Option<std::path::PathBuf>,
)> {
    if provider.is_some_and(|provider| provider.owner != owner)
        || (!principal.global_admin() && principal.owner != owner)
    {
        return Err(AppError::Authorization(
            "Storage provider owner mismatch".into(),
        ));
    }
    let kind = provider
        .map(|provider| provider.provider_type.as_str())
        .unwrap_or("local");
    if kind.eq_ignore_ascii_case("local") || kind.eq_ignore_ascii_case("Local File System") {
        let root = local_storage_root(
            principal,
            owner,
            provider.and_then(|provider| provider.bucket.as_deref()),
            create,
        )
        .await?;
        let storage = crate::services::providers::get_storage_provider(
            "local",
            "",
            "",
            "",
            root.to_str()
                .ok_or_else(|| AppError::Config("Storage path must be UTF-8".into()))?,
            "",
        )?;
        return Ok((storage, Some(root)));
    }
    if !kind.eq_ignore_ascii_case("s3") {
        return Err(AppError::Config("Unsupported storage provider type".into()));
    }
    let provider = provider.ok_or_else(|| AppError::Config("Storage provider required".into()))?;
    let bucket = provider.bucket.as_deref().unwrap_or("");
    let region = provider.region_id.as_deref().unwrap_or("");
    let endpoint = provider.endpoint.as_deref().unwrap_or("");
    let storage = crate::services::providers::s3_storage::S3StorageProvider::new(
        provider.client_id.as_deref().unwrap_or("").into(),
        provider.client_secret.as_deref().unwrap_or("").into(),
        region.into(),
        bucket.into(),
        endpoint.into(),
    );
    // Validate and pin the exact origin used by the provider's object requests.
    let client =
        crate::services::system_gap_service::client(&storage.base_url()?, principal.global_admin())
            .await?;
    let storage = storage.with_client(client);
    Ok((Box::new(storage), None))
}

pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEVICE_LIFETIME: i64 = 600;
const PREVIEW_LIMIT: usize = 2 * 1024 * 1024;

fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn invalid() -> AppError {
    AppError::Authentication("Invalid or expired device authorization".into())
}
fn grant_enabled(app: &Application) -> AppResult<()> {
    if app.is_deleted
        || app
            .grant_types
            .as_ref()
            .and_then(Value::as_array)
            .is_none_or(|grants| !grants.iter().any(|g| g.as_str() == Some(DEVICE_GRANT)))
    {
        return Err(AppError::Authorization(
            "Device authorization grant is not enabled".into(),
        ));
    }
    Ok(())
}
#[derive(sqlx::FromRow)]
pub struct DeviceState {
    pub device_hash: String,
    pub application_id: String,
    pub organization: String,
    pub scope: String,
    pub status: String,
    pub user_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub approval_token_hash: Option<String>,
    pub approval_expires_at: Option<DateTime<Utc>>,
    pub last_poll_at: Option<DateTime<Utc>>,
    pub poll_interval: i32,
    pub token_id: Option<String>,
}
pub async fn begin_device(
    pool: &PgPool,
    app: &Application,
    scope: &str,
    origin: &str,
) -> AppResult<Value> {
    grant_enabled(app)?;
    if scope.len() > 2048 || scope.chars().any(char::is_control) {
        return Err(AppError::Validation("Invalid scope".into()));
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("device:{}", app.id))
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM device_authorizations WHERE expires_at < clock_timestamp()")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_authorizations WHERE application_id=$1 AND status IN ('pending','approved')")
        .bind(&app.id).fetch_one(&mut *tx).await?;
    if count >= 1000 {
        return Err(AppError::Validation(
            "Too many pending device requests".into(),
        ));
    }
    let device = secret();
    let cancel = secret();
    const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
    let mut rng = rand::rngs::OsRng;
    let letters: String = (0..8)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    let user_code = format!("{}-{}", &letters[..4], &letters[4..]);
    sqlx::query("INSERT INTO device_authorizations(device_hash,user_code,cancel_hash,application_id,organization,scope) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(proof_hash(&device)).bind(&user_code).bind(proof_hash(&cancel))
        .bind(&app.id).bind(&app.organization).bind(scope).execute(&mut *tx).await?;
    tx.commit().await?;
    let uri = format!("{}/?user_code={user_code}", origin.trim_end_matches('/'));
    Ok(
        json!({"device_code":device,"user_code":user_code,"cancel_token":cancel,"verification_uri":format!("{}/",origin.trim_end_matches('/')),"verification_uri_complete":uri,"expires_in":DEVICE_LIFETIME,"interval":5}),
    )
}
pub async fn application_for_user_code(pool: &PgPool, code: &str) -> AppResult<String> {
    sqlx::query_scalar("SELECT application_id FROM device_authorizations WHERE user_code=$1 AND expires_at>clock_timestamp() AND status='pending'")
        .bind(code.to_ascii_uppercase()).fetch_optional(pool).await?.ok_or_else(invalid)
}
pub async fn verify_device(pool: &PgPool, principal: &Principal, code: &str) -> AppResult<Value> {
    let row: Option<(String,String,String,String)> = sqlx::query_as("SELECT d.application_id,a.display_name,d.scope,d.organization FROM device_authorizations d JOIN applications a ON a.id=d.application_id WHERE d.user_code=$1 AND d.status='pending' AND d.expires_at>clock_timestamp() AND NOT a.is_deleted")
        .bind(code.trim().to_ascii_uppercase()).fetch_optional(pool).await?;
    let (app, display, scope, organization) = row.ok_or_else(invalid)?;
    if organization != principal.owner {
        return Err(AppError::Authorization(
            "Device belongs to another organization".into(),
        ));
    }
    CheckService::check_login_permission(pool, &principal.id, &app).await?;
    // The browser receives the human code as its approval handle, never the device secret.
    Ok(json!({"device_code":code.trim().to_ascii_uppercase(),"application":display,"scope":scope}))
}
pub async fn authorize_device(
    pool: &PgPool,
    principal: &Principal,
    code: &str,
    approved: bool,
    claims: &crate::services::auth_service::Claims,
    bearer: &str,
) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    if claims.impersonator_user_id.is_some() {
        return Err(AppError::Authorization(
            "Impersonated sessions cannot authorize devices".into(),
        ));
    }
    resources::validate_mcp_session_conn(&mut tx, principal, claims, bearer).await?;
    let user: User = sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE")
        .bind(&principal.id).bind(&principal.owner).fetch_optional(&mut *tx).await?.ok_or_else(invalid)?;
    let row: Option<(String,String)> = sqlx::query_as("SELECT application_id,organization FROM device_authorizations WHERE user_code=$1 AND status='pending' AND expires_at>clock_timestamp() FOR UPDATE")
        .bind(code.trim().to_ascii_uppercase()).fetch_optional(&mut *tx).await?;
    let (app_id, org) = row.ok_or_else(invalid)?;
    if org != user.owner {
        return Err(AppError::Authorization(
            "Device belongs to another organization".into(),
        ));
    }
    let app: Application = sqlx::query_as("SELECT * FROM applications WHERE id=$1 FOR SHARE")
        .bind(&app_id)
        .fetch_one(&mut *tx)
        .await?;
    grant_enabled(&app)?;
    crate::handlers::social_login::ensure_social_account_policy_conn(&mut tx, &user).await?;
    CheckService::check_login_permission_conn(&mut tx, &user.id, &app.id).await?;
    if user.need_update_password {
        return Err(AppError::Authentication(
            "Update your password before authorizing a device".into(),
        ));
    }
    sqlx::query("UPDATE device_authorizations SET status=$2,user_id=$3,approved_at=clock_timestamp(),approval_token_hash=$4,approval_expires_at=to_timestamp($5) WHERE user_code=$1")
        .bind(code.trim().to_ascii_uppercase()).bind(if approved {"approved"} else {"denied"})
        .bind(&user.id).bind(crate::hoops::auth::session_fingerprint(bearer))
        .bind(claims.exp as f64).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
pub async fn cancel_device(pool: &PgPool, code: &str, cancel: &str) -> AppResult<()> {
    let affected = sqlx::query("UPDATE device_authorizations SET status='cancelled' WHERE user_code=$1 AND cancel_hash=$2 AND status IN ('pending','approved','denied') AND expires_at>clock_timestamp()")
        .bind(code.to_ascii_uppercase()).bind(proof_hash(cancel)).execute(pool).await?.rows_affected();
    if affected != 1 {
        return Err(invalid());
    }
    Ok(())
}
async fn current_device_user(
    conn: &mut PgConnection,
    state: &DeviceState,
    app: &Application,
) -> AppResult<User> {
    grant_enabled(app)?;
    if state.organization != app.organization || state.expires_at <= Utc::now() {
        return Err(invalid());
    }
    let user: User = sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE")
        .bind(&state.user_id).bind(&state.organization).fetch_optional(&mut *conn).await?.ok_or_else(invalid)?;
    crate::handlers::social_login::ensure_social_account_policy_conn(conn, &user).await?;
    CheckService::check_login_permission_conn(conn, &user.id, &app.id).await?;
    let approved = state.approved_at.ok_or_else(invalid)?;
    if state
        .approval_expires_at
        .is_none_or(|expires| expires <= Utc::now())
    {
        return Err(invalid());
    }
    let revoked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM revoked_session_tokens WHERE token_hash=$1 AND expires_at>clock_timestamp())")
        .bind(&state.approval_token_hash).fetch_one(&mut *conn).await?;
    if revoked {
        return Err(invalid());
    }

    let epoch: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT invalid_before FROM user_session_epochs WHERE user_id=$1")
            .bind(&user.id)
            .fetch_optional(&mut *conn)
            .await?;
    let changed = user
        .last_change_password_time
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|_| invalid())?;
    if user.need_update_password
        || epoch.is_some_and(|cutoff| approved <= cutoff)
        || changed.is_some_and(|cutoff| approved <= cutoff)
    {
        return Err(invalid());
    }
    Ok(user)
}
pub async fn poll_device(
    pool: &PgPool,
    diesel: &DieselPool,
    app: &Application,
    code: &str,
) -> AppResult<Value> {
    let mut tx = pool.begin().await?;
    // Match logout's user -> proof lock order to avoid deadlocks.
    let user_id: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM device_authorizations WHERE device_hash=$1")
            .bind(proof_hash(code))
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    if let Some(user_id) = user_id {
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
    }
    let state: Option<DeviceState> =
        sqlx::query_as("SELECT * FROM device_authorizations WHERE device_hash=$1 FOR UPDATE")
            .bind(proof_hash(code))
            .fetch_optional(&mut *tx)
            .await?;
    let Some(state) = state else {
        return Ok(json!({"error":"expired_token"}));
    };
    if state.application_id != app.id {
        return Err(invalid());
    }
    let current_app: Application =
        sqlx::query_as("SELECT * FROM applications WHERE id=$1 FOR SHARE")
            .bind(&app.id)
            .fetch_one(&mut *tx)
            .await?;
    if current_app.client_id != app.client_id || current_app.client_secret != app.client_secret {
        return Err(invalid());
    }
    let app = &current_app;
    grant_enabled(app)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    if state.expires_at <= now {
        return Ok(json!({"error":"expired_token"}));
    }
    if matches!(state.status.as_str(), "denied" | "cancelled") {
        return Ok(json!({"error":"access_denied"}));
    }
    if matches!(state.status.as_str(), "token_issued" | "completed") {
        return Ok(json!({"error":"invalid_grant"}));
    }
    let fast = state.last_poll_at.is_some_and(|last| {
        now.signed_duration_since(last).num_milliseconds() < i64::from(state.poll_interval) * 1000
    });
    let interval = if fast {
        state.poll_interval.saturating_add(5)
    } else {
        state.poll_interval
    };
    sqlx::query(
        "UPDATE device_authorizations SET last_poll_at=$2,poll_interval=$3 WHERE device_hash=$1",
    )
    .bind(&state.device_hash)
    .bind(now)
    .bind(interval)
    .execute(&mut *tx)
    .await?;
    if fast || state.status == "pending" {
        tx.commit().await?;
        return Ok(json!({"error":if fast {"slow_down"} else {"authorization_pending"}}));
    }
    let user = current_device_user(&mut tx, &state, app).await?;
    let response: UserResponse = user.clone().into();
    let auth = AuthService::new(UserService::new(diesel.clone()));
    let mut claims = auth.claims_for_user(&response);
    let expires = (i64::from(app.expire_in_hours) * 3600)
        .min(auth.expires_in_seconds())
        .max(1);
    claims.exp = now.timestamp() + expires;
    let access = auth.generate_token_from_claims(&claims)?;
    let refresh = secret();
    let id_token = if state
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
    {
        Some(
            IdTokenService::generate_id_token(
                diesel,
                &user.id,
                &user.name,
                &app.client_id,
                None,
                Some(&access),
                app.cert.as_deref(),
            )
            .await?,
        )
    } else {
        None
    };
    let token_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO tokens(id,owner,name,application,organization,user_id,access_token,refresh_token,expires_in,scope,token_type,created_at,code_is_used) VALUES($1,$2,$1,$3,$4,$5,$6,$7,$8,$9,'Bearer',clock_timestamp(),true)")
        .bind(&token_id).bind(&app.owner).bind(&app.name).bind(&app.organization).bind(&user.id)
        .bind(&access).bind(&refresh).bind(expires).bind(&state.scope).execute(&mut *tx).await?;
    let issued = sqlx::query(
        "UPDATE device_authorizations SET status='token_issued',token_id=$2 WHERE device_hash=$1 AND expires_at>clock_timestamp() AND approval_expires_at>clock_timestamp()",
    )
    .bind(&state.device_hash)
    .bind(&token_id)
    .execute(&mut *tx)
    .await?.rows_affected();
    if issued != 1 {
        return Err(invalid());
    }
    tx.commit().await?;
    Ok(
        json!({"access_token":access,"refresh_token":refresh,"token_type":"Bearer","expires_in":expires,"scope":state.scope,"id_token":id_token}),
    )
}
pub async fn complete_device(pool: &PgPool, code: &str) -> AppResult<Value> {
    let hash = proof_hash(code);
    let mut tx = pool.begin().await?;
    let user_id: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM device_authorizations WHERE device_hash=$1")
            .bind(&hash)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    let user_id = user_id.ok_or_else(invalid)?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    let state: DeviceState = sqlx::query_as("SELECT * FROM device_authorizations WHERE device_hash=$1 AND status='token_issued' FOR UPDATE")
        .bind(&hash).fetch_optional(&mut *tx).await?.ok_or_else(invalid)?;
    let app: Application = sqlx::query_as("SELECT * FROM applications WHERE id=$1 FOR SHARE")
        .bind(&state.application_id)
        .fetch_one(&mut *tx)
        .await?;
    let user = current_device_user(&mut tx, &state, &app).await?;
    let token: String = sqlx::query_scalar("SELECT access_token FROM tokens WHERE id=$1 AND created_at+expires_in*INTERVAL '1 second'>clock_timestamp()")
        .bind(&state.token_id).fetch_optional(&mut *tx).await?.ok_or_else(invalid)?;
    let completed = sqlx::query("UPDATE device_authorizations SET status='completed' WHERE device_hash=$1 AND expires_at>clock_timestamp() AND approval_expires_at>clock_timestamp()")
        .bind(hash).execute(&mut *tx).await?.rows_affected();
    if completed != 1 {
        return Err(invalid());
    }
    tx.commit().await?;
    Ok(json!({"token":token,"user":UserResponse::from(user),"token_type":"Bearer"}))
}

/// Upload the immutable raw object before publishing its session-scoped resource.
/// A database failure removes the unreferenced object, leaving the previous version readable.
pub async fn upload_transcript(
    pool: &PgPool,
    principal: &Principal,
    entry_id: &str,
    provider_name: &str,
    filename: &str,
    bytes: &[u8],
) -> AppResult<Value> {
    let (owner, name) = entry_id
        .split_once('/')
        .ok_or_else(|| AppError::Validation("entryId must be owner/name".into()))?;
    resources::authorize(principal, owner)?;
    resources::identity(owner, name)?;
    let entry = resources::get(pool, Kind::Entry, owner, name)
        .await?
        .ok_or_else(|| AppError::NotFound("Entry not found".into()))?;
    if text(&entry, "type") != "session" {
        return Err(AppError::Validation("Entry is not a session".into()));
    }
    let payload: Value = serde_json::from_str(text(&entry, "message"))
        .map_err(|_| AppError::Validation("Invalid OpenClaw payload".into()))?;
    let session = text(&payload, "sessionId");
    if session.is_empty() {
        return Err(AppError::Validation("Session ID missing".into()));
    }
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(AppError::Validation(
            "Transcript upload exceeds 32 MiB".into(),
        ));
    }
    std::str::from_utf8(bytes)
        .map_err(|_| AppError::Validation("Transcript must contain UTF-8 JSONL text".into()))?;
    let (provider_owner, provider_name) = provider_name
        .split_once('/')
        .unwrap_or((owner, provider_name));
    if provider_owner != owner {
        return Err(AppError::Authorization(
            "Storage provider belongs to another organization".into(),
        ));
    }
    let provider: Provider =
        sqlx::query_as("SELECT * FROM providers WHERE owner=$1 AND name=$2 AND category='Storage'")
            .bind(owner)
            .bind(provider_name)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| AppError::NotFound("Storage provider not found".into()))?;
    let (storage, _) = storage_for_owner(principal, owner, Some(&provider), true).await?;
    use md5::{Digest, Md5};
    let group = hex::encode(Md5::digest(format!(
        "{owner}|{}|{session}",
        text(&entry, "provider")
    )));
    let parent = format!("openclaw/{group}");
    let object_key = format!("openclaw/{group}/{}.jsonl", uuid::Uuid::new_v4());
    let url = storage
        .upload(&object_key, bytes, "application/jsonl")
        .await?;
    let filename = Path::new(filename)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("transcript.jsonl");
    let id = uuid::Uuid::new_v4().to_string();
    let inserted=sqlx::query("INSERT INTO resources(id,owner,name,user_id,provider,application,tag,parent,file_name,file_type,file_format,file_size,url,description) VALUES($1,$2,$3,$4,$5,$6,'openclawTranscript',$7,$8,'application/jsonl','.jsonl',$9,$10,'OpenClaw raw session transcript')")
        .bind(&id).bind(owner).bind(&object_key).bind(&principal.id).bind(provider_name)
        .bind(text(&entry,"application")).bind(&parent).bind(filename).bind(bytes.len() as i64).bind(&url).execute(pool).await;
    if let Err(error) = inserted {
        let _ = storage.delete(&object_key).await;
        return Err(error.into());
    }
    Ok(
        json!({"id":id,"name":filename,"url":url,"size":bytes.len(),"file_type":"application/jsonl"}),
    )
}

pub async fn transcript(
    pool: &PgPool,
    principal: &Principal,
    owner: &str,
    name: &str,
) -> AppResult<Value> {
    resources::authorize(principal, owner)?;
    let entry = resources::get(pool, Kind::Entry, owner, name)
        .await?
        .ok_or_else(|| AppError::NotFound("Entry not found".into()))?;
    if text(&entry, "type") != "session" {
        return Err(AppError::Validation("Entry is not a session".into()));
    }
    let payload: Value = serde_json::from_str(text(&entry, "message"))
        .map_err(|_| AppError::Validation("Invalid OpenClaw payload".into()))?;
    let session = text(&payload, "sessionId");
    if session.is_empty() {
        return Err(AppError::Validation("Session ID missing".into()));
    }
    use md5::{Digest, Md5};
    let parent = format!(
        "openclaw/{}",
        hex::encode(Md5::digest(
            format!("{owner}|{}|{session}", text(&entry, "provider")).as_bytes()
        ))
    );
    let resource: Resource = sqlx::query_as("SELECT resources.*,user_id AS \"user\" FROM resources WHERE owner=$1 AND tag='openclawTranscript' AND parent=$2 ORDER BY created_at DESC LIMIT 1")
        .bind(owner).bind(parent).fetch_optional(pool).await?.ok_or_else(||AppError::NotFound("Raw transcript not found".into()))?;
    let provider: Provider =
        sqlx::query_as("SELECT * FROM providers WHERE owner=$1 AND name=$2 AND category='Storage'")
            .bind(owner)
            .bind(resource.provider.as_deref().unwrap_or_default())
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| AppError::NotFound("Transcript storage provider not found".into()))?;
    let (storage, _) = storage_for_owner(principal, owner, Some(&provider), false).await?;
    let preview = storage.preview(&resource.name, PREVIEW_LIMIT).await?;
    let bytes = preview.bytes;
    let loaded = bytes.len();
    let filename = Path::new(&resource.file_name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("transcript.jsonl");
    Ok(
        json!({"fileName":filename,"fileSize":preview.size,"loadedSize":loaded,"truncated":preview.truncated,"content":String::from_utf8_lossy(&bytes)}),
    )
}

fn rpc_result(bytes: &[u8], id: i64, event_stream: bool) -> AppResult<Value> {
    let messages: Vec<Value> = if event_stream {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| AppError::Validation("Invalid MCP UTF-8".into()))?;
        text.replace("\r\n", "\n")
            .split("\n\n")
            .filter_map(|event| {
                let data = event
                    .lines()
                    .filter_map(|line| line.strip_prefix("data:").map(str::trim_start))
                    .collect::<Vec<_>>()
                    .join("\n");
                (!data.is_empty()).then(|| serde_json::from_str(&data))
            })
            .collect::<Result<_, _>>()
            .map_err(|_| AppError::Validation("Invalid MCP event stream".into()))?
    } else {
        vec![
            serde_json::from_slice(bytes)
                .map_err(|_| AppError::Validation("Invalid MCP JSON".into()))?,
        ]
    };
    let message = messages
        .into_iter()
        .find(|message| message["id"].as_i64() == Some(id))
        .ok_or_else(|| AppError::Validation("MCP response ID mismatch".into()))?;
    if message["jsonrpc"] != "2.0" || message.get("error").is_some() {
        return Err(AppError::Validation("MCP request failed".into()));
    }
    message
        .get("result")
        .cloned()
        .ok_or_else(|| AppError::Validation("MCP result missing".into()))
}
async fn mcp_request(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    session: Option<&str>,
    version: Option<&str>,
    body: Value,
    id: Option<i64>,
) -> AppResult<(Value, Option<String>)> {
    let mut request = client
        .post(url)
        .header("Accept", "application/json, text/event-stream")
        .json(&body);
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    if let Some(session) = session {
        request = request.header("Mcp-Session-Id", session);
    }
    if let Some(version) = version {
        request = request.header("MCP-Protocol-Version", version);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| AppError::Validation("MCP server unavailable".into()))?;
    if !response.status().is_success() {
        return Err(AppError::Validation(format!(
            "MCP server returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    if id.is_none() {
        return Ok((Value::Null, session));
    }
    let sse = response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.starts_with("text/event-stream"));
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppError::Validation("MCP response interrupted".into()))?
    {
        if bytes.len() + chunk.len() > PREVIEW_LIMIT {
            return Err(AppError::Validation("MCP response exceeds 2 MiB".into()));
        }
        bytes.extend_from_slice(&chunk);
        if sse && rpc_result(&bytes, id.unwrap(), true).is_ok() {
            break;
        }
    }
    Ok((rpc_result(&bytes, id.unwrap(), sse)?, session))
}
pub async fn sync_mcp(
    pool: &PgPool,
    principal: &Principal,
    owner: &str,
    name: &str,
    clear: bool,
) -> AppResult<Value> {
    resources::authorize(principal, owner)?;
    let old = resources::get(pool, Kind::Server, owner, name)
        .await?
        .ok_or_else(|| AppError::NotFound("Server not found".into()))?;
    let mut document = old.clone();
    let mut tools = Vec::new();
    if !clear {
        let url = text(&old, "url");
        let parsed =
            reqwest::Url::parse(url).map_err(|_| AppError::Validation("Invalid MCP URL".into()))?;
        let client =
            crate::services::system_gap_service::client(&parsed, principal.global_admin()).await?;
        let token = text(&old, "token");
        let (init,session)=mcp_request(&client,url,token,None,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"casdog","version":env!("CARGO_PKG_VERSION")}}}),Some(1)).await?;
        let version = text(&init, "protocolVersion");
        if !["2025-06-18", "2025-03-26"].contains(&version)
            || !init["capabilities"].get("tools").is_some()
        {
            return Err(AppError::Validation(
                "MCP server does not negotiate supported tools capability".into(),
            ));
        }
        mcp_request(
            &client,
            url,
            token,
            session.as_deref(),
            Some(version),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            None,
        )
        .await?;
        let mut cursor = None::<String>;
        let mut seen = HashSet::new();
        for page in 0..20 {
            let result=mcp_request(&client,url,token,session.as_deref(),Some(version),json!({"jsonrpc":"2.0","id":page+2,"method":"tools/list","params":cursor.as_ref().map(|cursor|json!({"cursor":cursor})).unwrap_or_else(||json!({}))}),Some(page+2)).await?.0;
            let entries = result["tools"]
                .as_array()
                .ok_or_else(|| AppError::Validation("MCP tools must be an array".into()))?;
            for tool in entries {
                let name = text(tool, "name");
                if name.is_empty()
                    || !seen.insert(name.to_string())
                    || !tool["inputSchema"].is_object()
                    || tools.len() >= 5000
                {
                    return Err(AppError::Validation(
                        "Invalid or excessive MCP tools".into(),
                    ));
                }
                let mut tool = tool.clone();
                tool["isAllowed"] = json!(
                    old["tools"]
                        .as_array()
                        .and_then(|list| list.iter().find(|old| text(old, "name") == name))
                        .and_then(|old| old["isAllowed"].as_bool())
                        .unwrap_or(true)
                );
                tools.push(tool);
            }
            cursor = result
                .get("nextCursor")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_string);
            if cursor.is_none() {
                break;
            }
            if page == 19 {
                return Err(AppError::Validation(
                    "MCP tool pagination exceeds limit".into(),
                ));
            }
        }
    }
    document["tools"] = json!(tools);
    document["updatedTime"] = json!(Utc::now().to_rfc3339());
    let changed=sqlx::query("UPDATE casdoor_objects SET document=$4,updated_at=clock_timestamp() WHERE kind='server' AND owner=$1 AND name=$2 AND document=$3")
        .bind(owner).bind(name).bind(&old).bind(document).execute(pool).await?.rows_affected();
    if changed != 1 {
        return Err(AppError::Conflict(
            "Server changed during synchronization; retry".into(),
        ));
    }
    Ok(json!({"status":"ok","data":true}))
}
