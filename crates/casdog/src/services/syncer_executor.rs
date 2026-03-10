use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::{Map, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tokio::time::{self, Duration};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{Syncer, SyncerResponse, TableColumn};
use crate::services::{LdapService, SyncerService, UserService};

static LAST_SYNC_RUNS: Lazy<Mutex<HashMap<String, DateTime<Utc>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone)]
pub struct SyncRunResult {
    pub syncer_id: String,
    pub success: bool,
    pub records_synced: u64,
    pub message: String,
}

#[derive(Debug, Default, Clone)]
struct SyncedUserRecord {
    source_id: Option<String>,
    ldap_id: Option<String>,
    external_id: Option<String>,
    name: Option<String>,
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    phone: Option<String>,
    avatar: Option<String>,
    affiliation: Option<String>,
    signup_application: Option<String>,
    password_hash: Option<String>,
    password_type: Option<String>,
    password_salt: Option<String>,
    is_forbidden: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct KeycloakSecretData {
    value: Option<String>,
    salt: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KeycloakCredentialData {
    #[serde(rename = "hashIterations")]
    hash_iterations: Option<u32>,
    algorithm: Option<String>,
}

pub struct SyncerExecutor;

impl SyncerExecutor {
    pub async fn execute_syncer(pool: &PgPool, syncer_id: &str) -> AppResult<SyncRunResult> {
        let syncer = SyncerService::get_by_id_internal(pool, syncer_id).await?;

        if !syncer.is_enabled {
            return Err(AppError::Validation(format!(
                "Syncer '{}' is disabled",
                syncer_id
            )));
        }

        let result = match syncer.syncer_type.as_str() {
            "Database" => Self::execute_database_sync(pool, &syncer).await,
            "LDAP" => Self::execute_ldap_sync(pool, &syncer).await,
            "Keycloak" => Self::execute_keycloak_sync(pool, &syncer).await,
            other => Ok(SyncRunResult {
                syncer_id: syncer.id.clone(),
                success: false,
                records_synced: 0,
                message: format!("Unsupported syncer type: {}", other),
            }),
        };

        Self::record_run(&syncer.id);

        match &result {
            Ok(run) => {
                Self::update_error_text(
                    pool,
                    &syncer.id,
                    if run.success {
                        None
                    } else {
                        Some(run.message.as_str())
                    },
                )
                .await;
            }
            Err(err) => {
                Self::update_error_text(pool, &syncer.id, Some(&err.to_string())).await;
            }
        }

        result
    }

    pub async fn execute_all_due(pool: &PgPool) -> AppResult<HashMap<String, SyncRunResult>> {
        let (syncers, _total) = SyncerService::list(pool, None, 1, 1000).await?;
        let now = Utc::now();
        let mut results = HashMap::new();

        for syncer in syncers {
            if !syncer.is_enabled || !Self::is_due(&syncer, now) {
                continue;
            }

            let id = syncer.id.clone();
            match Self::execute_syncer(pool, &id).await {
                Ok(result) => {
                    results.insert(id, result);
                }
                Err(err) => {
                    results.insert(
                        id.clone(),
                        SyncRunResult {
                            syncer_id: id,
                            success: false,
                            records_synced: 0,
                            message: err.to_string(),
                        },
                    );
                }
            }
        }

        Ok(results)
    }

    pub async fn start_scheduler(pool: PgPool, check_interval: Duration) {
        tracing::info!(
            interval_secs = check_interval.as_secs(),
            "Syncer scheduler started"
        );

        let mut interval = time::interval(check_interval);

        loop {
            interval.tick().await;

            match Self::execute_all_due(&pool).await {
                Ok(results) if !results.is_empty() => {
                    let succeeded = results.values().filter(|result| result.success).count();
                    let failed = results.len() - succeeded;
                    tracing::info!(
                        total = results.len(),
                        succeeded,
                        failed,
                        "Syncer scheduler run complete"
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::error!(error = %err, "Syncer scheduler failed to execute due syncers");
                }
            }
        }
    }

    async fn execute_database_sync(pool: &PgPool, syncer: &Syncer) -> AppResult<SyncRunResult> {
        let external_pool = Self::connect_external_postgres(syncer).await?;
        let table = syncer
            .table_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::Validation("Syncer table is required".to_string()))?;
        let columns = Self::parse_table_columns(syncer)?;
        let rows = Self::fetch_postgres_rows(&external_pool, table).await?;
        let mut synced = 0u64;

        for row in rows {
            let mut user = Self::map_database_row(syncer, &columns, &row)?;
            if syncer.syncer_type == "Keycloak" {
                Self::enrich_keycloak_user(&external_pool, &mut user).await?;
            }
            Self::upsert_local_user(pool, syncer, user).await?;
            synced += 1;
        }

        Ok(SyncRunResult {
            syncer_id: syncer.id.clone(),
            success: true,
            records_synced: synced,
            message: format!("Database sync completed, {} users synced", synced),
        })
    }

    async fn execute_ldap_sync(pool: &PgPool, syncer: &Syncer) -> AppResult<SyncRunResult> {
        let base_dn = syncer
            .database
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AppError::Validation("LDAP syncer requires base DN in database field".to_string())
            })?;
        let filter = syncer
            .table_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("(objectClass=person)");
        let users = LdapService::sync_users(
            &syncer.host,
            syncer.port as u16,
            &syncer.user,
            &syncer.password,
            base_dn,
            filter,
        )
        .await?;
        let mut synced = 0u64;

        for ldap_user in users {
            let record = SyncedUserRecord {
                source_id: Some(ldap_user.dn.clone()),
                ldap_id: Some(ldap_user.dn),
                external_id: Some(ldap_user.uid.clone()),
                name: Some(ldap_user.uid),
                display_name: Some(ldap_user.cn),
                email: ldap_user.email,
                phone: ldap_user.phone,
                ..SyncedUserRecord::default()
            };
            Self::upsert_local_user(pool, syncer, record).await?;
            synced += 1;
        }

        Ok(SyncRunResult {
            syncer_id: syncer.id.clone(),
            success: true,
            records_synced: synced,
            message: format!("LDAP sync completed, {} users synced", synced),
        })
    }

    async fn execute_keycloak_sync(pool: &PgPool, syncer: &Syncer) -> AppResult<SyncRunResult> {
        Self::execute_database_sync(pool, syncer)
            .await
            .map(|mut result| {
                result.message = result.message.replace("Database", "Keycloak");
                result
            })
    }

    fn is_due(syncer: &SyncerResponse, now: DateTime<Utc>) -> bool {
        let interval_minutes = i64::from(syncer.sync_interval.max(1));
        let runs = LAST_SYNC_RUNS.lock().unwrap();
        match runs.get(&syncer.id) {
            Some(last_run) => {
                now.signed_duration_since(*last_run) >= ChronoDuration::minutes(interval_minutes)
            }
            None => true,
        }
    }

    fn record_run(syncer_id: &str) {
        LAST_SYNC_RUNS
            .lock()
            .unwrap()
            .insert(syncer_id.to_string(), Utc::now());
    }

    fn parse_table_columns(syncer: &Syncer) -> AppResult<Vec<TableColumn>> {
        let raw = syncer
            .table_columns
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| AppError::Validation("Syncer table columns are required".to_string()))?;

        let columns = serde_json::from_str::<Vec<TableColumn>>(raw)
            .map_err(|e| AppError::Validation(format!("Invalid syncer table columns: {}", e)))?;
        if columns.is_empty() {
            return Err(AppError::Validation(
                "Syncer table columns are required".to_string(),
            ));
        }
        Ok(columns)
    }

    async fn connect_external_postgres(syncer: &Syncer) -> AppResult<PgPool> {
        let database_type = syncer
            .database_type
            .as_deref()
            .unwrap_or("postgres")
            .to_ascii_lowercase();
        if database_type != "postgres" {
            return Err(AppError::Validation(format!(
                "Unsupported syncer database_type '{}', only postgres is supported in this build",
                database_type
            )));
        }

        let database = syncer
            .database
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::Validation("Syncer database is required".to_string()))?;
        let ssl_mode = syncer
            .ssl_mode
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("disable");
        let dsn = format!(
            "postgres://{}:{}@{}:{}/{}?sslmode={}",
            urlencoding::encode(&syncer.user),
            urlencoding::encode(&syncer.password),
            syncer.host,
            syncer.port,
            urlencoding::encode(database),
            urlencoding::encode(ssl_mode)
        );

        PgPoolOptions::new()
            .max_connections(1)
            .connect(&dsn)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to connect to external database: {}", e))
            })
    }

    async fn fetch_postgres_rows(
        pool: &PgPool,
        table_name: &str,
    ) -> AppResult<Vec<Map<String, Value>>> {
        let sql = format!(
            "SELECT to_jsonb(t) AS row_json FROM {} t",
            Self::quote_identifier_path(table_name)?
        );
        let rows: Vec<Value> = sqlx::query_scalar::<_, Value>(&sql)
            .fetch_all(pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch external rows: {}", e)))?;

        rows.into_iter()
            .map(|row| match row {
                Value::Object(map) => Ok(map),
                _ => Err(AppError::Internal(
                    "External database row was not returned as an object".to_string(),
                )),
            })
            .collect()
    }

    fn quote_identifier_path(identifier: &str) -> AppResult<String> {
        let parts: Vec<&str> = identifier.split('.').collect();
        if parts.is_empty() {
            return Err(AppError::Validation(
                "Invalid syncer table name".to_string(),
            ));
        }

        let quoted = parts
            .into_iter()
            .map(Self::quote_identifier_part)
            .collect::<AppResult<Vec<_>>>()?;
        Ok(quoted.join("."))
    }

    fn quote_identifier_part(part: &str) -> AppResult<String> {
        let trimmed = part.trim();
        if trimmed.is_empty()
            || !trimmed.chars().enumerate().all(|(index, ch)| {
                if index == 0 {
                    ch.is_ascii_alphabetic() || ch == '_'
                } else {
                    ch.is_ascii_alphanumeric() || ch == '_'
                }
            })
        {
            return Err(AppError::Validation(format!(
                "Invalid syncer identifier '{}'",
                part
            )));
        }

        Ok(format!("\"{}\"", trimmed))
    }

    fn lookup_row_value(syncer: &Syncer, row: &Map<String, Value>, column_name: &str) -> String {
        let keycloak_pg = syncer.syncer_type == "Keycloak"
            && syncer
                .database_type
                .as_deref()
                .unwrap_or_default()
                .eq_ignore_ascii_case("postgres");

        if column_name.contains('+') {
            return column_name
                .split('+')
                .map(str::trim)
                .filter_map(|name| Self::lookup_single_value(row, name, keycloak_pg))
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
        }

        Self::lookup_single_value(row, column_name.trim(), keycloak_pg).unwrap_or_default()
    }

    fn lookup_single_value(
        row: &Map<String, Value>,
        column_name: &str,
        keycloak_pg: bool,
    ) -> Option<String> {
        let candidates = if keycloak_pg {
            vec![column_name.to_ascii_lowercase(), column_name.to_string()]
        } else {
            vec![column_name.to_string()]
        };

        candidates.into_iter().find_map(|candidate| {
            row.get(&candidate)
                .map(Self::json_value_to_string)
                .filter(|value| !value.is_empty())
        })
    }

    fn json_value_to_string(value: &Value) -> String {
        match value {
            Value::Null => String::new(),
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            other => other.to_string(),
        }
    }

    fn normalize_casdoor_field(name: &str) -> String {
        name.chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect()
    }

    fn parse_bool(value: &str) -> bool {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "y" | "on"
        )
    }

    fn map_database_row(
        syncer: &Syncer,
        columns: &[TableColumn],
        row: &Map<String, Value>,
    ) -> AppResult<SyncedUserRecord> {
        let mut user = SyncedUserRecord::default();

        for column in columns {
            let value = Self::lookup_row_value(syncer, row, &column.name);
            if value.is_empty() {
                continue;
            }

            match Self::normalize_casdoor_field(&column.casdoor_name).as_str() {
                "id" => {
                    user.source_id = Some(value.clone());
                    if syncer.syncer_type == "LDAP" {
                        user.ldap_id = Some(value);
                    } else {
                        user.external_id = Some(value);
                    }
                }
                "name" => user.name = Some(value),
                "displayname" => user.display_name = Some(value),
                "firstname" => user.first_name = Some(value),
                "lastname" => user.last_name = Some(value),
                "email" => user.email = Some(value),
                "emailverified" => user.email_verified = Some(Self::parse_bool(&value)),
                "phone" => user.phone = Some(value),
                "avatar" => user.avatar = Some(value),
                "affiliation" => user.affiliation = Some(value),
                "externalid" => user.external_id = Some(value),
                "ldap" => user.ldap_id = Some(value),
                "signupapplication" => user.signup_application = Some(value),
                "password" => {
                    if column.is_hashed {
                        user.password_hash = Some(value);
                    } else {
                        user.password_hash = Some(UserService::hash_password(&value)?);
                    }
                }
                "passwordtype" => user.password_type = Some(value),
                "passwordsalt" => user.password_salt = Some(value),
                "isforbidden" => {
                    user.is_forbidden = Some(if syncer.syncer_type == "Keycloak" {
                        !Self::parse_bool(&value)
                    } else {
                        Self::parse_bool(&value)
                    });
                }
                _ => {}
            }
        }

        Ok(user)
    }

    async fn enrich_keycloak_user(
        external_pool: &PgPool,
        user: &mut SyncedUserRecord,
    ) -> AppResult<()> {
        let source_id = match user.source_id.as_deref() {
            Some(source_id) if !source_id.is_empty() => source_id,
            _ => return Ok(()),
        };

        let credential_row = sqlx::query(
            r#"
            SELECT secret_data, credential_data
            FROM credential
            WHERE type = 'password' AND user_id = $1
            ORDER BY created_date DESC NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(source_id)
        .fetch_optional(external_pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read Keycloak credentials: {}", e)))?;

        if let Some(row) = credential_row {
            let secret_data: Option<String> = row.try_get("secret_data").ok();
            let credential_data: Option<String> = row.try_get("credential_data").ok();
            if let Some(secret_data) = secret_data {
                let secret: KeycloakSecretData =
                    serde_json::from_str(&secret_data).map_err(|e| {
                        AppError::Internal(format!("Failed to parse Keycloak secret_data: {}", e))
                    })?;
                if let (Some(value), Some(salt)) = (secret.value, secret.salt) {
                    let iterations = credential_data
                        .as_deref()
                        .and_then(|raw| serde_json::from_str::<KeycloakCredentialData>(raw).ok())
                        .and_then(|parsed| {
                            if parsed
                                .algorithm
                                .as_deref()
                                .map(|value| value.to_ascii_lowercase().contains("pbkdf2"))
                                .unwrap_or(true)
                            {
                                parsed.hash_iterations
                            } else {
                                None
                            }
                        })
                        .unwrap_or(27_500);
                    user.password_hash =
                        Some(format!("$pbkdf2-sha256${}${}${}", iterations, salt, value));
                    user.password_type = Some("pbkdf2-sha256".to_string());
                    user.password_salt = None;
                }
            }
        }

        if user.signup_application.is_none() {
            user.signup_application = sqlx::query_scalar::<_, String>(
                r#"
                SELECT kg.name
                FROM keycloak_group kg
                JOIN user_group_membership ugm ON kg.id = ugm.group_id
                WHERE ugm.user_id = $1
                ORDER BY kg.name
                LIMIT 1
                "#,
            )
            .bind(source_id)
            .fetch_optional(external_pool)
            .await
            .ok()
            .flatten();
        }

        Ok(())
    }

    async fn upsert_local_user(
        pool: &PgPool,
        syncer: &Syncer,
        mut user: SyncedUserRecord,
    ) -> AppResult<()> {
        if let Some(avatar) = user.avatar.as_mut() {
            if let Some(base) = syncer
                .avatar_base_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if !avatar.starts_with("http://") && !avatar.starts_with("https://") {
                    *avatar = format!(
                        "{}{}{}",
                        base.trim_end_matches('/'),
                        if avatar.starts_with('/') { "" } else { "/" },
                        avatar.trim_start_matches('/')
                    );
                }
            }
        }

        let base_name = Self::sanitize_user_name(
            user.name
                .clone()
                .or_else(|| {
                    user.email
                        .as_deref()
                        .and_then(|email| email.split('@').next().map(ToOwned::to_owned))
                })
                .or_else(|| user.external_id.clone())
                .or_else(|| user.ldap_id.clone())
                .or_else(|| user.source_id.clone())
                .unwrap_or_else(|| format!("synced_{}", &Uuid::new_v4().to_string()[..8])),
        );
        let display_name = user
            .display_name
            .clone()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| match (&user.first_name, &user.last_name) {
                (Some(first_name), Some(last_name)) => Some(
                    format!("{} {}", first_name.trim(), last_name.trim())
                        .trim()
                        .to_string(),
                ),
                (Some(first_name), None) => Some(first_name.clone()),
                (None, Some(last_name)) => Some(last_name.clone()),
                (None, None) => None,
            })
            .unwrap_or_else(|| base_name.clone());
        let password_hash = match user.password_hash.clone() {
            Some(password_hash) if !password_hash.is_empty() => password_hash,
            _ => UserService::hash_password(&Uuid::new_v4().to_string())?,
        };

        let existing_id = Self::find_existing_local_user(
            pool,
            &syncer.organization,
            &base_name,
            user.external_id.as_deref(),
            user.ldap_id.as_deref(),
        )
        .await?;
        let final_name = Self::ensure_unique_name(
            pool,
            &syncer.organization,
            &base_name,
            existing_id.as_deref(),
        )
        .await?;

        if let Some(id) = existing_id {
            sqlx::query(
                r#"
                UPDATE users
                SET name = $2,
                    display_name = $3,
                    first_name = $4,
                    last_name = $5,
                    email = $6,
                    email_verified = COALESCE($7, email_verified),
                    phone = $8,
                    avatar = $9,
                    affiliation = $10,
                    external_id = COALESCE($11, external_id),
                    ldap = COALESCE($12, ldap),
                    signup_application = COALESCE($13, signup_application),
                    password_hash = $14,
                    password_type = COALESCE($15, password_type),
                    password_salt = COALESCE($16, password_salt),
                    is_forbidden = COALESCE($17, is_forbidden),
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(&id)
            .bind(&final_name)
            .bind(&display_name)
            .bind(&user.first_name)
            .bind(&user.last_name)
            .bind(&user.email)
            .bind(user.email_verified)
            .bind(&user.phone)
            .bind(&user.avatar)
            .bind(&user.affiliation)
            .bind(&user.external_id)
            .bind(&user.ldap_id)
            .bind(&user.signup_application)
            .bind(&password_hash)
            .bind(&user.password_type)
            .bind(&user.password_salt)
            .bind(user.is_forbidden)
            .execute(pool)
            .await?;
        } else {
            sqlx::query(
                r#"
                INSERT INTO users (
                    id, owner, name, password_hash, display_name, first_name, last_name,
                    email, email_verified, phone, avatar, affiliation, external_id, ldap,
                    signup_application, password_type, password_salt, is_forbidden,
                    is_deleted, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    $8, $9, $10, $11, $12, $13, $14,
                    $15, $16, $17, $18,
                    false, NOW(), NOW()
                )
                "#,
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&syncer.organization)
            .bind(&final_name)
            .bind(&password_hash)
            .bind(&display_name)
            .bind(&user.first_name)
            .bind(&user.last_name)
            .bind(&user.email)
            .bind(user.email_verified.unwrap_or(false))
            .bind(&user.phone)
            .bind(&user.avatar)
            .bind(&user.affiliation)
            .bind(&user.external_id)
            .bind(&user.ldap_id)
            .bind(&user.signup_application)
            .bind(&user.password_type)
            .bind(&user.password_salt)
            .bind(user.is_forbidden.unwrap_or(false))
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    async fn find_existing_local_user(
        pool: &PgPool,
        owner: &str,
        name: &str,
        external_id: Option<&str>,
        ldap_id: Option<&str>,
    ) -> AppResult<Option<String>> {
        if let Some(external_id) = external_id.filter(|value| !value.is_empty()) {
            if let Some(id) = sqlx::query_scalar::<_, String>(
                "SELECT id FROM users WHERE owner = $1 AND external_id = $2 AND is_deleted = FALSE LIMIT 1",
            )
            .bind(owner)
            .bind(external_id)
            .fetch_optional(pool)
            .await?
            {
                return Ok(Some(id));
            }
        }

        if let Some(ldap_id) = ldap_id.filter(|value| !value.is_empty()) {
            if let Some(id) = sqlx::query_scalar::<_, String>(
                "SELECT id FROM users WHERE owner = $1 AND ldap = $2 AND is_deleted = FALSE LIMIT 1",
            )
            .bind(owner)
            .bind(ldap_id)
            .fetch_optional(pool)
            .await?
            {
                return Ok(Some(id));
            }
        }

        sqlx::query_scalar::<_, String>(
            "SELECT id FROM users WHERE owner = $1 AND name = $2 AND is_deleted = FALSE LIMIT 1",
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
    }

    async fn ensure_unique_name(
        pool: &PgPool,
        owner: &str,
        preferred_name: &str,
        current_user_id: Option<&str>,
    ) -> AppResult<String> {
        let mut candidate = preferred_name.to_string();
        let mut suffix = 1u32;

        loop {
            let existing_id = sqlx::query_scalar::<_, String>(
                "SELECT id FROM users WHERE owner = $1 AND name = $2 AND is_deleted = FALSE LIMIT 1",
            )
            .bind(owner)
            .bind(&candidate)
            .fetch_optional(pool)
            .await?;

            match existing_id {
                Some(existing_id) if current_user_id != Some(existing_id.as_str()) => {
                    suffix += 1;
                    candidate = format!("{}_{}", preferred_name, suffix);
                }
                _ => return Ok(candidate),
            }
        }
    }

    fn sanitize_user_name(name: String) -> String {
        let sanitized = name
            .trim()
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
            .to_string();

        if sanitized.is_empty() {
            "synced_user".to_string()
        } else {
            sanitized
        }
    }

    async fn update_error_text(pool: &PgPool, syncer_id: &str, error: Option<&str>) {
        let result = sqlx::query("UPDATE syncers SET error_text = $1 WHERE id = $2")
            .bind(error)
            .bind(syncer_id)
            .execute(pool)
            .await;

        if let Err(err) = result {
            tracing::warn!(
                syncer_id = %syncer_id,
                error = %err,
                "Failed to update syncer error_text"
            );
        }
    }
}
