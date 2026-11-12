use std::collections::HashMap;

use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgConnection, PgPool, Row};
use tokio::time::{self, Duration};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{Syncer, TableColumn, User};
use crate::services::{PasswordService, SyncerService};

#[derive(Debug, Clone, Default)]
pub struct SyncRunResult {
    pub syncer_id: String,
    pub success: bool,
    pub records_synced: u64,
    pub message: String,
    pub records_exported: u64,
    pub records_forbidden: u64,
    pub conflicts: u64,
    pub operations_pending: u64,
}

#[derive(Debug, Default, Clone)]
struct SyncedUserRecord {
    source_key: String,
    key_by_name: bool,
    key_field: String,
    password_plaintext: Option<String>,
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
    score: Option<i32>,
}

#[derive(Clone, sqlx::FromRow)]
struct LinkState {
    source_key: String,
    user_id: String,
    baseline_local: Option<Value>,
    baseline_source: Option<Value>,
    baseline_config_hash: Option<String>,
    conflict_state: Option<String>,
    disabled_by_sync: bool,
    disabled_user_updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(sqlx::FromRow)]
struct PendingOperation {
    id: String,
    source_key: String,
    user_id: String,
    organization: String,
    config_hash: String,
    expected_source: Option<Value>,
    desired_source: Value,
    local_snapshot: Value,
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
        Self::execute(pool, syncer_id, false).await
    }

    async fn execute(pool: &PgPool, syncer_id: &str, scheduled: bool) -> AppResult<SyncRunResult> {
        let token = Uuid::new_v4().to_string();
        let mut claim = pool.begin().await?;
        let row: Option<(bool, String)> = sqlx::query_as(
            "SELECT is_enabled,organization FROM syncers WHERE id=$1 FOR UPDATE SKIP LOCKED",
        )
        .bind(syncer_id)
        .fetch_optional(&mut *claim)
        .await?;
        let Some((enabled, org)) = row else {
            return Err(AppError::Conflict(
                "Syncer is running or unavailable".into(),
            ));
        };
        if !enabled {
            return Err(AppError::Validation("Syncer is disabled".into()));
        }
        let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin)")
            .bind(org).fetch_one(&mut *claim).await?;
        if !active {
            return Err(AppError::Validation(
                "Syncer organization is unavailable".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO syncer_runtime_state(syncer_id) VALUES($1) ON CONFLICT DO NOTHING",
        )
        .bind(syncer_id)
        .execute(&mut *claim)
        .await?;
        let claimed=sqlx::query("UPDATE syncer_runtime_state SET claimed_generation=change_generation,lease_token=$2,lease_until=clock_timestamp()+INTERVAL '90 seconds',last_started_at=clock_timestamp() WHERE syncer_id=$1 AND (lease_until IS NULL OR lease_until<=clock_timestamp()) AND (NOT $3 OR next_run_at<=clock_timestamp())")
            .bind(syncer_id).bind(&token).bind(scheduled).execute(&mut *claim).await?.rows_affected();
        if claimed != 1 {
            return Err(AppError::Conflict("Syncer is running or not due".into()));
        }
        claim.commit().await?;
        // The lease outlives this deadline. The transaction's row locks fence
        // stale workers as well as concurrent manual/scheduled executions.
        let work = async {
            let mut exported = Self::flush_operations(pool, syncer_id, &token).await?;
            let mut tx = pool.begin().await?;
            sqlx::query("SET LOCAL statement_timeout='30s'")
                .execute(&mut *tx)
                .await?;
            let syncer = SyncerService::get_conn(&mut tx, syncer_id, true).await?;
            let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM syncer_runtime_state WHERE syncer_id=$1 AND lease_token=$2 AND lease_until>clock_timestamp())")
                .bind(syncer_id).bind(&token).fetch_one(&mut *tx).await?;
            if !owned || !syncer.is_enabled {
                return Err(AppError::Conflict(
                    "Syncer lease changed or syncer disabled".into(),
                ));
            }
            SyncerService::validate(&mut tx, &syncer).await?;
            sqlx::query("SELECT name FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin FOR SHARE")
                .bind(&syncer.organization).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::Validation("Syncer organization is unavailable".into()))?;
            let mut run = match syncer.syncer_type.as_str() {
                "Database" | "Keycloak" => Self::execute_database_sync(&mut tx, &syncer).await?,
                "LDAP" => Self::execute_ldap_sync(&mut tx, &syncer).await?,
                _ => return Err(AppError::Validation("Unsupported syncer type".into())),
            };
            tx.commit().await?;
            exported += Self::flush_operations(pool, syncer_id, &token).await?;
            run.records_exported = exported;
            run.conflicts = sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM syncer_user_links WHERE syncer_id=$1 AND conflict_state IS NOT NULL")
                .bind(syncer_id).fetch_one(pool).await? as u64;
            run.operations_pending = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM syncer_operations WHERE syncer_id=$1 AND status='pending'",
            )
            .bind(syncer_id)
            .fetch_one(pool)
            .await? as u64;
            run.success = run.conflicts == 0 && run.operations_pending == 0;
            run.message = format!(
                "Sync completed: {} imported, {} exported, {} forbidden, {} conflicts, {} pending",
                run.records_synced,
                run.records_exported,
                run.records_forbidden,
                run.conflicts,
                run.operations_pending
            );
            Ok::<_, AppError>(run)
        };
        let result = match time::timeout(Duration::from_secs(60), work).await {
            Ok(result) => result,
            Err(_) => Err(AppError::Internal(
                "Syncer run exceeded its 60 second execution limit; durable writes remain queued for retry".into(),
            )),
        };
        let success = result.as_ref().is_ok_and(|r| r.success);
        let mut error = result.as_ref().err().map(|error| match error {
            AppError::Validation(message)
            | AppError::Conflict(message)
            | AppError::Internal(message) => message.clone(),
            _ => "Syncer import failed; local changes rolled back".into(),
        });
        if let Ok(run) = &result {
            if !run.success {
                error = Some(run.message.clone());
            }
        }
        // A failed completion never clears a different worker's lease.
        let mut finish = pool.begin().await?;
        sqlx::query("SELECT id FROM syncers WHERE id=$1 FOR UPDATE")
            .bind(syncer_id)
            .execute(&mut *finish)
            .await?;
        let updated=sqlx::query("UPDATE syncer_runtime_state r SET lease_token=NULL,lease_until=NULL,last_finished_at=clock_timestamp(),last_success_at=CASE WHEN $3 THEN clock_timestamp() ELSE last_success_at END,consecutive_failures=CASE WHEN $3 THEN 0 ELSE LEAST(consecutive_failures+1,20) END,last_error=$4,next_run_at=clock_timestamp()+make_interval(secs=>CASE WHEN $3 AND r.change_generation>r.claimed_generation THEN 0 WHEN $3 THEN s.sync_interval*60 ELSE LEAST(300,5*(1<<LEAST(r.consecutive_failures,6))) END) FROM syncers s WHERE r.syncer_id=s.id AND r.syncer_id=$1 AND r.lease_token=$2")
            .bind(syncer_id).bind(&token).bind(success).bind(&error).execute(&mut *finish).await?.rows_affected();
        if updated == 1 {
            sqlx::query("UPDATE syncers SET error_text=$2 WHERE id=$1")
                .bind(syncer_id)
                .bind(&error)
                .execute(&mut *finish)
                .await?;
        }
        finish.commit().await?;
        result
            .map_err(|_| AppError::Internal(error.unwrap_or_else(|| "Syncer import failed".into())))
    }

    pub async fn execute_all_due(pool: &PgPool) -> AppResult<HashMap<String, SyncRunResult>> {
        let ids:Vec<String>=sqlx::query_scalar("SELECT s.id FROM syncers s LEFT JOIN syncer_runtime_state r ON r.syncer_id=s.id JOIN organizations o ON o.name=s.organization AND NOT o.is_deleted AND NOT o.disable_signin WHERE s.is_enabled AND (r.next_run_at IS NULL OR r.next_run_at<=clock_timestamp()) AND (r.lease_until IS NULL OR r.lease_until<=clock_timestamp()) ORDER BY COALESCE(r.next_run_at,s.created_at) LIMIT 100")
            .fetch_all(pool).await?;
        let mut results = HashMap::new();
        for id in ids {
            match Self::execute(pool, &id, true).await {
                Ok(run) => {
                    results.insert(id, run);
                }
                Err(AppError::Conflict(_)) => {}
                Err(error) => {
                    results.insert(
                        id.clone(),
                        SyncRunResult {
                            syncer_id: id,
                            success: false,
                            records_synced: 0,
                            message: error.to_string(),
                            ..Default::default()
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

    async fn execute_database_sync(
        conn: &mut PgConnection,
        syncer: &Syncer,
    ) -> AppResult<SyncRunResult> {
        let external_pool = Self::connect_external_postgres(syncer).await?;
        let table = syncer
            .table_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::Validation("Syncer table is required".to_string()))?;
        let columns = Self::parse_table_columns(syncer)?;
        Self::reject_iam_database(conn, &external_pool).await?;
        if !syncer.is_read_only {
            Self::validate_writable_table(&external_pool, table, &columns).await?;
        }
        let (rows, affiliations) = Self::fetch_postgres_snapshot(&external_pool, syncer).await?;
        let mut seen = std::collections::HashSet::new();
        let mut prepared = Vec::new();

        for row in rows {
            let mut user = Self::map_database_row(syncer, &columns, &row)?;
            if syncer
                .affiliation_table
                .as_ref()
                .is_some_and(|v| !v.is_empty())
            {
                Self::resolve_affiliation(&mut user, &affiliations)?;
            }
            if !seen.insert(user.source_key.clone()) {
                return Err(AppError::Validation(
                    "Duplicate primary key in syncer source".into(),
                ));
            }
            if syncer.syncer_type == "Keycloak" {
                Self::enrich_keycloak_user(&external_pool, &mut user).await?;
                if let Some(hash) = user.password_hash.as_deref() {
                    PasswordService::validate_encoded_hash(
                        hash,
                        user.password_type.as_deref().unwrap_or("argon2"),
                        user.password_salt.as_deref(),
                    )
                    .map_err(|_| {
                        AppError::Validation("Unsupported Keycloak credential encoding".into())
                    })?;
                }
            }
            prepared.push((Self::source_projection(syncer, &columns, &row)?, row, user));
        }
        external_pool.close().await;
        Self::reconcile_rows(conn, syncer, &columns, prepared, &affiliations).await
    }

    async fn execute_ldap_sync(
        conn: &mut PgConnection,
        syncer: &Syncer,
    ) -> AppResult<SyncRunResult> {
        if !syncer.is_read_only {
            return Err(AppError::Validation(
                "LDAP writeback is unsupported; enable read-only synchronization".into(),
            ));
        }
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
        let url = if syncer.host.starts_with("ldap://") || syncer.host.starts_with("ldaps://") {
            syncer.host.clone()
        } else {
            format!(
                "{}://{}:{}",
                if syncer.port == 636 { "ldaps" } else { "ldap" },
                syncer.host,
                syncer.port
            )
        };
        let parsed = reqwest::Url::parse(&url)
            .map_err(|_| AppError::Validation("Invalid LDAP syncer endpoint".into()))?;
        if !matches!(parsed.scheme(), "ldap" | "ldaps")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(AppError::Validation("Invalid LDAP syncer endpoint".into()));
        }
        let settings = ldap3::LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(5))
            .set_starttls(syncer.ssl_mode.as_deref() == Some("starttls"));
        let (connection, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|_| AppError::Internal("LDAP syncer connection failed".into()))?;
        ldap3::drive!(connection);
        if !syncer.user.is_empty() {
            if syncer.password.is_empty() {
                return Err(AppError::Validation(
                    "LDAP bind requires a nonempty password".into(),
                ));
            }
            ldap.with_timeout(Duration::from_secs(10))
                .simple_bind(&syncer.user, &syncer.password)
                .await
                .map_err(|_| AppError::Internal("LDAP syncer bind unavailable".into()))?
                .success()
                .map_err(|_| AppError::Internal("LDAP syncer bind rejected".into()))?;
        }
        let columns = if syncer
            .table_columns
            .as_deref()
            .is_some_and(|v| !v.is_empty())
        {
            Self::parse_table_columns(syncer)?
        } else {
            [
                ("dn", "Id", true),
                ("uid", "Name", false),
                ("displayName", "DisplayName", false),
                ("mail", "Email", false),
                ("mobile", "Phone", false),
            ]
            .into_iter()
            .map(|(name, field, key)| TableColumn {
                name: name.into(),
                column_type: "String".into(),
                casdoor_name: field.into(),
                is_key: key,
                is_hashed: false,
                values: None,
            })
            .collect()
        };
        let mut attrs = vec![
            "uid".to_string(),
            "cn".into(),
            "displayName".into(),
            "mail".into(),
            "mobile".into(),
            "sAMAccountName".into(),
            "userPrincipalName".into(),
        ];
        for column in &columns {
            for name in column.name.split('+').map(str::trim) {
                if name != "dn" {
                    attrs.push(name.into());
                }
            }
        }
        attrs.sort();
        attrs.dedup();
        let (entries, result) = ldap
            .with_timeout(Duration::from_secs(10))
            .with_search_options(ldap3::SearchOptions::new().sizelimit(10001).timelimit(10))
            .search(base_dn, ldap3::Scope::Subtree, filter, attrs)
            .await
            .map_err(|_| AppError::Internal("LDAP syncer search failed".into()))?
            .success()
            .map_err(|_| {
                AppError::Internal("LDAP syncer search rejected or exceeded limits".into())
            })?;
        if !result.refs.is_empty()
            || result
                .ctrls
                .iter()
                .any(|c| c.1.ctype == "1.2.840.113556.1.4.319")
        {
            return Err(AppError::Validation(
                "Paged LDAP responses require complete paging; this snapshot was not imported"
                    .into(),
            ));
        }
        if entries.len() > 10000 {
            return Err(AppError::Validation(
                "Syncer source exceeds 10000 users per run".into(),
            ));
        }
        let _ = ldap.with_timeout(Duration::from_secs(5)).unbind().await;
        let mut prepared = Vec::new();
        let mut total_bytes = 0usize;
        let mut seen = std::collections::HashSet::new();
        for entry in entries {
            let entry = ldap3::SearchEntry::construct(entry);
            let mut row: Map<String, Value> = entry
                .attrs
                .into_iter()
                .map(|(name, values)| {
                    (
                        name,
                        Value::String(values.first().cloned().unwrap_or_default()),
                    )
                })
                .collect();
            row.insert("dn".into(), Value::String(entry.dn));
            total_bytes += serde_json::to_vec(&row)
                .map_err(|_| AppError::Internal("Invalid LDAP snapshot".into()))?
                .len();
            if total_bytes > 32 * 1024 * 1024 {
                return Err(AppError::Validation("LDAP snapshot exceeds 32 MiB".into()));
            }
            if !row.contains_key("uid") {
                if let Some(value) = row
                    .get("sAMAccountName")
                    .or_else(|| row.get("userPrincipalName"))
                    .or_else(|| row.get("cn"))
                    .cloned()
                {
                    row.insert("uid".into(), value);
                }
            }
            if !row.contains_key("displayName") {
                if let Some(value) = row.get("cn").cloned() {
                    row.insert("displayName".into(), value);
                }
            }
            let record = Self::map_database_row(syncer, &columns, &row)?;
            if !seen.insert(record.source_key.clone()) {
                return Err(AppError::Validation(
                    "Duplicate primary key in LDAP source".into(),
                ));
            }
            prepared.push((
                Self::source_projection(syncer, &columns, &row)?,
                row,
                record,
            ));
        }

        Self::reconcile_rows(conn, syncer, &columns, prepared, &HashMap::new()).await
    }

    pub(crate) fn parse_table_columns(syncer: &Syncer) -> AppResult<Vec<TableColumn>> {
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

    pub(crate) fn validate_columns(syncer: &Syncer) -> AppResult<()> {
        if !syncer.is_read_only && syncer.syncer_type != "Database" {
            return Err(AppError::Validation("Writeback is supported only for PostgreSQL Database syncers; LDAP and Keycloak require read-only mode".into()));
        }
        let columns = Self::parse_table_columns(syncer)?;
        if columns.iter().filter(|column| column.is_key).count() != 1 {
            return Err(AppError::Validation(
                "Syncer needs exactly one primary key mapping".into(),
            ));
        }
        let mut fields = std::collections::HashSet::new();
        let mut source_fields = std::collections::HashSet::new();
        for column in columns {
            let target = Self::normalize_casdoor_field(&column.casdoor_name);
            if !matches!(
                target.as_str(),
                "id" | "name"
                    | "displayname"
                    | "firstname"
                    | "lastname"
                    | "email"
                    | "emailverified"
                    | "phone"
                    | "avatar"
                    | "affiliation"
                    | "externalid"
                    | "ldap"
                    | "signupapplication"
                    | "password"
                    | "passwordtype"
                    | "passwordsalt"
                    | "isforbidden"
                    | "score"
            ) || !fields.insert(target.clone())
            {
                return Err(AppError::Validation(
                    "Unsupported or duplicate syncer target mapping".into(),
                ));
            }
            if column.is_key
                && !matches!(
                    target.as_str(),
                    "id" | "name" | "externalid" | "ldap" | "email" | "phone"
                )
            {
                return Err(AppError::Validation(
                    "Primary mapping must identify a stable user field".into(),
                ));
            }
            if column.name.is_empty()
                || column.name.len() > 255
                || column.name.chars().any(char::is_control)
            {
                return Err(AppError::Validation("Invalid mapping source".into()));
            }
            if !syncer.is_read_only {
                Self::quote_identifier_part(&column.name)?;
                if !source_fields.insert(column.name.clone()) {
                    return Err(AppError::Validation(
                        "Writeback source columns must be unique".into(),
                    ));
                }
                if target == "password" && !column.is_hashed {
                    return Err(AppError::Validation("Writeback requires an encoded Password mapping (isHashed=true); plaintext credentials cannot be exported".into()));
                }
            }
            let conversions = Self::conversions(&column)?;
            if !conversions.is_empty()
                && (column.is_key
                    || matches!(
                        target.as_str(),
                        "password" | "passwordtype" | "passwordsalt"
                    ))
            {
                return Err(AppError::Validation(
                    "Identity and credential mappings cannot use value conversions".into(),
                ));
            }
            if !syncer.is_read_only {
                let mut targets = std::collections::HashSet::new();
                if conversions.iter().any(|(_, v)| !targets.insert(v)) {
                    return Err(AppError::Validation(
                        "Writeback value conversions must be reversible and unique".into(),
                    ));
                }
            }
        }
        if (fields.contains("passwordtype") || fields.contains("passwordsalt"))
            && !fields.contains("password")
        {
            return Err(AppError::Validation(
                "Password metadata requires a password mapping".into(),
            ));
        }
        if syncer.syncer_type != "LDAP" {
            Self::quote_identifier_path(syncer.table_name.as_deref().unwrap_or_default())?;
            if let Some(table) = syncer
                .affiliation_table
                .as_deref()
                .filter(|s| !s.is_empty())
            {
                Self::quote_identifier_path(table)?;
            }
        }
        Ok(())
    }

    async fn connect_external_postgres(syncer: &Syncer) -> AppResult<PgPool> {
        let database_type = syncer
            .database_type
            .as_deref()
            .unwrap_or("postgres")
            .to_ascii_lowercase();
        if !matches!(database_type.as_str(), "postgres" | "postgresql") {
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
        let ssl = match ssl_mode {
            "disable" => sqlx::postgres::PgSslMode::Disable,
            "allow" => sqlx::postgres::PgSslMode::Allow,
            "prefer" => sqlx::postgres::PgSslMode::Prefer,
            "require" => sqlx::postgres::PgSslMode::Require,
            "verify-ca" => sqlx::postgres::PgSslMode::VerifyCa,
            "verify-full" => sqlx::postgres::PgSslMode::VerifyFull,
            _ => return Err(AppError::Validation("Invalid PostgreSQL SSL mode".into())),
        };
        let options = sqlx::postgres::PgConnectOptions::new()
            .host(&syncer.host)
            .port(syncer.port as u16)
            .username(&syncer.user)
            .password(&syncer.password)
            .database(database)
            .ssl_mode(ssl);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|_| AppError::Internal("External PostgreSQL connection failed".into()))?;
        sqlx::query("SET statement_timeout='10s'")
            .execute(&pool)
            .await
            .map_err(|_| AppError::Internal("External PostgreSQL session setup failed".into()))?;
        Ok(pool)
    }

    async fn fetch_postgres_snapshot(
        pool: &PgPool,
        syncer: &Syncer,
    ) -> AppResult<(Vec<Map<String, Value>>, HashMap<i32, String>)> {
        let table = Self::quote_identifier_path(syncer.table_name.as_deref().unwrap_or_default())?;
        let mut snapshot = pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *snapshot)
            .await?;
        let (count,size):(i64,i64)=sqlx::query_as(&format!("SELECT COUNT(*),COALESCE(SUM(octet_length(to_jsonb(t)::text)),0)::bigint FROM (SELECT * FROM {table} LIMIT 10001) t"))
            .fetch_one(&mut *snapshot).await.map_err(|_|AppError::Internal("Cannot inspect external PostgreSQL snapshot".into()))?;
        if count > 10000 || size > 32 * 1024 * 1024 {
            return Err(AppError::Validation(
                "Syncer source exceeds the 10000 row or 32 MiB snapshot limit".into(),
            ));
        }
        let rows: Vec<Value> =
            sqlx::query_scalar(&format!("SELECT to_jsonb(t) FROM {table} t LIMIT 10001"))
                .fetch_all(&mut *snapshot)
                .await
                .map_err(|_| {
                    AppError::Internal("Failed to fetch external PostgreSQL rows".into())
                })?;
        let mut affiliations = HashMap::new();
        if let Some(table) = syncer
            .affiliation_table
            .as_deref()
            .filter(|v| !v.is_empty())
        {
            let table = Self::quote_identifier_path(table)?;
            let lookup: Vec<Value> =
                sqlx::query_scalar(&format!("SELECT to_jsonb(t) FROM {table} t LIMIT 10001"))
                    .fetch_all(&mut *snapshot)
                    .await
                    .map_err(|_| AppError::Internal("Cannot read affiliation snapshot".into()))?;
            if lookup.len() > 10000
                || lookup.iter().map(|v| v.to_string().len()).sum::<usize>() > 32 * 1024 * 1024
            {
                return Err(AppError::Validation(
                    "Affiliation snapshot exceeds limits".into(),
                ));
            }
            for row in lookup {
                let id = Self::json_value_to_string(&row["id"])
                    .parse::<i32>()
                    .map_err(|_| {
                        AppError::Validation(
                            "Affiliation table needs integer id and nonempty name".into(),
                        )
                    })?;
                let name = row["name"]
                    .as_str()
                    .filter(|v| !v.is_empty() && v.len() <= 255)
                    .ok_or_else(|| {
                        AppError::Validation(
                            "Affiliation table needs integer id and nonempty name".into(),
                        )
                    })?;
                if affiliations.insert(id, name.to_owned()).is_some() {
                    return Err(AppError::Validation("Duplicate affiliation id".into()));
                }
            }
        }
        snapshot.commit().await?;
        let rows = rows
            .into_iter()
            .map(|row| match row {
                Value::Object(map) => Ok(map),
                _ => Err(AppError::Internal(
                    "External database row was not returned as an object".to_string(),
                )),
            })
            .collect::<AppResult<Vec<_>>>()?;
        Ok((rows, affiliations))
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

        let lookup = |name: &str| {
            if syncer.syncer_type == "LDAP" {
                row.iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| Self::json_value_to_string(value))
                    .filter(|value| !value.is_empty())
            } else {
                Self::lookup_single_value(row, name, keycloak_pg)
            }
        };
        if column_name.contains('+') {
            return column_name
                .split('+')
                .map(str::trim)
                .filter_map(lookup)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
        }

        lookup(column_name.trim()).unwrap_or_default()
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

    fn parse_bool(value: &str) -> AppResult<bool> {
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "y" | "on" => Ok(true),
            "0" | "false" | "no" | "n" | "off" => Ok(false),
            _ => Err(AppError::Validation(
                "Invalid boolean in syncer mapping".into(),
            )),
        }
    }

    fn map_database_row(
        syncer: &Syncer,
        columns: &[TableColumn],
        row: &Map<String, Value>,
    ) -> AppResult<SyncedUserRecord> {
        let mut user = SyncedUserRecord::default();
        let key = columns.iter().find(|column| column.is_key).ok_or_else(|| {
            AppError::Validation("Syncer requires exactly one stable primary key mapping".into())
        })?;
        user.source_key = Self::lookup_row_value(syncer, row, &key.name);
        user.key_field = Self::normalize_casdoor_field(&key.casdoor_name);
        user.key_by_name = user.key_field == "name";
        if user.source_key.is_empty() || user.source_key.len() > 8192 {
            return Err(AppError::Validation(
                "Syncer row has no valid stable primary key".into(),
            ));
        }
        let mut hashed = false;

        for column in columns {
            let value = Self::convert_value(
                column,
                &Self::lookup_row_value(syncer, row, &column.name),
                false,
            )?;
            if value.len() > 65536 {
                return Err(AppError::Validation(
                    "Mapped syncer field exceeds 64 KiB".into(),
                ));
            }
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
                "emailverified" => user.email_verified = Some(Self::parse_bool(&value)?),
                "phone" => user.phone = Some(value),
                "avatar" => user.avatar = Some(value),
                "affiliation" => user.affiliation = Some(value),
                "score" => {
                    user.score = Some(value.parse().map_err(|_| {
                        AppError::Validation("Invalid integer Score mapping".into())
                    })?)
                }
                "externalid" => user.external_id = Some(value),
                "ldap" => user.ldap_id = Some(value),
                "signupapplication" => user.signup_application = Some(value),
                "password" => {
                    hashed = column.is_hashed;
                    if !hashed {
                        user.password_plaintext = Some(value.clone());
                    }
                    user.password_hash = Some(value);
                }
                "passwordtype" => user.password_type = Some(value),
                "passwordsalt" => user.password_salt = Some(value),
                "isforbidden" => {
                    user.is_forbidden = Some(if syncer.syncer_type == "Keycloak" {
                        !Self::parse_bool(&value)?
                    } else {
                        Self::parse_bool(&value)?
                    });
                }
                _ => {}
            }
        }

        if let Some(password) = user.password_hash.take() {
            let imported = PasswordService::import_credential(
                &password,
                user.password_type.as_deref(),
                user.password_salt.as_deref(),
                hashed,
            )
            .map_err(|_| {
                AppError::Validation("Invalid mapped password format or algorithm".into())
            })?;
            if !syncer.is_read_only && imported.hash != password {
                return Err(AppError::Validation("Writeback requires a genuinely encoded source credential; plain PasswordType cannot be reversed".into()));
            }
            user.password_hash = Some(imported.hash);
            user.password_type = Some(imported.password_type);
            user.password_salt = imported.salt;
        }
        Ok(user)
    }

    // Values is a documented local extension. Empty arrays preserve upstream
    // mappings. Boolean arrays are [false-source,true-source]; other entries
    // are exact "source=local" pairs, never executable expressions.
    fn conversions(column: &TableColumn) -> AppResult<Vec<(String, String)>> {
        let Some(values) = column.values.as_ref().filter(|v| !v.is_empty()) else {
            return Ok(vec![]);
        };
        if values.len() > 256 || values.iter().any(|v| v.len() > 65536) {
            return Err(AppError::Validation(
                "Value conversion exceeds limits".into(),
            ));
        }
        let boolean = matches!(
            column.column_type.to_ascii_lowercase().as_str(),
            "bool" | "boolean"
        ) || matches!(
            Self::normalize_casdoor_field(&column.casdoor_name).as_str(),
            "emailverified" | "isforbidden"
        );
        if boolean && values.len() == 2 && values.iter().all(|v| !v.contains('=')) {
            if values[0] == values[1] {
                return Err(AppError::Validation(
                    "Boolean conversion values must differ".into(),
                ));
            }
            return Ok(vec![
                (values[0].clone(), "false".into()),
                (values[1].clone(), "true".into()),
            ]);
        }
        let mut seen = std::collections::HashSet::new();
        values
            .iter()
            .map(|v| {
                let (source, target) = v.split_once('=').ok_or_else(|| {
                    AppError::Validation(
                        "Value conversions need source=local pairs or two Boolean values".into(),
                    )
                })?;
                if !seen.insert(source.to_string()) {
                    return Err(AppError::Validation(
                        "Duplicate source conversion value".into(),
                    ));
                }
                let target = if boolean {
                    Self::parse_bool(target)?.to_string()
                } else {
                    target.to_string()
                };
                Ok((source.to_string(), target))
            })
            .collect()
    }

    fn convert_value(column: &TableColumn, value: &str, reverse: bool) -> AppResult<String> {
        let mappings = Self::conversions(column)?;
        if mappings.is_empty() || value.is_empty() {
            return Ok(value.to_string());
        }
        mappings
            .into_iter()
            .find_map(|(source, target)| {
                if reverse {
                    (target == value).then_some(source)
                } else {
                    (source == value).then_some(target)
                }
            })
            .ok_or_else(|| {
                AppError::Validation("Mapped field has no configured value conversion".into())
            })
    }

    fn resolve_affiliation(
        user: &mut SyncedUserRecord,
        lookup: &HashMap<i32, String>,
    ) -> AppResult<()> {
        if let Some(id) = user.score.filter(|id| *id != 0) {
            user.affiliation = Some(lookup.get(&id).cloned().ok_or_else(|| {
                AppError::Validation("Source Score has no affiliation lookup entry".into())
            })?);
        }
        Ok(())
    }

    fn config_hash(syncer: &Syncer) -> String {
        let bytes = serde_json::to_vec(&json!([
            syncer.organization,
            syncer.syncer_type,
            syncer.database_type,
            syncer.host,
            syncer.port,
            syncer.user,
            syncer.database,
            syncer.table_name,
            syncer.table_columns,
            syncer.affiliation_table,
            syncer.avatar_base_url
        ]))
        .expect("JSON config");
        format!("{:x}", Sha256::digest(bytes))
    }

    fn credential_fingerprint(value: &str) -> String {
        let mut hmac =
            Hmac::<Sha256>::new_from_slice(crate::config::AppConfig::get().jwt.secret.as_bytes())
                .expect("HMAC key");
        hmac.update(b"casdog-syncer-baseline-v1\0");
        hmac.update(value.as_bytes());
        hmac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn credential_encoding(hash: &str, kind: Option<&str>) -> String {
        PasswordService::encoded_type(hash)
            .map(str::to_owned)
            .unwrap_or_else(|| kind.unwrap_or_default().to_ascii_lowercase())
    }

    fn source_projection(
        syncer: &Syncer,
        columns: &[TableColumn],
        row: &Map<String, Value>,
    ) -> AppResult<Value> {
        let mut result = Map::new();
        for c in columns {
            let mut value = Self::lookup_row_value(syncer, row, &c.name);
            if matches!(
                Self::normalize_casdoor_field(&c.casdoor_name).as_str(),
                "password" | "passwordsalt"
            ) {
                value = Self::credential_fingerprint(&value);
            }
            result.insert(c.name.clone(), Value::String(value));
        }
        Ok(Value::Object(result))
    }

    fn local_value(user: &User, field: &str, affiliation: bool) -> String {
        match field {
            "id" | "externalid" => user.external_id.clone().unwrap_or_default(),
            "name" => user.name.clone(),
            "displayname" => user.display_name.clone(),
            "firstname" => user.first_name.clone().unwrap_or_default(),
            "lastname" => user.last_name.clone().unwrap_or_default(),
            "email" => user.email.clone().unwrap_or_default(),
            "emailverified" => user.email_verified.to_string(),
            "phone" => user.phone.clone().unwrap_or_default(),
            "avatar" => user.avatar.clone().unwrap_or_default(),
            "affiliation" => user.affiliation.clone().unwrap_or_default(),
            "ldap" => user.ldap.clone().unwrap_or_default(),
            "signupapplication" => user.signup_application.clone().unwrap_or_default(),
            "password" => user.password_hash.clone(),
            "passwordtype" => user.password_type.clone().unwrap_or_else(|| {
                PasswordService::encoded_type(&user.password_hash)
                    .unwrap_or("argon2")
                    .into()
            }),
            "passwordsalt" => user.password_salt.clone().unwrap_or_default(),
            "isforbidden" => user.is_forbidden.to_string(),
            "score" if affiliation => user.affiliation.clone().unwrap_or_default(),
            "score" => user.score.to_string(),
            _ => String::new(),
        }
    }

    fn local_projection(syncer: &Syncer, columns: &[TableColumn], user: &User) -> Value {
        let mut result = Map::new();
        for c in columns {
            let field = Self::normalize_casdoor_field(&c.casdoor_name);
            let mut value = if field == "id" && syncer.syncer_type == "LDAP" {
                user.ldap.clone().unwrap_or_default()
            } else {
                Self::local_value(
                    user,
                    &field,
                    syncer
                        .affiliation_table
                        .as_ref()
                        .is_some_and(|v| !v.is_empty()),
                )
            };
            if matches!(field.as_str(), "password" | "passwordsalt") {
                value = Self::credential_fingerprint(&value);
            }
            result.insert(field, Value::String(value));
        }
        Value::Object(result)
    }

    fn export_user(
        syncer: &Syncer,
        columns: &[TableColumn],
        user: &User,
        affiliations: &HashMap<i32, String>,
    ) -> AppResult<Value> {
        let mut result = Map::new();
        for c in columns {
            let field = Self::normalize_casdoor_field(&c.casdoor_name);
            let mut value = Self::local_value(user, &field, false);
            if field == "password" {
                let kind = user
                    .password_type
                    .as_deref()
                    .or_else(|| PasswordService::encoded_type(&user.password_hash))
                    .unwrap_or_default();
                if kind.eq_ignore_ascii_case("plain")
                    || PasswordService::validate_encoded_hash(
                        &user.password_hash,
                        kind,
                        user.password_salt.as_deref(),
                    )
                    .is_err()
                {
                    return Err(AppError::Validation("Writeback requires a valid encoded local credential; plaintext or missing credentials cannot be exported".into()));
                }
            }
            if field == "score"
                && syncer
                    .affiliation_table
                    .as_ref()
                    .is_some_and(|v| !v.is_empty())
            {
                let name = user.affiliation.as_deref().unwrap_or_default();
                let matches: Vec<i32> = affiliations
                    .iter()
                    .filter_map(|(id, v)| (v == name).then_some(*id))
                    .collect();
                if matches.len() != 1 {
                    return Err(AppError::Validation(
                        "Writeback affiliation must match exactly one lookup entry".into(),
                    ));
                }
                value = matches[0].to_string();
            }
            if field == "avatar" {
                if let Some(base) = syncer.avatar_base_url.as_deref().filter(|b| !b.is_empty()) {
                    if let Some(relative) =
                        value.strip_prefix(&format!("{}/", base.trim_end_matches('/')))
                    {
                        value = relative.to_string();
                    }
                }
            }
            value = Self::convert_value(c, &value, true)?;
            result.insert(c.name.clone(), Value::String(value));
        }
        Ok(Value::Object(result))
    }

    async fn mark_conflict(
        conn: &mut PgConnection,
        syncer: &Syncer,
        key: &str,
        reason: &str,
    ) -> AppResult<()> {
        sqlx::query("UPDATE syncer_user_links SET conflict_state=$3,conflict_at=clock_timestamp(),last_seen_at=clock_timestamp() WHERE syncer_id=$1 AND source_key=$2")
            .bind(&syncer.id).bind(key).bind(reason).execute(&mut *conn).await?;
        Ok(())
    }

    async fn acknowledge(
        conn: &mut PgConnection,
        syncer: &Syncer,
        key: &str,
        local: &Value,
        source: &Value,
    ) -> AppResult<()> {
        sqlx::query("UPDATE syncer_user_links SET baseline_local=$3,baseline_source=$4,baseline_config_hash=$5,conflict_state=NULL,conflict_at=NULL,last_seen_at=clock_timestamp(),disabled_by_sync=FALSE,disabled_user_updated_at=NULL WHERE syncer_id=$1 AND source_key=$2")
            .bind(&syncer.id).bind(key).bind(local).bind(source).bind(Self::config_hash(syncer)).execute(&mut *conn).await?;
        Ok(())
    }

    async fn enqueue(
        conn: &mut PgConnection,
        syncer: &Syncer,
        key: &str,
        user: &User,
        expected: Option<&Value>,
        desired: Value,
        local: Value,
    ) -> AppResult<()> {
        sqlx::query("INSERT INTO syncer_operations(id,syncer_id,source_key,user_id,organization,config_hash,expected_source,desired_source,local_snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(syncer_id,source_key) WHERE status='pending' DO NOTHING")
            .bind(Uuid::new_v4().to_string()).bind(&syncer.id).bind(key).bind(&user.id).bind(&syncer.organization).bind(Self::config_hash(syncer)).bind(expected).bind(desired).bind(local).execute(&mut *conn).await?;
        Ok(())
    }

    async fn reconcile_rows(
        conn: &mut PgConnection,
        syncer: &Syncer,
        columns: &[TableColumn],
        prepared: Vec<(Value, Map<String, Value>, SyncedUserRecord)>,
        affiliations: &HashMap<i32, String>,
    ) -> AppResult<SyncRunResult> {
        let links:Vec<LinkState>=sqlx::query_as("SELECT source_key,user_id,baseline_local,baseline_source,baseline_config_hash,conflict_state,disabled_by_sync,disabled_user_updated_at FROM syncer_user_links WHERE syncer_id=$1")
            .bind(&syncer.id).fetch_all(&mut *conn).await?;
        let links: HashMap<String, LinkState> = links
            .into_iter()
            .map(|l| (l.source_key.clone(), l))
            .collect();
        let mut seen = std::collections::HashSet::new();
        let mut run = SyncRunResult {
            syncer_id: syncer.id.clone(),
            success: true,
            ..Default::default()
        };
        let config = Self::config_hash(syncer);
        for (source, source_row, mut incoming) in prepared {
            let key = incoming.source_key.clone();
            seen.insert(key.clone());
            let mut pull = true;
            if let Some(link) = links.get(&key) {
                let mut user:User=sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_admin FOR UPDATE")
                    .bind(&link.user_id).bind(&syncer.organization).fetch_optional(&mut *conn).await?.ok_or_else(||AppError::Validation("Linked account is unavailable or privileged".into()))?;
                if link.disabled_by_sync {
                    if link.disabled_user_updated_at == Some(user.updated_at) && user.is_forbidden {
                        user.is_forbidden = false;
                        if incoming.is_forbidden.is_none() {
                            incoming.is_forbidden = Some(false);
                        }
                    } else {
                        Self::mark_conflict(conn,syncer,&key,"Account changed after source deletion; review its binding before restoring").await?;
                        continue;
                    }
                }
                let local = Self::local_projection(syncer, columns, &user);
                if !syncer.is_read_only {
                    if link.baseline_local.is_none()
                        && link.baseline_source.is_none()
                        && link.conflict_state.is_some()
                    {
                        // A competing source INSERT after a never-acknowledged
                        // export is a conflict, not a first-time import that
                        // may silently replace the local account on retry.
                        let desired = Self::export_user(syncer, columns, &user, affiliations)?;
                        if Self::source_projection(
                            syncer,
                            columns,
                            desired.as_object().expect("export object"),
                        )? == source
                        {
                            Self::acknowledge(conn, syncer, &key, &local, &source).await?;
                        } else {
                            Self::mark_conflict(conn,syncer,&key,"Source account appeared before the first export was acknowledged; resolve both account versions explicitly").await?;
                        }
                        continue;
                    }
                    let unchanged = if link.baseline_config_hash.as_deref() == Some(config.as_str())
                    {
                        link.baseline_local.as_ref() == Some(&local)
                    } else {
                        // Adding a mapping does not make its previously
                        // untracked local field an unsynchronized edit. Verify
                        // every old tracked field against the actual user.
                        link.baseline_local
                            .as_ref()
                            .and_then(Value::as_object)
                            .is_some_and(|old| {
                                old.iter().all(|(field, value)| {
                                    let mut current =
                                        if field == "id" && syncer.syncer_type == "LDAP" {
                                            user.ldap.clone().unwrap_or_default()
                                        } else {
                                            Self::local_value(
                                                &user,
                                                field,
                                                syncer
                                                    .affiliation_table
                                                    .as_ref()
                                                    .is_some_and(|v| !v.is_empty()),
                                            )
                                        };
                                    if matches!(field.as_str(), "password" | "passwordsalt") {
                                        current = Self::credential_fingerprint(&current);
                                    }
                                    value.as_str() == Some(current.as_str())
                                })
                            })
                    };
                    if link.baseline_local.is_some() && !unchanged {
                        pull = false;
                        if link.baseline_config_hash.as_deref() != Some(config.as_str()) {
                            Self::mark_conflict(conn,syncer,&key,"Configuration changed while local account had unsynchronized edits").await?;
                        } else {
                            let credential_changed = columns.iter().any(|c| {
                                let f = Self::normalize_casdoor_field(&c.casdoor_name);
                                matches!(f.as_str(), "password" | "passwordtype" | "passwordsalt")
                                    && link.baseline_local.as_ref().and_then(|v| v.get(&f))
                                        != local.get(&f)
                            });
                            let encoding_supported = if let Some(hash) =
                                incoming.password_hash.as_deref()
                            {
                                Self::credential_encoding(hash, incoming.password_type.as_deref())
                                    == Self::credential_encoding(
                                        &user.password_hash,
                                        user.password_type.as_deref(),
                                    )
                            } else if let Some(kind) =
                                incoming.password_type.as_deref().filter(|v| !v.is_empty())
                            {
                                !kind.eq_ignore_ascii_case("plain")
                                    && PasswordService::validate_encoded_hash(
                                        &user.password_hash,
                                        kind,
                                        user.password_salt.as_deref(),
                                    )
                                    .is_ok()
                            } else {
                                // With no existing source encoding, an explicit
                                // PasswordType output column is the capability
                                // contract; an untyped password column is not.
                                columns.iter().any(|c| {
                                    Self::normalize_casdoor_field(&c.casdoor_name) == "passwordtype"
                                })
                            };
                            let local_kind = user
                                .password_type
                                .as_deref()
                                .or_else(|| PasswordService::encoded_type(&user.password_hash))
                                .unwrap_or_default();
                            let encoding_supported = encoding_supported
                                && !local_kind.eq_ignore_ascii_case("plain")
                                && PasswordService::validate_encoded_hash(
                                    &user.password_hash,
                                    local_kind,
                                    user.password_salt.as_deref(),
                                )
                                .is_ok();
                            if credential_changed
                                && (!encoding_supported
                                    || !columns.iter().any(|c| {
                                        Self::normalize_casdoor_field(&c.casdoor_name)
                                            == "passwordsalt"
                                    }) && incoming.password_salt != user.password_salt)
                            {
                                Self::mark_conflict(conn,syncer,&key,"Credential encoding changed locally; source algorithm/salt capability requires explicit review").await?;
                                continue;
                            }
                            let mut desired = Map::new();
                            // Copy untouched source fields verbatim. Only fields
                            // changed since the local baseline are converted.
                            for c in columns {
                                let f = Self::normalize_casdoor_field(&c.casdoor_name);
                                let needs_type = credential_changed
                                    && f == "passwordtype"
                                    && incoming.password_hash.is_none()
                                    && incoming.password_type.as_deref().is_none_or(str::is_empty);
                                let value = if !needs_type
                                    && link.baseline_local.as_ref().and_then(|v| v.get(&f))
                                        == local.get(&f)
                                {
                                    source_row.get(&c.name).cloned().unwrap_or(Value::Null)
                                } else {
                                    Self::export_user(
                                        syncer,
                                        std::slice::from_ref(c),
                                        &user,
                                        affiliations,
                                    )?[&c.name]
                                        .clone()
                                };
                                desired.insert(c.name.clone(), value);
                            }
                            let desired = Value::Object(desired);
                            let desired_projection = Self::source_projection(
                                syncer,
                                columns,
                                desired.as_object().expect("export object"),
                            )?;
                            if desired_projection == source {
                                Self::acknowledge(conn, syncer, &key, &local, &source).await?;
                            } else if link.baseline_source.as_ref() == Some(&source) {
                                let key_column =
                                    columns.iter().find(|c| c.is_key).expect("validated key");
                                if Self::json_value_to_string(&desired[&key_column.name]) != key {
                                    Self::mark_conflict(conn,syncer,&key,"Changing a synchronized primary identity requires an explicit new binding").await?;
                                } else {
                                    Self::enqueue(
                                        conn,
                                        syncer,
                                        &key,
                                        &user,
                                        Some(&source),
                                        desired,
                                        local,
                                    )
                                    .await?;
                                }
                            } else {
                                Self::mark_conflict(conn,syncer,&key,"Both local and source fields changed since the acknowledged baseline").await?;
                            }
                        }
                    }
                }
            }
            if pull {
                Self::upsert_local_user(conn, syncer, incoming).await?;
                let user:User=sqlx::query_as("SELECT u.* FROM users u JOIN syncer_user_links l ON l.user_id=u.id WHERE l.syncer_id=$1 AND l.source_key=$2 AND u.owner=$3")
                    .bind(&syncer.id).bind(&key).bind(&syncer.organization).fetch_one(&mut *conn).await?;
                Self::acknowledge(
                    conn,
                    syncer,
                    &key,
                    &Self::local_projection(syncer, columns, &user),
                    &source,
                )
                .await?;
                run.records_synced += 1;
            }
        }
        // Only an entirely successful, bounded source read reaches here. A
        // missing key never causes an unrelated username match or a hard delete.
        for (key, link) in &links {
            if seen.contains(key) || link.disabled_by_sync {
                continue;
            }
            if link.baseline_source.is_none() {
                // An export rejected before its first source write retains its
                // binding. Re-evaluate only this never-acknowledged local
                // account after configuration repair; deleted source accounts
                // have a baseline and can never enter this insertion path.
                if syncer.is_read_only || link.baseline_local.is_some() {
                    continue;
                }
                let user:Option<User>=sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_admin AND NOT is_forbidden FOR UPDATE")
                    .bind(&link.user_id).bind(&syncer.organization).fetch_optional(&mut *conn).await?;
                let Some(user) = user else { continue };
                let foreign:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM syncer_user_links WHERE user_id=$1 AND syncer_id<>$2)")
                    .bind(&user.id).bind(&syncer.id).fetch_one(&mut *conn).await?;
                if foreign {
                    Self::mark_conflict(conn, syncer, key, "Account is bound to another syncer")
                        .await?;
                    continue;
                }
                if columns
                    .iter()
                    .any(|c| Self::normalize_casdoor_field(&c.casdoor_name) == "password")
                    && !columns
                        .iter()
                        .any(|c| Self::normalize_casdoor_field(&c.casdoor_name) == "passwordtype")
                {
                    Self::mark_conflict(conn,syncer,key,"New-account credential export requires an explicit PasswordType output column").await?;
                    continue;
                }
                let desired = Self::export_user(syncer, columns, &user, affiliations)?;
                let key_column = columns.iter().find(|c| c.is_key).expect("validated key");
                if Self::json_value_to_string(&desired[&key_column.name]) != *key {
                    Self::mark_conflict(conn,syncer,key,"Primary identity changed before first export; explicit binding review required").await?;
                    continue;
                }
                Self::enqueue(
                    conn,
                    syncer,
                    key,
                    &user,
                    None,
                    desired,
                    Self::local_projection(syncer, columns, &user),
                )
                .await?;
                continue;
            }
            let changed:Option<chrono::DateTime<chrono::Utc>>=sqlx::query_scalar("UPDATE users u SET is_forbidden=TRUE,updated_at=clock_timestamp() WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_admin AND NOT is_forbidden AND NOT EXISTS(SELECT 1 FROM syncer_user_links l WHERE l.user_id=u.id AND l.syncer_id<>$3) RETURNING updated_at")
                .bind(&link.user_id).bind(&syncer.organization).bind(&syncer.id).fetch_optional(&mut *conn).await?;
            if let Some(version) = changed {
                sqlx::query("UPDATE syncer_user_links SET disabled_by_sync=TRUE,disabled_user_updated_at=$3,conflict_state=NULL,conflict_at=NULL WHERE syncer_id=$1 AND source_key=$2")
                    .bind(&syncer.id).bind(key).bind(version).execute(&mut *conn).await?;
                run.records_forbidden += 1;
            }
        }
        if !syncer.is_read_only {
            let candidates:Vec<User>=sqlx::query_as("SELECT * FROM users u WHERE owner=$1 AND NOT is_deleted AND NOT is_admin AND NOT is_forbidden AND NOT EXISTS(SELECT 1 FROM syncer_user_links l WHERE l.user_id=u.id) ORDER BY id LIMIT 10001 FOR UPDATE")
                .bind(&syncer.organization).fetch_all(&mut *conn).await?;
            if candidates.len() > 10000 {
                return Err(AppError::Validation(
                    "Too many local export candidates".into(),
                ));
            }
            let key_column = columns.iter().find(|c| c.is_key).expect("validated key");
            for user in candidates {
                // The candidate SELECT may have waited on another Syncer's
                // user row lock. Recheck links in a fresh statement after that
                // wait; its original MVCC snapshot could predate the binding.
                let bound: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM syncer_user_links WHERE user_id=$1)",
                )
                .bind(&user.id)
                .fetch_one(&mut *conn)
                .await?;
                if bound {
                    continue;
                }
                if Self::local_value(
                    &user,
                    &Self::normalize_casdoor_field(&key_column.casdoor_name),
                    false,
                )
                .is_empty()
                {
                    continue;
                }
                let desired = Self::export_user(syncer, columns, &user, affiliations)?;
                let key = desired[&key_column.name].as_str().unwrap_or_default();
                if key.is_empty() || seen.contains(key) || links.contains_key(key) {
                    continue;
                }
                sqlx::query(
                    "INSERT INTO syncer_user_links(syncer_id,source_key,user_id) VALUES($1,$2,$3)",
                )
                .bind(&syncer.id)
                .bind(key)
                .bind(&user.id)
                .execute(&mut *conn)
                .await?;
                if columns
                    .iter()
                    .any(|c| Self::normalize_casdoor_field(&c.casdoor_name) == "password")
                    && !columns
                        .iter()
                        .any(|c| Self::normalize_casdoor_field(&c.casdoor_name) == "passwordtype")
                {
                    Self::mark_conflict(conn,syncer,key,"New-account credential export requires an explicit PasswordType output column").await?;
                    continue;
                }
                Self::enqueue(
                    conn,
                    syncer,
                    key,
                    &user,
                    None,
                    desired.clone(),
                    Self::local_projection(syncer, columns, &user),
                )
                .await?;
            }
        }
        Ok(run)
    }

    async fn reject_iam_database(conn: &mut PgConnection, source: &PgPool) -> AppResult<()> {
        let local: (String, i32, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT current_database(),inet_server_port(),pg_postmaster_start_time()",
        )
        .fetch_one(&mut *conn)
        .await?;
        let remote: (String, i32, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT current_database(),inet_server_port(),pg_postmaster_start_time()",
        )
        .fetch_one(source)
        .await?;
        if local == remote {
            return Err(AppError::Validation(
                "The identity database cannot be used as an external syncer source".into(),
            ));
        }
        Ok(())
    }

    async fn validate_writable_table(
        pool: &PgPool,
        table: &str,
        columns: &[TableColumn],
    ) -> AppResult<()> {
        let key = columns
            .iter()
            .find(|c| c.is_key)
            .ok_or_else(|| AppError::Validation("Missing primary key mapping".into()))?;
        let table = Self::quote_identifier_path(table)?;
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_index i ON i.indrelid=c.oid JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=i.indkey[0] WHERE c.oid=to_regclass($1) AND c.relkind IN ('r','p') AND i.indisunique AND i.indisvalid AND i.indnkeyatts=1 AND i.indpred IS NULL AND i.indexprs IS NULL AND a.attname=$2)")
            .bind(table).bind(&key.name).fetch_one(pool).await?;
        if !valid {
            return Err(AppError::Validation(
                "PostgreSQL writeback needs a real table and a single-column unique source key"
                    .into(),
            ));
        }
        Ok(())
    }

    async fn flush_operations(pool: &PgPool, syncer_id: &str, token: &str) -> AppResult<u64> {
        let ids:Vec<String>=sqlx::query_scalar("SELECT id FROM syncer_operations WHERE syncer_id=$1 AND status='pending' ORDER BY created_at,id LIMIT 10000")
            .bind(syncer_id).fetch_all(pool).await?;
        let mut exported = 0;
        for id in ids {
            // Configuration is fenced throughout remote I/O; users are never
            // locked while awaiting the source database. The outbox commits
            // before this phase and survives cancellation or process failure.
            let mut local = pool.begin().await?;
            let syncer = SyncerService::get_conn(&mut local, syncer_id, true).await?;
            let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM syncer_runtime_state WHERE syncer_id=$1 AND lease_token=$2 AND lease_until>clock_timestamp())")
                .bind(syncer_id).bind(token).fetch_one(&mut *local).await?;
            if !owned || !syncer.is_enabled {
                return Err(AppError::Conflict(
                    "Syncer is disabled or lease changed; operations remain queued".into(),
                ));
            }
            let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted AND NOT disable_signin)")
                .bind(&syncer.organization).fetch_one(&mut *local).await?;
            if !active {
                return Err(AppError::Validation(
                    "Syncer organization is unavailable; operations remain queued".into(),
                ));
            }
            let op:Option<PendingOperation>=sqlx::query_as("SELECT id,source_key,user_id,organization,config_hash,expected_source,desired_source,local_snapshot FROM syncer_operations WHERE id=$1 AND status='pending' FOR UPDATE")
                .bind(&id).fetch_optional(&mut *local).await?;
            let Some(op) = op else { continue };
            let eligible:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users u JOIN syncer_user_links l ON l.user_id=u.id AND l.syncer_id=$3 AND l.source_key=$4 WHERE u.id=$1 AND u.owner=$2 AND NOT u.is_deleted AND NOT u.is_admin)")
                .bind(&op.user_id).bind(&syncer.organization).bind(syncer_id).bind(&op.source_key).fetch_one(&mut *local).await?;
            if syncer.is_read_only
                || op.organization != syncer.organization
                || op.config_hash != Self::config_hash(&syncer)
                || !eligible
            {
                sqlx::query("UPDATE syncer_operations SET status='cancelled',last_error='Binding or configuration changed; explicit review required',updated_at=clock_timestamp() WHERE id=$1").bind(&id).execute(&mut *local).await?;
                Self::mark_conflict(
                    &mut local,
                    &syncer,
                    &op.source_key,
                    "Queued export cancelled because its binding or configuration changed",
                )
                .await?;
                local.commit().await?;
                continue;
            }
            let columns = Self::parse_table_columns(&syncer)?;
            let result = Self::apply_operation(&mut local, &syncer, &columns, &op).await;
            match result {
                Ok(Some(source)) => {
                    Self::acknowledge(
                        &mut local,
                        &syncer,
                        &op.source_key,
                        &op.local_snapshot,
                        &source,
                    )
                    .await?;
                    sqlx::query("UPDATE syncer_operations SET status='applied',attempts=attempts+1,last_error=NULL,updated_at=clock_timestamp() WHERE id=$1")
                        .bind(&op.id).execute(&mut *local).await?;
                    exported += 1;
                    local.commit().await?;
                }
                Ok(None) => {
                    Self::mark_conflict(
                        &mut local,
                        &syncer,
                        &op.source_key,
                        "Source changed before queued writeback; no source fields were overwritten",
                    )
                    .await?;
                    sqlx::query("UPDATE syncer_operations SET status='conflict',attempts=attempts+1,last_error='Source compare-and-swap conflict',updated_at=clock_timestamp() WHERE id=$1")
                        .bind(&op.id).execute(&mut *local).await?;
                    local.commit().await?;
                }
                Err(_) => {
                    // The source may already have committed. Leave the original
                    // desired projection intact; retry recognizes that value
                    // before issuing any UPDATE/INSERT (including triggers).
                    local.rollback().await?;
                    sqlx::query("UPDATE syncer_operations SET attempts=attempts+1,last_error='External writeback unavailable; durable operation retained for retry',updated_at=clock_timestamp() WHERE id=$1 AND status='pending'")
                        .bind(&op.id).execute(pool).await?;
                    return Err(AppError::Internal(
                        "External writeback unavailable; durable operation retained for retry"
                            .into(),
                    ));
                }
            }
        }
        Ok(exported)
    }

    async fn apply_operation(
        conn: &mut PgConnection,
        syncer: &Syncer,
        columns: &[TableColumn],
        op: &PendingOperation,
    ) -> AppResult<Option<Value>> {
        let pool = Self::connect_external_postgres(syncer).await?;
        Self::reject_iam_database(conn, &pool).await?;
        let table_name = syncer.table_name.as_deref().unwrap_or_default();
        Self::validate_writable_table(&pool, table_name, columns).await?;
        let table = Self::quote_identifier_path(table_name)?;
        let key_column = columns.iter().find(|c| c.is_key).expect("validated key");
        let key = Self::quote_identifier_part(&key_column.name)?;
        let mut remote = pool.begin().await?;
        let typed: Value = sqlx::query_scalar(&format!(
            "SELECT to_jsonb(p) FROM jsonb_populate_record(NULL::{table},$1) p"
        ))
        .bind(&op.desired_source)
        .fetch_one(&mut *remote)
        .await?;
        let typed = typed
            .as_object()
            .ok_or_else(|| AppError::Internal("Invalid typed source projection".into()))?;
        if Self::json_value_to_string(typed.get(&key_column.name).unwrap_or(&Value::Null))
            != op.source_key
        {
            return Err(AppError::Validation(
                "Source primary key cannot be converted losslessly".into(),
            ));
        }
        let desired = Self::source_projection(syncer, columns, typed)?;
        let current:Option<Value>=sqlx::query_scalar(&format!("SELECT to_jsonb(t) FROM {table} t,jsonb_populate_record(NULL::{table},$1) p WHERE t.{key}=p.{key} FOR UPDATE OF t"))
            .bind(&op.desired_source).fetch_optional(&mut *remote).await?;
        let current_projection = current
            .as_ref()
            .map(|v| {
                Self::source_projection(syncer, columns, v.as_object().expect("database object"))
            })
            .transpose()?;
        if current_projection.as_ref() == Some(&desired) {
            remote.commit().await?;
            return Ok(Some(desired));
        }
        if current_projection != op.expected_source {
            return Ok(None);
        }
        let fields = columns
            .iter()
            .map(|c| Self::quote_identifier_part(&c.name))
            .collect::<AppResult<Vec<_>>>()?;
        let actual: Value = if current.is_some() {
            let assignments = columns
                .iter()
                .filter(|c| {
                    !c.is_key
                        && current_projection.as_ref().and_then(|v| v.get(&c.name))
                            != desired.get(&c.name)
                })
                .map(|c| Self::quote_identifier_part(&c.name).map(|q| format!("{q}=p.{q}")))
                .collect::<AppResult<Vec<_>>>()?;
            if assignments.is_empty() {
                remote.commit().await?;
                return Ok(Some(desired));
            }
            sqlx::query_scalar(&format!("UPDATE {table} t SET {} FROM jsonb_populate_record(NULL::{table},$1) p WHERE t.{key}=p.{key} RETURNING to_jsonb(t)",assignments.join(",")))
                .bind(&op.desired_source).fetch_one(&mut *remote).await?
        } else {
            sqlx::query_scalar(&format!("INSERT INTO {table} AS t ({}) SELECT {} FROM jsonb_populate_record(NULL::{table},$1) p RETURNING to_jsonb(t)",fields.join(","),fields.iter().map(|q|format!("p.{q}")).collect::<Vec<_>>().join(",")))
                .bind(&op.desired_source).fetch_one(&mut *remote).await?
        };
        let source = Self::source_projection(
            syncer,
            columns,
            actual.as_object().expect("database object"),
        )?;
        remote.commit().await?;
        Ok(Some(source))
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
        conn: &mut PgConnection,
        syncer: &Syncer,
        mut incoming: SyncedUserRecord,
    ) -> AppResult<()> {
        if let Some(avatar) = incoming.avatar.as_mut() {
            if let Some(base) = syncer
                .avatar_base_url
                .as_deref()
                .filter(|base| !base.is_empty())
            {
                if !avatar.starts_with("http://") && !avatar.starts_with("https://") {
                    *avatar = format!(
                        "{}/{}",
                        base.trim_end_matches('/'),
                        avatar.trim_start_matches('/')
                    );
                }
            }
        }
        let linked: Option<String> = sqlx::query_scalar(
            "SELECT user_id FROM syncer_user_links WHERE syncer_id=$1 AND source_key=$2",
        )
        .bind(&syncer.id)
        .bind(&incoming.source_key)
        .fetch_optional(&mut *conn)
        .await?;
        let existing: Option<User> = if let Some(id) = linked {
            Some(sqlx::query_as("SELECT * FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted FOR UPDATE")
                .bind(id).bind(&syncer.organization).fetch_optional(&mut *conn).await?.ok_or_else(||AppError::Validation("Linked syncer account was deleted or moved; recreate its binding explicitly".into()))?)
        } else {
            let (field, value) = if incoming.key_by_name {
                ("name", incoming.name.as_deref())
            } else if incoming.key_field == "email" {
                ("email", incoming.email.as_deref())
            } else if incoming.key_field == "phone" {
                ("phone", incoming.phone.as_deref())
            } else if incoming.ldap_id.is_some() {
                ("ldap", incoming.ldap_id.as_deref())
            } else {
                ("external_id", incoming.external_id.as_deref())
            };
            if let Some(value) = value {
                let matches:Vec<User>=sqlx::query_as(&format!("SELECT * FROM users WHERE owner=$1 AND {field}=$2 AND NOT is_deleted LIMIT 2 FOR UPDATE"))
                    .bind(&syncer.organization).bind(value).fetch_all(&mut *conn).await?;
                if matches.len() > 1 {
                    return Err(AppError::Validation(
                        "Ambiguous syncer identity mapping".into(),
                    ));
                }
                matches.into_iter().next()
            } else {
                None
            }
        };
        if let Some(user) = &existing {
            let foreign: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM syncer_user_links WHERE user_id=$1 AND syncer_id<>$2)",
            )
            .bind(&user.id)
            .bind(&syncer.id)
            .fetch_one(&mut *conn)
            .await?;
            if foreign || user.is_admin {
                return Err(AppError::Validation(
                    "Privileged accounts or users bound to another syncer cannot be imported"
                        .into(),
                ));
            }
        }
        let base = Self::sanitize_user_name(
            incoming
                .name
                .clone()
                .or_else(|| existing.as_ref().map(|user| user.name.clone()))
                .or_else(|| {
                    incoming
                        .email
                        .as_deref()
                        .and_then(|email| email.split('@').next())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| {
                    format!("synced_{}", &Uuid::new_v4().simple().to_string()[..12])
                }),
        );
        let mut name = base.clone();
        let mut suffix = 1;
        loop {
            let occupied: Option<String> =
                sqlx::query_scalar("SELECT id FROM users WHERE owner=$1 AND name=$2")
                    .bind(&syncer.organization)
                    .bind(&name)
                    .fetch_optional(&mut *conn)
                    .await?;
            if occupied
                .as_ref()
                .is_none_or(|id| existing.as_ref().is_some_and(|user| user.id == *id))
            {
                break;
            }
            suffix += 1;
            name = format!("{}_{}", base, suffix);
        }
        if let Some(user) = existing {
            // No password mapping means no password write. For plaintext imports,
            // preserve a matching existing hash instead of rotating random salts
            // and invalidating every login on every scheduled run.
            if let Some(plain) = incoming.password_plaintext.as_deref() {
                if PasswordService::verify_password(
                    plain,
                    &user.password_hash,
                    user.password_type.as_deref().unwrap_or("argon2"),
                    user.password_salt.as_deref(),
                )? {
                    incoming.password_hash = None;
                    incoming.password_type = None;
                    incoming.password_salt = None;
                }
            }
            let changed = incoming
                .password_hash
                .as_ref()
                .is_some_and(|hash| hash != &user.password_hash)
                || incoming
                    .password_type
                    .as_ref()
                    .is_some_and(|kind| Some(kind) != user.password_type.as_ref())
                || incoming.password_hash.is_some() && incoming.password_salt != user.password_salt;
            sqlx::query("UPDATE users SET name=$3,display_name=COALESCE($4,display_name),first_name=COALESCE($5,first_name),last_name=COALESCE($6,last_name),email=COALESCE($7,email),email_verified=COALESCE($8,email_verified),phone=COALESCE($9,phone),avatar=COALESCE($10,avatar),affiliation=COALESCE($11,affiliation),external_id=COALESCE($12,external_id),ldap=COALESCE($13,ldap),signup_application=COALESCE($14,signup_application),password_hash=COALESCE($15,password_hash),password_type=CASE WHEN $15::text IS NULL THEN password_type ELSE $16 END,password_salt=CASE WHEN $15::text IS NULL THEN password_salt ELSE $17 END,is_forbidden=COALESCE($18,is_forbidden),score=COALESCE($20,score),last_change_password_time=CASE WHEN $19 THEN to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') ELSE last_change_password_time END,updated_at=clock_timestamp() WHERE id=$1 AND owner=$2")
                .bind(&user.id).bind(&syncer.organization).bind(&name).bind(&incoming.display_name).bind(&incoming.first_name).bind(&incoming.last_name).bind(&incoming.email).bind(incoming.email_verified).bind(&incoming.phone).bind(&incoming.avatar).bind(&incoming.affiliation).bind(&incoming.external_id).bind(&incoming.ldap_id).bind(&incoming.signup_application).bind(&incoming.password_hash).bind(&incoming.password_type).bind(&incoming.password_salt).bind(incoming.is_forbidden).bind(changed).bind(incoming.score).execute(&mut *conn).await?;
            sqlx::query("INSERT INTO syncer_user_links(syncer_id,source_key,user_id) VALUES($1,$2,$3) ON CONFLICT(syncer_id,source_key) DO NOTHING")
                .bind(&syncer.id).bind(&incoming.source_key).bind(&user.id).execute(&mut *conn).await?;
        } else {
            let id = Uuid::new_v4().to_string();
            let credential_present = incoming.password_hash.is_some();
            let hash = match incoming.password_hash {
                Some(hash) => hash,
                None => {
                    PasswordService::hash_password(&Uuid::new_v4().to_string(), "argon2", None)?
                }
            };
            let display = incoming.display_name.unwrap_or_else(|| name.clone());
            sqlx::query("INSERT INTO users(id,owner,name,password_hash,display_name,first_name,last_name,email,email_verified,phone,avatar,affiliation,external_id,ldap,signup_application,password_type,password_salt,is_forbidden,score) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)")
                .bind(&id).bind(&syncer.organization).bind(&name).bind(hash).bind(display).bind(&incoming.first_name).bind(&incoming.last_name).bind(&incoming.email).bind(incoming.email_verified.unwrap_or(false)).bind(&incoming.phone).bind(&incoming.avatar).bind(&incoming.affiliation).bind(&incoming.external_id).bind(&incoming.ldap_id).bind(&incoming.signup_application).bind(if credential_present {incoming.password_type.as_deref().unwrap_or("argon2")} else {"argon2"}).bind(if credential_present {incoming.password_salt.as_deref()} else {None}).bind(incoming.is_forbidden.unwrap_or(false)).bind(incoming.score.unwrap_or(0)).execute(&mut *conn).await?;
            sqlx::query(
                "INSERT INTO syncer_user_links(syncer_id,source_key,user_id) VALUES($1,$2,$3)",
            )
            .bind(&syncer.id)
            .bind(&incoming.source_key)
            .bind(&id)
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    }

    fn sanitize_user_name(name: String) -> String {
        let value = name
            .trim()
            .chars()
            .take(80)
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();
        if value.is_empty() {
            "synced_user".into()
        } else {
            value
        }
    }
}
