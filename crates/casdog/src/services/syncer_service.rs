use crate::{
    error::{AppError, AppResult},
    models::{CreateSyncerRequest, Syncer, SyncerResponse, UpdateSyncerRequest},
    services::syncer_executor::SyncRunResult,
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;
pub struct SyncerService;
// Preserve the column labels expected by Syncer's explicit sqlx(rename) fields.
const SYNCER_SELECT: &str = "SELECT id,owner,name,created_at,organization,\"type\",database_type,ssl_mode,host,port,\"user\",password,\"database\",\"table\",table_columns,affiliation_table,avatar_base_url,error_text,sync_interval,is_read_only,is_enabled FROM syncers";
impl SyncerService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<SyncerResponse>, i64)> {
        Self::list_scoped(pool, owner, None, page, page_size).await
    }
    pub async fn list_scoped(
        pool: &PgPool,
        owner: Option<&str>,
        organization: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<SyncerResponse>, i64)> {
        if page < 1 || !(1..=1000).contains(&page_size) {
            return Err(AppError::Validation("Invalid syncer pagination".into()));
        }
        let offset = (page - 1)
            .checked_mul(page_size)
            .ok_or_else(|| AppError::Validation("Syncer page overflow".into()))?;
        let rows:Vec<Syncer>=sqlx::query_as(&format!("{SYNCER_SELECT} WHERE ($1::text IS NULL OR owner=$1) AND ($2::text IS NULL OR organization=$2) ORDER BY created_at DESC LIMIT $3 OFFSET $4"))
            .bind(owner).bind(organization).bind(page_size).bind(offset).fetch_all(pool).await?;
        let total =
            sqlx::query_scalar("SELECT COUNT(*) FROM syncers WHERE ($1::text IS NULL OR owner=$1) AND ($2::text IS NULL OR organization=$2)")
                .bind(owner)
                .bind(organization)
                .fetch_one(pool)
                .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total))
    }
    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<SyncerResponse> {
        Ok(Self::get_by_id_internal(pool, id).await?.into())
    }
    pub async fn get_by_id_internal(pool: &PgPool, id: &str) -> AppResult<Syncer> {
        Self::get_conn(&mut *pool.acquire().await?, id, false).await
    }
    pub(crate) async fn get_conn(
        conn: &mut PgConnection,
        id: &str,
        lock: bool,
    ) -> AppResult<Syncer> {
        sqlx::query_as(&format!(
            "{SYNCER_SELECT} WHERE id=$1{}",
            if lock { " FOR UPDATE" } else { "" }
        ))
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| AppError::NotFound("Syncer not found".into()))
    }
    /// Fence competing runs and configuration writes while allowing an
    /// independently reviewed grant's FK check during a long source request.
    pub(crate) async fn get_run_conn(conn: &mut PgConnection, id: &str) -> AppResult<Syncer> {
        sqlx::query_as(&format!("{SYNCER_SELECT} WHERE id=$1 FOR NO KEY UPDATE"))
            .bind(id)
            .fetch_optional(conn)
            .await?
            .ok_or_else(|| AppError::NotFound("Syncer not found".into()))
    }
    pub(crate) async fn validate(conn: &mut PgConnection, s: &Syncer) -> AppResult<()> {
        crate::handlers::parity_resources::service::identity(&s.owner, &s.name)?;
        if !(1..=65535).contains(&s.port)
            || !(1..=525600).contains(&s.sync_interval)
            || s.host.is_empty()
            || s.host.len() > 255
            || s.host.chars().any(char::is_control)
        {
            return Err(AppError::Validation(
                "Invalid syncer host, port or interval".into(),
            ));
        }
        let org: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM organizations WHERE name=$1 AND NOT is_deleted)",
        )
        .bind(&s.organization)
        .fetch_one(&mut *conn)
        .await?;
        if !org {
            return Err(AppError::Validation(
                "Syncer organization is unavailable".into(),
            ));
        }
        if !matches!(
            s.syncer_type.as_str(),
            "Database"
                | "LDAP"
                | "Active Directory"
                | "Keycloak"
                | "SCIM"
                | "Azure AD"
                | "Google Workspace"
        ) {
            return Err(AppError::Validation("Unsupported syncer type".into()));
        }
        if !s.is_read_only && s.syncer_type != "Database" {
            return Err(AppError::Validation(
                "LDAP, Active Directory, Keycloak, SCIM and cloud-directory writeback are unsupported; enable read-only synchronization"
                    .into(),
            ));
        }
        if matches!(s.syncer_type.as_str(), "Azure AD" | "Google Workspace") {
            return super::syncer_cloud::CloudSource::validate(s);
        }
        if s.syncer_type == "SCIM" {
            return super::syncer_scim::ScimSource::validate(s);
        }
        if s.database.as_deref().is_none_or(str::is_empty)
            || s.database.as_ref().is_some_and(|v| v.len() > 100)
            || s.table_name.as_ref().is_some_and(|v| v.len() > 100)
            || s.user.len() > 100
            || s.password.len() > 255
        {
            return Err(AppError::Validation(
                "Invalid syncer source database, table or credentials".into(),
            ));
        }
        if s.syncer_type == "Active Directory" {
            crate::services::syncer_executor::SyncerExecutor::ad_columns(s)?;
        } else if s.syncer_type != "LDAP" {
            if !matches!(
                s.database_type
                    .as_deref()
                    .unwrap_or("postgres")
                    .to_ascii_lowercase()
                    .as_str(),
                "postgres" | "postgresql"
            ) {
                return Err(AppError::Validation(
                    "Only PostgreSQL database sync is supported".into(),
                ));
            }
            crate::services::syncer_executor::SyncerExecutor::validate_columns(s)?;
        } else if s.table_columns.as_deref().is_some_and(|v| !v.is_empty()) {
            crate::services::syncer_executor::SyncerExecutor::validate_columns(s)?;
        }
        Ok(())
    }
    pub async fn create(pool: &PgPool, req: CreateSyncerRequest) -> AppResult<SyncerResponse> {
        let row = Syncer {
            id: Uuid::new_v4().to_string(),
            owner: req.owner,
            name: req.name,
            created_at: chrono::Utc::now(),
            organization: req.organization,
            syncer_type: req.syncer_type,
            database_type: req.database_type,
            ssl_mode: req.ssl_mode,
            host: req.host,
            port: req.port,
            user: req.user,
            password: req.password,
            database: req.database,
            table_name: req.table_name,
            table_columns: req
                .table_columns
                .map(|v| serde_json::to_string(&v).unwrap()),
            affiliation_table: req.affiliation_table,
            avatar_base_url: req.avatar_base_url,
            error_text: None,
            sync_interval: req.sync_interval.unwrap_or(60),
            is_read_only: req.is_read_only.unwrap_or(false),
            is_enabled: req.is_enabled.unwrap_or(true),
        };
        if row.password == "***" {
            return Err(AppError::Validation(
                "A real source password is required when creating a syncer".into(),
            ));
        }
        let mut tx = pool.begin().await?;
        Self::validate(&mut tx, &row).await?;
        sqlx::query("INSERT INTO syncers(id,owner,name,organization,\"type\",database_type,ssl_mode,host,port,\"user\",password,\"database\",\"table\",table_columns,affiliation_table,avatar_base_url,sync_interval,is_read_only,is_enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)")
            .bind(&row.id).bind(&row.owner).bind(&row.name).bind(&row.organization).bind(&row.syncer_type).bind(&row.database_type).bind(&row.ssl_mode).bind(&row.host).bind(row.port).bind(&row.user).bind(&row.password).bind(&row.database).bind(&row.table_name).bind(&row.table_columns).bind(&row.affiliation_table).bind(&row.avatar_base_url).bind(row.sync_interval).bind(row.is_read_only).bind(row.is_enabled).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO syncer_runtime_state(syncer_id) VALUES($1)")
            .bind(&row.id)
            .execute(&mut *tx)
            .await?;
        let saved = Self::get_conn(&mut tx, &row.id, false).await?;
        tx.commit().await?;
        Ok(saved.into())
    }
    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateSyncerRequest,
    ) -> AppResult<SyncerResponse> {
        let mut tx = pool.begin().await?;
        let mut row = Self::get_conn(&mut tx, id, true).await?;
        let original_binding = serde_json::json!([
            row.organization,
            row.syncer_type,
            row.database_type,
            row.host,
            row.port,
            row.user,
            row.database,
            row.table_name
        ]);
        if let Some(v) = req.organization {
            if v != row.organization {
                let bound: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM syncer_user_links WHERE syncer_id=$1)",
                )
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
                if bound {
                    return Err(AppError::Validation(
                        "Create a new syncer to change an organization with linked accounts".into(),
                    ));
                }
            }
            row.organization = v;
        }
        if let Some(v) = req.syncer_type {
            row.syncer_type = v;
        }
        if let Some(v) = req.database_type {
            row.database_type = Some(v);
        }
        if let Some(v) = req.ssl_mode {
            row.ssl_mode = Some(v);
        }
        if let Some(v) = req.host {
            row.host = v;
        }
        if let Some(v) = req.port {
            row.port = v;
        }
        if let Some(v) = req.user {
            if !(row.syncer_type == "SCIM" && row.password.is_empty() && v == "***") {
                row.user = v;
            }
        }
        if let Some(v) = req.password.filter(|v| v != "***") {
            row.password = v;
        }
        if let Some(v) = req.database {
            row.database = Some(v);
        }
        if let Some(v) = req.table_name {
            row.table_name = Some(v);
        }
        if let Some(v) = req.table_columns {
            row.table_columns = Some(serde_json::to_string(&v).unwrap());
        }
        if let Some(v) = req.affiliation_table {
            row.affiliation_table = Some(v);
        }
        if let Some(v) = req.avatar_base_url {
            row.avatar_base_url = Some(v);
        }
        if let Some(v) = req.sync_interval {
            row.sync_interval = v;
        }
        if let Some(v) = req.is_read_only {
            row.is_read_only = v;
        }
        if let Some(v) = req.is_enabled {
            row.is_enabled = v;
        }
        let updated_binding = serde_json::json!([
            row.organization,
            row.syncer_type,
            row.database_type,
            row.host,
            row.port,
            row.user,
            row.database,
            row.table_name
        ]);
        if original_binding != updated_binding {
            let bound: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM syncer_user_links WHERE syncer_id=$1)",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            if bound {
                return Err(AppError::Validation(
                    "Create a new syncer to change the source or tenant of linked accounts".into(),
                ));
            }
        }
        Self::validate(&mut tx, &row).await?;
        sqlx::query("UPDATE syncers SET organization=$2,\"type\"=$3,database_type=$4,ssl_mode=$5,host=$6,port=$7,\"user\"=$8,password=$9,\"database\"=$10,\"table\"=$11,table_columns=$12,affiliation_table=$13,avatar_base_url=$14,sync_interval=$15,is_read_only=$16,is_enabled=$17 WHERE id=$1")
            .bind(id).bind(&row.organization).bind(&row.syncer_type).bind(&row.database_type).bind(&row.ssl_mode).bind(&row.host).bind(row.port).bind(&row.user).bind(&row.password).bind(&row.database).bind(&row.table_name).bind(&row.table_columns).bind(&row.affiliation_table).bind(&row.avatar_base_url).bind(row.sync_interval).bind(row.is_read_only).bind(row.is_enabled).execute(&mut *tx).await?;
        // Edits schedule a new run but cannot invalidate an in-flight lease.
        sqlx::query("INSERT INTO syncer_runtime_state(syncer_id) VALUES($1) ON CONFLICT(syncer_id) DO UPDATE SET next_run_at=clock_timestamp()")
            .bind(id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(row.into())
    }
    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let mut tx = pool.begin().await?;
        let record = Self::get_conn(&mut tx, id, true).await?;
        super::syncer_cloud::CloudSource::detach(&mut tx, &record).await?;
        sqlx::query("UPDATE syncer_operations SET status='cancelled',last_error='Syncer deleted',updated_at=clock_timestamp() WHERE syncer_id=$1 AND status='pending'")
            .bind(id).execute(&mut *tx).await?;
        if sqlx::query("DELETE FROM syncers WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            == 0
        {
            return Err(AppError::NotFound("Syncer not found".into()));
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn run_sync(pool: &PgPool, id: &str) -> AppResult<SyncRunResult> {
        crate::services::syncer_executor::SyncerExecutor::execute_syncer(pool, id).await
    }
}
