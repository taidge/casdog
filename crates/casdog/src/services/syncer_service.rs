use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreateSyncerRequest, Syncer, SyncerResponse, UpdateSyncerRequest};
use crate::services::syncer_executor::SyncRunResult;

pub struct SyncerService;

const SYNCER_SELECT: &str = r#"
    SELECT id, owner, name, created_at, organization, "type" as syncer_type,
           database_type, ssl_mode, host, port, "user", password, "database",
           "table" as table_name, table_columns, affiliation_table, avatar_base_url,
           error_text, sync_interval, is_read_only, is_enabled
    FROM syncers
"#;

impl SyncerService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<SyncerResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let syncers: Vec<Syncer> = if let Some(owner) = owner {
            sqlx::query_as(&format!(
                "{} WHERE owner = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                SYNCER_SELECT
            ))
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as(&format!(
                "{} ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                SYNCER_SELECT
            ))
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?
        };

        let total: i64 = if let Some(owner) = owner {
            sqlx::query_scalar("SELECT COUNT(*) FROM syncers WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM syncers")
                .fetch_one(pool)
                .await?
        };

        Ok((syncers.into_iter().map(|s| s.into()).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<SyncerResponse> {
        let syncer = Self::get_by_id_internal(pool, id).await?;
        Ok(syncer.into())
    }

    pub async fn get_by_id_internal(pool: &PgPool, id: &str) -> AppResult<Syncer> {
        let syncer: Syncer = sqlx::query_as(&format!("{} WHERE id = $1", SYNCER_SELECT))
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| AppError::NotFound("Syncer not found".to_string()))?;

        Ok(syncer)
    }

    pub async fn create(pool: &PgPool, req: CreateSyncerRequest) -> AppResult<SyncerResponse> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let table_columns_json = req
            .table_columns
            .map(|c| serde_json::to_string(&c).unwrap_or_default());

        sqlx::query(
            r#"
            INSERT INTO syncers (id, owner, name, created_at, organization, "type", database_type,
                                 host, port, "user", password, "database", "table", table_columns,
                                 sync_interval, is_read_only, is_enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(now)
        .bind(&req.organization)
        .bind(&req.syncer_type)
        .bind(&req.database_type)
        .bind(&req.host)
        .bind(req.port)
        .bind(&req.user)
        .bind(&req.password)
        .bind(&req.database)
        .bind(&req.table_name)
        .bind(&table_columns_json)
        .bind(req.sync_interval.unwrap_or(60))
        .bind(req.is_read_only.unwrap_or(false))
        .bind(req.is_enabled.unwrap_or(true))
        .execute(pool)
        .await?;

        Self::get_by_id(pool, &id).await
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateSyncerRequest,
    ) -> AppResult<SyncerResponse> {
        let table_columns_json = req
            .table_columns
            .map(|c| serde_json::to_string(&c).unwrap_or_default());

        sqlx::query(
            r#"
            UPDATE syncers
            SET organization = COALESCE($1, organization),
                "type" = COALESCE($2, "type"),
                database_type = COALESCE($3, database_type),
                host = COALESCE($4, host),
                port = COALESCE($5, port),
                "user" = COALESCE($6, "user"),
                password = COALESCE($7, password),
                "database" = COALESCE($8, "database"),
                "table" = COALESCE($9, "table"),
                table_columns = COALESCE($10, table_columns),
                sync_interval = COALESCE($11, sync_interval),
                is_read_only = COALESCE($12, is_read_only),
                is_enabled = COALESCE($13, is_enabled)
            WHERE id = $14
            "#,
        )
        .bind(&req.organization)
        .bind(&req.syncer_type)
        .bind(&req.database_type)
        .bind(&req.host)
        .bind(req.port)
        .bind(&req.user)
        .bind(&req.password)
        .bind(&req.database)
        .bind(&req.table_name)
        .bind(&table_columns_json)
        .bind(req.sync_interval)
        .bind(req.is_read_only)
        .bind(req.is_enabled)
        .bind(id)
        .execute(pool)
        .await?;

        Self::get_by_id(pool, id).await
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM syncers WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Syncer not found".to_string()));
        }

        Ok(())
    }

    pub async fn run_sync(pool: &PgPool, id: &str) -> AppResult<SyncRunResult> {
        crate::services::syncer_executor::SyncerExecutor::execute_syncer(pool, id).await
    }
}
