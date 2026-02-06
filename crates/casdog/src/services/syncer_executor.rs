use std::collections::HashMap;

use sqlx::PgPool;
use tokio::time::{self, Duration};
use tracing;

use crate::error::{AppError, AppResult};
use crate::models::SyncerResponse;
use crate::services::SyncerService;

// ---------------------------------------------------------------------------
// Syncer execution result
// ---------------------------------------------------------------------------

/// Outcome of a single syncer execution run.
#[derive(Debug, Clone)]
pub struct SyncRunResult {
    /// ID of the syncer that was executed.
    pub syncer_id: String,
    /// Whether the run completed without errors.
    pub success: bool,
    /// Number of records that were synchronised (0 for placeholder runs).
    pub records_synced: u64,
    /// Human-readable message describing the outcome.
    pub message: String,
}

// ---------------------------------------------------------------------------
// SyncerExecutor
// ---------------------------------------------------------------------------

/// Responsible for actually executing syncer tasks.
///
/// `SyncerService` manages CRUD for syncer *configurations*; this struct
/// contains the logic that connects to external data sources, fetches rows,
/// and upserts them into the local users table.
///
/// **Current status:** placeholder.  The `execute_syncer` method validates
/// the configuration and records the attempt but does not yet perform real
/// data synchronisation.  Each database/protocol back-end should be
/// implemented behind a trait so that new syncer types can be added without
/// modifying this file.
pub struct SyncerExecutor;

impl SyncerExecutor {
    // -------------------------------------------------------------------
    // Single-syncer execution
    // -------------------------------------------------------------------

    /// Execute a single syncer by its ID.
    ///
    /// 1. Fetches the syncer configuration from the database.
    /// 2. Validates that the syncer is enabled.
    /// 3. Dispatches to the appropriate back-end based on `syncer_type`.
    /// 4. Updates the syncer's `error_text` column with the result.
    pub async fn execute_syncer(pool: &PgPool, syncer_id: &str) -> AppResult<SyncRunResult> {
        // Load configuration.
        let syncer = SyncerService::get_by_id(pool, syncer_id).await?;

        if !syncer.is_enabled {
            return Err(AppError::Validation(format!(
                "Syncer '{}' is disabled",
                syncer_id
            )));
        }

        // Dispatch based on type.
        let result = match syncer.syncer_type.as_str() {
            "Database" => Self::execute_database_sync(pool, &syncer).await,
            "LDAP" => Self::execute_ldap_sync(pool, &syncer).await,
            "Keycloak" => Self::execute_keycloak_sync(pool, &syncer).await,
            other => Ok(SyncRunResult {
                syncer_id: syncer_id.to_string(),
                success: false,
                records_synced: 0,
                message: format!("Unsupported syncer type: {}", other),
            }),
        };

        // Persist the outcome in the syncer's error_text field.
        match &result {
            Ok(run) => {
                Self::update_error_text(
                    pool,
                    syncer_id,
                    if run.success {
                        None
                    } else {
                        Some(&run.message)
                    },
                )
                .await;
            }
            Err(e) => {
                Self::update_error_text(pool, syncer_id, Some(&e.to_string())).await;
            }
        }

        result
    }

    // -------------------------------------------------------------------
    // Batch execution
    // -------------------------------------------------------------------

    /// Execute all enabled syncers whose interval has elapsed.
    ///
    /// Returns a map from syncer ID to the run result.
    pub async fn execute_all_due(pool: &PgPool) -> AppResult<HashMap<String, SyncRunResult>> {
        // Fetch all enabled syncers.
        let (syncers, _total) = SyncerService::list(pool, None, 1, 1000).await?;

        let mut results = HashMap::new();

        for syncer in syncers {
            if !syncer.is_enabled {
                continue;
            }

            let id = syncer.id.clone();
            match Self::execute_syncer(pool, &id).await {
                Ok(result) => {
                    results.insert(id, result);
                }
                Err(e) => {
                    tracing::error!(syncer_id = %id, error = %e, "Syncer execution failed");
                    results.insert(
                        id.clone(),
                        SyncRunResult {
                            syncer_id: id,
                            success: false,
                            records_synced: 0,
                            message: e.to_string(),
                        },
                    );
                }
            }
        }

        Ok(results)
    }

    // -------------------------------------------------------------------
    // Background scheduler
    // -------------------------------------------------------------------

    /// Spawn a background task that periodically executes due syncers.
    ///
    /// The task runs in an infinite loop, sleeping for `check_interval`
    /// between iterations.  It is intended to be spawned once at application
    /// startup via `tokio::spawn`.
    ///
    /// ```ignore
    /// let pool = pool.clone();
    /// tokio::spawn(async move {
    ///     SyncerExecutor::start_scheduler(pool, Duration::from_secs(60)).await;
    /// });
    /// ```
    pub async fn start_scheduler(pool: PgPool, check_interval: Duration) {
        tracing::info!(
            interval_secs = check_interval.as_secs(),
            "Syncer scheduler started"
        );

        let mut interval = time::interval(check_interval);

        loop {
            interval.tick().await;

            tracing::debug!("Syncer scheduler tick - checking for due syncers");

            match Self::execute_all_due(&pool).await {
                Ok(results) => {
                    let succeeded = results.values().filter(|r| r.success).count();
                    let failed = results.len() - succeeded;
                    if !results.is_empty() {
                        tracing::info!(
                            total = results.len(),
                            succeeded,
                            failed,
                            "Syncer scheduler run complete"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Syncer scheduler failed to execute due syncers");
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Back-end stubs (placeholder implementations)
    // -------------------------------------------------------------------

    /// Placeholder for database-type syncer execution.
    ///
    /// In production this would:
    /// 1. Open a connection to the external database using the syncer config.
    /// 2. Query the configured table and columns.
    /// 3. Map each row to a user via the `table_columns` mapping.
    /// 4. Upsert the mapped users into the local `users` table.
    async fn execute_database_sync(
        _pool: &PgPool,
        syncer: &SyncerResponse,
    ) -> AppResult<SyncRunResult> {
        tracing::info!(
            syncer_id = %syncer.id,
            host = %syncer.host,
            port = %syncer.port,
            "Database sync requested (placeholder)"
        );

        // TODO: Implement real database synchronisation.
        //
        // Rough outline:
        //   let external_pool = build_external_pool(&syncer).await?;
        //   let rows = fetch_external_rows(&external_pool, &syncer).await?;
        //   let mapped = map_rows_to_users(rows, &syncer.table_columns)?;
        //   let count = upsert_users(pool, mapped).await?;

        Ok(SyncRunResult {
            syncer_id: syncer.id.clone(),
            success: true,
            records_synced: 0,
            message: "Database sync completed (placeholder - no records synced)".to_string(),
        })
    }

    /// Placeholder for LDAP-type syncer execution.
    ///
    /// In production this would connect to the LDAP directory, perform a
    /// search with the configured base DN and filter, and map entries to
    /// local users.
    async fn execute_ldap_sync(
        _pool: &PgPool,
        syncer: &SyncerResponse,
    ) -> AppResult<SyncRunResult> {
        tracing::info!(
            syncer_id = %syncer.id,
            host = %syncer.host,
            port = %syncer.port,
            "LDAP sync requested (placeholder)"
        );

        // TODO: Implement real LDAP synchronisation.

        Ok(SyncRunResult {
            syncer_id: syncer.id.clone(),
            success: true,
            records_synced: 0,
            message: "LDAP sync completed (placeholder - no records synced)".to_string(),
        })
    }

    /// Placeholder for Keycloak-type syncer execution.
    ///
    /// In production this would use the Keycloak Admin REST API to fetch
    /// users from the configured realm and upsert them locally.
    async fn execute_keycloak_sync(
        _pool: &PgPool,
        syncer: &SyncerResponse,
    ) -> AppResult<SyncRunResult> {
        tracing::info!(
            syncer_id = %syncer.id,
            host = %syncer.host,
            port = %syncer.port,
            "Keycloak sync requested (placeholder)"
        );

        // TODO: Implement real Keycloak synchronisation.

        Ok(SyncRunResult {
            syncer_id: syncer.id.clone(),
            success: true,
            records_synced: 0,
            message: "Keycloak sync completed (placeholder - no records synced)".to_string(),
        })
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    /// Update the `error_text` column on the syncer record.
    ///
    /// Passing `None` clears any previous error.
    async fn update_error_text(pool: &PgPool, syncer_id: &str, error: Option<&str>) {
        let result = sqlx::query("UPDATE syncers SET error_text = $1 WHERE id = $2")
            .bind(error)
            .bind(syncer_id)
            .execute(pool)
            .await;

        if let Err(e) = result {
            tracing::warn!(
                syncer_id = %syncer_id,
                error = %e,
                "Failed to update syncer error_text"
            );
        }
    }
}
