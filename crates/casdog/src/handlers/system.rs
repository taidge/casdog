use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::Serialize;
use sqlx::{Pool, Postgres};

use crate::error::{AppError, AppResult};

/// System version and build information.
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemInfoResponse {
    /// Application version from Cargo.toml
    pub version: String,
    /// Git commit hash (read from CASDOG_COMMIT_ID env var at runtime, or "unknown")
    pub commit_id: String,
    /// Language/runtime version. Named `go_version` for Casdoor API compatibility,
    /// but returns "rust-{rustc_version}" in Casdog.
    pub go_version: String,
    /// Build timestamp (read from CASDOG_BUILD_TIME env var at runtime, or "unknown")
    pub build_time: String,
}

/// Prometheus-style metrics summary.
#[derive(Debug, Serialize, ToSchema)]
pub struct PrometheusInfoResponse {
    pub content_type: String,
    pub metrics: String,
}

fn build_system_info_response() -> SystemInfoResponse {
    let version = env!("CARGO_PKG_VERSION").to_string();

    let commit_id = std::env::var("CASDOG_COMMIT_ID").unwrap_or_else(|_| "unknown".to_string());

    let build_time = std::env::var("CASDOG_BUILD_TIME").unwrap_or_else(|_| "unknown".to_string());

    // Casdoor returns the Go version here; we return the Rust toolchain info instead.
    let rust_version = format!(
        "rust-{}",
        option_env!("CARGO_PKG_RUST_VERSION").unwrap_or("stable")
    );

    SystemInfoResponse {
        version,
        commit_id,
        go_version: rust_version,
        build_time,
    }
}

/// Returns system version and build metadata.
///
/// The commit hash and build time are read from the `CASDOG_COMMIT_ID` and
/// `CASDOG_BUILD_TIME` environment variables respectively. If those variables
/// are not set the fields fall back to `"unknown"`.
#[endpoint(
    tags("System"),
    summary = "Get system info",
    responses(
        (status_code = 200, description = "System information", body = SystemInfoResponse)
    )
)]
pub async fn get_system_info() -> AppResult<Json<SystemInfoResponse>> {
    Ok(Json(build_system_info_response()))
}

/// Returns version and build metadata using Casdoor's `get-version-info` naming.
#[endpoint(
    tags("System"),
    summary = "Get version info",
    responses(
        (status_code = 200, description = "Version information", body = SystemInfoResponse)
    )
)]
pub async fn get_version_info() -> AppResult<Json<SystemInfoResponse>> {
    Ok(Json(build_system_info_response()))
}

/// Returns Prometheus-compatible metrics text.
///
/// Queries live counts from the database and formats them in the Prometheus
/// exposition format so that a `/metrics` scrape endpoint can consume them.
#[endpoint(
    tags("System"),
    summary = "Get Prometheus metrics info",
    responses(
        (status_code = 200, description = "Prometheus metrics text")
    )
)]
pub async fn get_prometheus_info(depot: &mut Depot) -> AppResult<String> {
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not found".to_string()))?
        .clone();

    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_deleted = FALSE")
        .fetch_one(&pool)
        .await?;
    let org_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM organizations WHERE is_deleted = FALSE")
            .fetch_one(&pool)
            .await?;
    let provider_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM providers WHERE is_deleted = FALSE")
            .fetch_one(&pool)
            .await?;
    let app_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM applications WHERE is_deleted = FALSE")
            .fetch_one(&pool)
            .await?;
    let session_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool)
        .await?;
    let token_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tokens")
        .fetch_one(&pool)
        .await?;

    let version = env!("CARGO_PKG_VERSION");

    let metrics = format!(
        "# HELP casdog_info Casdog build information\n\
         # TYPE casdog_info gauge\n\
         casdog_info{{version=\"{}\"}} 1\n\
         # HELP casdog_users_total Total number of active users\n\
         # TYPE casdog_users_total gauge\n\
         casdog_users_total {}\n\
         # HELP casdog_organizations_total Total number of active organizations\n\
         # TYPE casdog_organizations_total gauge\n\
         casdog_organizations_total {}\n\
         # HELP casdog_providers_total Total number of active providers\n\
         # TYPE casdog_providers_total gauge\n\
         casdog_providers_total {}\n\
         # HELP casdog_applications_total Total number of active applications\n\
         # TYPE casdog_applications_total gauge\n\
         casdog_applications_total {}\n\
         # HELP casdog_sessions_active Current number of sessions\n\
         # TYPE casdog_sessions_active gauge\n\
         casdog_sessions_active {}\n\
         # HELP casdog_tokens_total Total number of tokens\n\
         # TYPE casdog_tokens_total gauge\n\
         casdog_tokens_total {}\n",
        version,
        user_count.0,
        org_count.0,
        provider_count.0,
        app_count.0,
        session_count.0,
        token_count.0,
    );

    Ok(metrics)
}
