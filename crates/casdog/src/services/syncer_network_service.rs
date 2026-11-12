//! Explicit private-network exceptions for cloud-directory transports.
//! No Syncer row lock: an executing snapshot holds that lock and must not block
//! an administrator from revoking the independent network grant.
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use salvo::oapi::ToSchema;
use serde::Serialize;
use sha2::Sha256;
use sqlx::{PgConnection, PgPool};

use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    models::Syncer,
};

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncerNetworkApproval {
    pub syncer_id: String,
    pub target_origins: Vec<String>,
    pub allow_private: bool,
    pub stale: bool,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
}

pub fn configuration_stamp(s: &Syncer) -> String {
    let bytes = serde_json::to_vec(&serde_json::json!([
        "casdog.cloud-directory.network.v1",
        s.id,
        s.owner,
        s.organization,
        s.syncer_type,
        s.database_type,
        s.host,
        s.port,
        s.user,
        s.password,
        s.database,
        s.table_name,
        s.table_columns,
        s.affiliation_table,
        s.avatar_base_url,
        s.is_read_only,
    ]))
    .expect("serializable directory configuration");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(crate::config::AppConfig::get().jwt.secret.as_bytes())
            .expect("HMAC key");
    mac.update(&bytes);
    hex::encode(mac.finalize().into_bytes())
}

async fn current(conn: &mut PgConnection, id: &str) -> AppResult<Syncer> {
    super::SyncerService::get_conn(conn, id, false).await
}

/// Reuse the executor's existing Read Committed connection. Every statement
/// sees committed grant revocations, without needing a second pool slot.
pub async fn current_access_conn(conn: &mut PgConnection, snapshot: &Syncer) -> AppResult<bool> {
    Ok(network_binding_conn(conn, snapshot).await?.is_some())
}

/// A snapshot pins this generation. Reapproval must not resurrect work which
/// started under a revoked grant, even when its stored configuration is equal.
pub async fn network_binding_conn(
    conn: &mut PgConnection,
    snapshot: &Syncer,
) -> AppResult<Option<String>> {
    let saved = current(conn, &snapshot.id).await?;
    let stamp = configuration_stamp(&saved);
    if stamp != configuration_stamp(snapshot) {
        return Err(AppError::Authorization(
            "Directory configuration changed; start a new synchronization".into(),
        ));
    }
    Ok(sqlx::query_scalar("SELECT generation FROM syncer_network_approvals WHERE syncer_id=$1 AND configuration_stamp=$2")
        .bind(&saved.id).bind(stamp).fetch_optional(conn).await?)
}

pub async fn current_access(pool: &PgPool, snapshot: &Syncer) -> AppResult<bool> {
    current_access_conn(&mut *pool.acquire().await?, snapshot).await
}

async fn status(conn: &mut PgConnection, s: &Syncer) -> AppResult<SyncerNetworkApproval> {
    let target_origins = if matches!(s.syncer_type.as_str(), "Azure AD" | "Google Workspace") {
        super::syncer_cloud::CloudSource::network_origins(s)?
    } else {
        Vec::new()
    };
    let row: Option<(String, String, DateTime<Utc>)> = sqlx::query_as("SELECT configuration_stamp,approved_by,approved_at FROM syncer_network_approvals WHERE syncer_id=$1")
        .bind(&s.id).fetch_optional(conn).await?;
    let (allow_private, stale, approved_by, approved_at) = match row {
        Some((stamp, actor, at)) => {
            let matches = stamp == configuration_stamp(s);
            (matches, !matches, Some(actor), Some(at))
        }
        None => (false, false, None, None),
    };
    Ok(SyncerNetworkApproval {
        syncer_id: s.id.clone(),
        target_origins,
        allow_private,
        stale,
        approved_by,
        approved_at,
    })
}

pub async fn get(pool: &PgPool, actor: &Principal, id: &str) -> AppResult<SyncerNetworkApproval> {
    let mut tx = pool.begin().await?;
    super::provider_network_service::administrator(&mut tx, actor).await?;
    let s = current(&mut tx, id).await?;
    let result = status(&mut tx, &s).await?;
    tx.commit().await?;
    Ok(result)
}

pub async fn approve(
    pool: &PgPool,
    actor: &Principal,
    id: &str,
) -> AppResult<SyncerNetworkApproval> {
    let mut tx = pool.begin().await?;
    super::provider_network_service::administrator(&mut tx, actor).await?;
    let s = current(&mut tx, id).await?;
    if !matches!(s.syncer_type.as_str(), "Azure AD" | "Google Workspace") {
        return Err(AppError::Validation(
            "Private directory approval requires an Azure AD or Google Workspace source".into(),
        ));
    }
    super::syncer_cloud::CloudSource::validate(&s)?;
    sqlx::query("INSERT INTO syncer_network_approvals(syncer_id,configuration_stamp,generation,approved_by) VALUES($1,$2,$3,$4) ON CONFLICT(syncer_id) DO UPDATE SET configuration_stamp=EXCLUDED.configuration_stamp,generation=EXCLUDED.generation,approved_by=EXCLUDED.approved_by,approved_at=clock_timestamp()")
        .bind(&s.id).bind(configuration_stamp(&s)).bind(uuid::Uuid::new_v4().to_string()).bind(&actor.id).execute(&mut *tx).await?;
    let result = status(&mut tx, &s).await?;
    tx.commit().await?;
    Ok(result)
}

pub async fn revoke(
    pool: &PgPool,
    actor: &Principal,
    id: &str,
) -> AppResult<SyncerNetworkApproval> {
    let mut tx = pool.begin().await?;
    super::provider_network_service::administrator(&mut tx, actor).await?;
    let s = current(&mut tx, id).await?;
    sqlx::query("DELETE FROM syncer_network_approvals WHERE syncer_id=$1")
        .bind(&s.id)
        .execute(&mut *tx)
        .await?;
    let result = status(&mut tx, &s).await?;
    tx.commit().await?;
    Ok(result)
}
