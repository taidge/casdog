use salvo::Depot;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSettings {
    pub db_max_open_conns: i64,
    pub db_max_idle_conns: i64,
    pub db_conn_max_lifetime: i64,
    pub record_retention_days: i64,
}
impl RuntimeSettings {
    pub fn parse(value: &Value) -> AppResult<Self> {
        let mut data = value
            .as_object()
            .cloned()
            .ok_or_else(|| AppError::Validation("Settings must be an object".into()))?;
        for field in ["owner", "name", "createdTime", "updatedTime", "runtime"] {
            data.remove(field);
        }
        let settings: Self = serde_json::from_value(Value::Object(data))
            .map_err(|_| AppError::Validation("Invalid or unknown settings fields".into()))?;
        if !(0..=4096).contains(&settings.db_max_open_conns)
            || !(0..=4096).contains(&settings.db_max_idle_conns)
            || !(0..=31536000).contains(&settings.db_conn_max_lifetime)
            || !(0..=365000).contains(&settings.record_retention_days)
            || (settings.db_max_open_conns > 0
                && settings.db_max_idle_conns > settings.db_max_open_conns)
        {
            return Err(AppError::Validation(
                "Invalid connection pool limits or record retention days".into(),
            ));
        }
        Ok(settings)
    }
    fn value(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("Settings serialization");
        value["owner"] = json!("admin");
        value["name"] = json!("setting-built-in");
        value
    }
}

pub struct RuntimeSettingsService;
impl RuntimeSettingsService {
    pub fn pool(depot: &Depot) -> AppResult<PgPool> {
        depot
            .obtain::<PgPool>()
            .cloned()
            .map_err(|_| AppError::Internal("Database unavailable".into()))
    }
    pub async fn read(pool: &PgPool) -> AppResult<Value> {
        let mut value:Value=sqlx::query_scalar("SELECT data||jsonb_build_object('createdTime',created_at,'updatedTime',updated_at) FROM operation_settings WHERE singleton")
            .fetch_one(pool).await?;
        RuntimeSettings::parse(&value)?;
        value["runtime"] = json!({"recordRetentionApplied":true,"poolSettingsApplied":false,"poolSettingsMessage":"No runtime pool manager is attached; settings persisted but pool application is unconfirmed"});
        Ok(value)
    }
    pub async fn update(pool: &PgPool, principal: &Principal, value: &Value) -> AppResult<Value> {
        if !principal.global_admin() || principal.is_application() {
            return Err(AppError::Authorization(
                "A real global administrator is required".into(),
            ));
        }
        let settings = RuntimeSettings::parse(value)?;
        let mut tx = pool.begin().await?;
        let current:Option<bool>=sqlx::query_scalar("SELECT is_admin FROM users WHERE id=$1 AND owner='built-in' AND name=$2 AND NOT is_deleted AND NOT is_forbidden FOR SHARE")
            .bind(&principal.id).bind(&principal.name).fetch_optional(&mut *tx).await?;
        if current != Some(true) {
            return Err(AppError::Authorization(
                "Current global administrator is unavailable".into(),
            ));
        }
        let changed = sqlx::query(
            "UPDATE operation_settings SET data=$1,updated_at=clock_timestamp() WHERE singleton",
        )
        .bind(settings.value())
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(AppError::NotFound("Site settings are unavailable".into()));
        }
        tx.commit().await?;
        Ok(
            json!({"status":"ok","data":true,"applied":false,"recordRetentionApplied":true,"poolSettingsApplied":false,"msg":"No runtime pool manager is attached; settings persisted but pool application is unconfirmed. Record retention applies at the next cleanup"}),
        )
    }
    /// Short shared transactions serialize policy edits with deletion. No
    /// in-process policy cache can retain an obsolete tenant/global cutoff.
    pub async fn cleanup_batch(pool: &PgPool, limit: i64) -> AppResult<u64> {
        if !(1..=1000).contains(&limit) {
            return Err(AppError::Validation(
                "Retention batch limit must be between 1 and 1000".into(),
            ));
        }
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='30s'")
            .execute(&mut *tx)
            .await?;
        let locked: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_xact_lock(hashtext('casdog.record-retention.v1')::bigint)",
        )
        .fetch_one(&mut *tx)
        .await?;
        if !locked {
            return Ok(0);
        }
        let data: Value =
            sqlx::query_scalar("SELECT data FROM operation_settings WHERE singleton FOR SHARE")
                .fetch_one(&mut *tx)
                .await?;
        let settings = RuntimeSettings::parse(&data)?;
        let policies: Vec<(String, i32)> =
            sqlx::query_as("SELECT name,record_retention_days FROM organizations FOR SHARE")
                .fetch_all(&mut *tx)
                .await?;
        let mut names = std::collections::HashSet::new();
        if policies.iter().any(|(name, _)| !names.insert(name)) {
            return Err(AppError::Validation(
                "Ambiguous organization names; review audit retention policies before cleanup"
                    .into(),
            ));
        }
        if settings.record_retention_days == 0 && policies.iter().all(|(_, days)| *days == 0) {
            return Ok(0);
        }
        let deleted=sqlx::query("WITH expired AS (SELECT r.id FROM records r LEFT JOIN organizations o ON o.name=CASE WHEN r.owner IN ('','anonymous') THEN 'built-in' ELSE r.owner END WHERE COALESCE(NULLIF(o.record_retention_days,0),$1)>0 AND r.created_at<clock_timestamp()-make_interval(days=>COALESCE(NULLIF(o.record_retention_days,0),$1)) ORDER BY r.created_at,r.id LIMIT $2 FOR UPDATE OF r SKIP LOCKED) DELETE FROM records r USING expired e WHERE r.id=e.id")
            .bind(settings.record_retention_days as i32).bind(limit).execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        Ok(deleted)
    }
    pub async fn run_once(pool: &PgPool) -> AppResult<u64> {
        let mut total = 0;
        for _ in 0..64 {
            let removed = Self::cleanup_batch(pool, 1000).await?;
            total += removed;
            if removed < 1000 {
                break;
            }
        }
        Ok(total)
    }
}
