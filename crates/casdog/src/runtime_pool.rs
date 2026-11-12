//! A request captures one immutable pool generation. Rotation never closes the
//! old generation; outstanding transactions retain it until their normal end.
use crate::{
    diesel_pool::DieselPool,
    error::{AppError, AppResult},
    services::{CasbinService, runtime_settings_service::RuntimeSettings},
};
use salvo::prelude::*;
use serde_json::{Value, json};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    collections::HashSet,
    str::FromStr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub struct PoolLimits {
    pub max_open: u32,
    pub max_idle: u32,
    pub lifetime: Option<Duration>,
}
impl PoolLimits {
    pub fn from_settings(s: &RuntimeSettings, server_capacity: u32) -> Self {
        let max_open = if s.db_max_open_conns == 0 {
            server_capacity
        } else {
            s.db_max_open_conns as u32
        };
        Self {
            max_open,
            max_idle: (if s.db_max_idle_conns == 0 {
                2
            } else {
                s.db_max_idle_conns as u32
            })
            .min(max_open),
            lifetime: if s.db_conn_max_lifetime == 0 {
                None
            } else {
                Some(Duration::from_secs(s.db_conn_max_lifetime as u64))
            },
        }
    }
}
pub struct PoolGeneration {
    pub sqlx: PgPool,
    pub diesel: DieselPool,
    pub casbin: CasbinService,
    pub limits: PoolLimits,
    pub id: String,
}
#[derive(Clone)]
pub struct RuntimePoolManager(Arc<Manager>);
struct Manager {
    url: String,
    server_capacity: AtomicU32,
    current: RwLock<Arc<PoolGeneration>>,
    refresh: Mutex<()>,
    last_error: RwLock<Option<String>>,
}
impl RuntimePoolManager {
    pub async fn new(url: &str, bootstrap: &PgPool) -> AppResult<Self> {
        let data: Value = sqlx::query_scalar("SELECT data FROM operation_settings WHERE singleton")
            .fetch_one(bootstrap)
            .await?;
        let server_capacity = Self::read_server_capacity(bootstrap).await?;
        let limits = PoolLimits::from_settings(&RuntimeSettings::parse(&data)?, server_capacity);
        let generation = Self::build(url, limits).await?;
        Ok(Self(Arc::new(Manager {
            url: url.into(),
            server_capacity: AtomicU32::new(server_capacity),
            current: RwLock::new(Arc::new(generation)),
            refresh: Mutex::new(()),
            last_error: RwLock::new(None),
        })))
    }
    async fn read_server_capacity(pool: &PgPool) -> AppResult<u32> {
        let capacity: i32 = sqlx::query_scalar("SELECT current_setting('max_connections')::int")
            .fetch_one(pool)
            .await?;
        u32::try_from(capacity)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                AppError::Internal("PostgreSQL returned an invalid max_connections capacity".into())
            })
    }
    pub fn current(&self) -> Arc<PoolGeneration> {
        self.0.current.read().unwrap().clone()
    }
    async fn build(url: &str, limits: PoolLimits) -> AppResult<PoolGeneration> {
        let id = uuid::Uuid::new_v4().to_string();
        let tag = format!("casdog-pool-{id}");
        // The set reserves idle slots before SQLx returns the connection to its
        // queue, preventing concurrent release callbacks exceeding the cap.
        // Backend IDs survive Rust moves. Dead idle IDs are pruned on connect.
        let idle = Arc::new(Mutex::new(HashSet::<i32>::new()));
        let connect_idle = idle.clone();
        let acquire_idle = idle.clone();
        let release_idle = idle.clone();
        let connect_tag = tag.clone();
        let cap = limits.max_idle as usize;
        let lifetime = limits.lifetime;
        let sqlx = PgPoolOptions::new()
            .max_connections(limits.max_open)
            .min_connections(0)
            .max_lifetime(limits.lifetime)
            .idle_timeout(None)
            .acquire_timeout(Duration::from_secs(30))
            .after_connect(move |c, _| {
                let idle = connect_idle.clone();
                let tag = connect_tag.clone();
                Box::pin(async move {
                    let mut ids = idle.lock().await;
                    let live: Vec<i32> = sqlx::query_scalar(
                        "SELECT pid FROM pg_stat_activity WHERE application_name=$1",
                    )
                    .bind(tag)
                    .fetch_all(c)
                    .await?;
                    ids.retain(|p| live.contains(p));
                    Ok(())
                })
            })
            .before_acquire(move |c, meta| {
                let idle = acquire_idle.clone();
                Box::pin(async move {
                    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(c)
                        .await?;
                    idle.lock().await.remove(&pid);
                    // SQLx's sweeper and on-release age check do not guarantee
                    // an expired idle connection is rejected on checkout.
                    Ok(!lifetime.is_some_and(|max| meta.age >= max))
                })
            })
            .after_release(move |c, _| {
                let idle = release_idle.clone();
                Box::pin(async move {
                    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(c)
                        .await?;
                    let mut ids = idle.lock().await;
                    if ids.len() >= cap {
                        return Ok(false);
                    }
                    ids.insert(pid);
                    Ok(true)
                })
            })
            .connect_with(PgConnectOptions::from_str(url)?.application_name(&tag))
            .await?;
        let diesel = DieselPool::configured(url, limits.max_open, limits.max_idle, limits.lifetime);
        drop(diesel.get().await?);
        let casbin = CasbinService::with_pool(sqlx.clone()).await?;
        Ok(PoolGeneration {
            sqlx,
            diesel,
            casbin,
            limits,
            id,
        })
    }
    pub async fn refresh(&self) -> AppResult<()> {
        let _serial = self.0.refresh.lock().await;
        let result = async {
            for _ in 0..8 {
                let current = self.current();
                let data: Value =
                    sqlx::query_scalar("SELECT data FROM operation_settings WHERE singleton")
                        .fetch_one(&current.sqlx)
                        .await?;
                let capacity = Self::read_server_capacity(&current.sqlx).await?;
                self.0.server_capacity.store(capacity, Ordering::Relaxed);
                let desired = PoolLimits::from_settings(&RuntimeSettings::parse(&data)?, capacity);
                if desired == current.limits {
                    return Ok(());
                }
                let replacement = Arc::new(Self::build(&self.0.url, desired.clone()).await?);
                // Keep the saved version locked until publication. A newer
                // settings write cannot commit between recheck and publish.
                let mut publication = replacement.sqlx.begin().await?;
                let latest: Value = sqlx::query_scalar(
                    "SELECT data FROM operation_settings WHERE singleton FOR SHARE",
                )
                .fetch_one(&mut *publication)
                .await?;
                let latest_capacity: i32 =
                    sqlx::query_scalar("SELECT current_setting('max_connections')::int")
                        .fetch_one(&mut *publication)
                        .await?;
                if latest_capacity != capacity as i32
                    || PoolLimits::from_settings(&RuntimeSettings::parse(&latest)?, capacity)
                        != desired
                {
                    continue;
                }
                *self.0.current.write().unwrap() = replacement.clone();
                if let Err(error) = publication.commit().await {
                    *self.0.current.write().unwrap() = current;
                    return Err(error.into());
                }
                return Ok(());
            }
            Err(AppError::Conflict(
                "Pool settings changed repeatedly; the previous generation remains active".into(),
            ))
        }
        .await;
        *self.0.last_error.write().unwrap() = result.as_ref().err().map(ToString::to_string);
        result
    }
    pub fn status(&self, settings: &RuntimeSettings) -> Value {
        let c = self.current();
        let server_capacity = self.0.server_capacity.load(Ordering::Relaxed);
        let applied = c.limits == PoolLimits::from_settings(settings, server_capacity);
        json!({"recordRetentionApplied":true,"poolSettingsApplied":applied,"generation":c.id,"effectiveMaxOpen":c.limits.max_open,"effectiveMaxIdle":c.limits.max_idle,"effectiveLifetimeSeconds":c.limits.lifetime.map(|d|d.as_secs()).unwrap_or(0),"serverMaxConnections":server_capacity,"zeroMaxOpenPolicy":"0 uses the connected PostgreSQL server max_connections capacity as the client ceiling; PostgreSQL role/reserved/global limits still apply","poolSettingsMessage":if applied{"Applied to new requests; existing requests retain their generation"}else{"Saved settings differ from the active generation"},"lastError":self.0.last_error.read().unwrap().clone()})
    }
}
#[derive(Clone)]
pub struct RuntimePools(pub RuntimePoolManager);
#[handler]
impl RuntimePools {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let generation = self.0.current();
        depot.inject(generation.sqlx.clone());
        depot.inject(generation.diesel.clone());
        depot.inject(generation.casbin.clone());
        depot.inject(self.0.clone());
        depot.inject(generation);
        ctrl.call_next(req, depot, res).await;
    }
}
