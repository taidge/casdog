//! Main-database Diesel pool. Idle is a ceiling, never a minimum. A checked-out
//! connection owns its permit and generation until it is returned.
use crate::error::{AppError, AppResult};
use diesel_async::pooled_connection::PoolableConnection;
use diesel_async::{AsyncConnection, AsyncPgConnection, SimpleAsyncConnection};
use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct DieselPool(Arc<Inner>);
struct Inner {
    url: String,
    permits: Arc<Semaphore>,
    idle: Mutex<Vec<(AsyncPgConnection, Instant)>>,
    max_idle: usize,
    lifetime: Option<Duration>,
}
pub struct DieselConnection {
    connection: Option<AsyncPgConnection>,
    born: Instant,
    pool: Arc<Inner>,
    _permit: OwnedSemaphorePermit,
}
impl Deref for DieselConnection {
    type Target = AsyncPgConnection;
    fn deref(&self) -> &Self::Target {
        self.connection.as_ref().unwrap()
    }
}
impl DerefMut for DieselConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection.as_mut().unwrap()
    }
}
impl Drop for DieselConnection {
    fn drop(&mut self) {
        if std::thread::panicking()
            || self.connection.as_mut().is_some_and(|c| c.is_broken())
            || self.pool.lifetime.is_some_and(|d| self.born.elapsed() >= d)
        {
            return;
        }
        let mut idle = self.pool.idle.lock().unwrap();
        if idle.len() < self.pool.max_idle {
            if let Some(c) = self.connection.take() {
                idle.push((c, self.born));
            }
        }
    }
}
impl DieselPool {
    pub fn configured(url: &str, max: u32, idle: u32, lifetime: Option<Duration>) -> Self {
        let pool = Self(Arc::new(Inner {
            url: url.into(),
            permits: Arc::new(Semaphore::new(max as usize)),
            idle: Mutex::new(Vec::new()),
            max_idle: idle.min(max) as usize,
            lifetime,
        }));
        if lifetime.is_some() {
            let weak = Arc::downgrade(&pool.0);
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let mut timer = tokio::time::interval(Duration::from_secs(1));
                    loop {
                        timer.tick().await;
                        let Some(inner) = weak.upgrade() else {
                            break;
                        };
                        inner.idle.lock().unwrap().retain(|(_, born)| {
                            !inner.lifetime.is_some_and(|d| born.elapsed() >= d)
                        });
                    }
                });
            }
        }
        pool
    }
    pub fn idle_count(&self) -> usize {
        self.0.idle.lock().unwrap().len()
    }
    pub async fn get(&self) -> AppResult<DieselConnection> {
        let permit = tokio::time::timeout(
            Duration::from_secs(30),
            self.0.permits.clone().acquire_owned(),
        )
        .await
        .map_err(|_| AppError::Internal("Diesel connection acquisition timed out".into()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
        loop {
            let cached = self.0.idle.lock().unwrap().pop();
            let (mut connection, born) = if let Some((connection, born)) = cached {
                if self.0.lifetime.is_some_and(|d| born.elapsed() >= d) {
                    continue;
                }
                (connection, born)
            } else {
                (
                    tokio::time::timeout(
                        Duration::from_secs(30),
                        AsyncPgConnection::establish(&self.0.url),
                    )
                    .await
                    .map_err(|_| {
                        AppError::Internal("Diesel connection establishment timed out".into())
                    })?
                    .map_err(|e| AppError::Internal(format!("Diesel connection failed: {e}")))?,
                    Instant::now(),
                )
            };
            if tokio::time::timeout(
                Duration::from_secs(30),
                connection.batch_execute("SELECT 1"),
            )
            .await
            .map_err(|_| AppError::Internal("Diesel connection health check timed out".into()))?
            .is_err()
            {
                continue;
            }
            return Ok(DieselConnection {
                connection: Some(connection),
                born,
                pool: self.0.clone(),
                _permit: permit,
            });
        }
    }
}
pub async fn create_diesel_pool(
    database_url: &str,
) -> Result<DieselPool, Box<dyn std::error::Error>> {
    let pool = DieselPool::configured(database_url, 10, 2, None);
    drop(pool.get().await?);
    Ok(pool)
}
