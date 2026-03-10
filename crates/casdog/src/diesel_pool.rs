use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;

/// Type alias for the Diesel async connection pool.
pub type DieselPool = Pool<AsyncPgConnection>;

/// Create a Diesel async connection pool from a database URL.
pub async fn create_diesel_pool(
    database_url: &str,
) -> Result<DieselPool, Box<dyn std::error::Error>> {
    let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
    let pool = Pool::builder().build(config).await?;
    Ok(pool)
}
