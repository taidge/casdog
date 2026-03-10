mod config;
mod error;
mod handlers;
mod hoops;
mod models;
mod routes;
mod services;

use salvo::affix_state::AffixList;
use salvo::cors::Cors;
use salvo::http::Method;
use salvo::logging::Logger;
use salvo::prelude::*;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::AppConfig;
use crate::services::syncer_executor::SyncerExecutor;
use crate::services::{CasbinService, InitService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load()?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "casdog={},salvo={}",
                    config.logging.level, config.logging.level
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Casdog IAM/SSO server...");

    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;

    tracing::info!("Database connection pool created");

    // Initialize database with built-in seed data (idempotent, skips if already done)
    InitService::init_db(&pool).await?;

    // Ensure uploads directory exists for local file storage
    std::fs::create_dir_all("./uploads").ok();

    let casbin_service = CasbinService::new().await?;
    tracing::info!("Casbin authorization service initialized");

    let syncer_pool = pool.clone();
    tokio::spawn(async move {
        SyncerExecutor::start_scheduler(syncer_pool, tokio::time::Duration::from_secs(60)).await;
    });

    let cors = Cors::new()
        .allow_origin("*")
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(vec!["Content-Type", "Authorization"])
        .into_handler();

    let router = routes::create_router();

    let service = Service::new(router)
        .hoop(Logger::new())
        .hoop(cors)
        .hoop(AffixList::new().inject(pool).inject(casbin_service))
        .hoop(hoops::RecordFilter);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Server listening on http://{}", addr);
    tracing::info!("Swagger UI available at http://{}/swagger-ui/", addr);

    let acceptor = TcpListener::new(addr).bind().await;
    Server::new(acceptor).serve(service).await;

    Ok(())
}
