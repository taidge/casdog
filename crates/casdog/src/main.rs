use casdog::{config, hoops, routes, runtime_pool, services};

use salvo::cors::Cors;
use salvo::http::Method;
use salvo::prelude::*;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::AppConfig;
use crate::runtime_pool::{RuntimePoolManager, RuntimePools};
use crate::services::InitService;
use crate::services::syncer_executor::SyncerExecutor;

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

    tracing::info!("SQLx database connection pool created");

    services::system_gap_service::reconcile_upgrades(
        &pool,
        &services::system_gap_service::SystemGapConfig::from_env(),
    )
    .await?;

    // Initialize database with built-in seed data (idempotent, skips if already done)
    InitService::init_db(&pool).await?;

    // Ensure uploads directory exists for local file storage
    std::fs::create_dir_all("./uploads").ok();

    let manager = RuntimePoolManager::new(&config.database.url, &pool).await?;
    manager.refresh().await?;
    drop(pool);
    let refresh_manager = manager.clone();
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            timer.tick().await;
            if let Err(error) = refresh_manager.refresh().await {
                tracing::error!(%error,"Runtime pool settings refresh failed; previous generation remains active");
            }
        }
    });
    for worker in 0..4 {
        let worker_manager = manager.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(60));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                timer.tick().await;
                let generation = worker_manager.current();
                let result=match worker {
                    0=>SyncerExecutor::execute_all_due(&generation.sqlx).await.map(|_|()),
                    1=>services::subscription_renewal_service::SubscriptionRenewalService::run_once(&generation.sqlx,100).await.map(|_|()),
                    2=>services::payment_reconcile_scheduler::PaymentReconcileScheduler::run_once(&generation.sqlx,20).await.map(|_|()),
                    _=>services::runtime_settings_service::RuntimeSettingsService::run_once(&generation.sqlx).await.map(|_|()),
                };
                if let Err(error) = result {
                    tracing::error!(%error,worker,"Database worker failed");
                }
            }
        });
    }

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
        .hoop(hoops::record_filter::RequestLogger)
        .hoop(cors)
        .hoop(RuntimePools(manager))
        .hoop(hoops::RecordFilter);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Server listening on http://{}", addr);
    tracing::info!("Swagger UI available at http://{}/swagger-ui/", addr);

    let acceptor = TcpListener::new(addr).bind().await;
    Server::new(acceptor).serve(service).await;

    Ok(())
}
