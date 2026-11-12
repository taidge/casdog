mod config;
mod diesel_pool;
mod error;
mod handlers;
mod hoops;
mod models;
mod routes;
mod schema;
mod services;

use salvo::affix_state::AffixList;
use salvo::cors::Cors;
use salvo::http::Method;
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

    tracing::info!("SQLx database connection pool created");

    let diesel_pool = diesel_pool::create_diesel_pool(&config.database.url).await?;

    tracing::info!("Diesel database connection pool created");

    services::system_gap_service::reconcile_upgrades(
        &pool,
        &services::system_gap_service::SystemGapConfig::from_env(),
    )
    .await?;

    // Initialize database with built-in seed data (idempotent, skips if already done)
    InitService::init_db(&pool).await?;

    // Ensure uploads directory exists for local file storage
    std::fs::create_dir_all("./uploads").ok();

    let casbin_service = CasbinService::with_pool(pool.clone()).await?;
    tracing::info!("Casbin authorization service initialized");

    let syncer_pool = pool.clone();
    tokio::spawn(async move {
        SyncerExecutor::start_scheduler(syncer_pool, tokio::time::Duration::from_secs(60)).await;
    });

    let renewal_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(error) =
                services::subscription_renewal_service::SubscriptionRenewalService::run_once(
                    &renewal_pool,
                    100,
                )
                .await
            {
                tracing::error!(%error,"Subscription renewal worker failed");
            }
        }
    });
    let reconcile_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(error) =
                services::payment_reconcile_scheduler::PaymentReconcileScheduler::run_once(
                    &reconcile_pool,
                    20,
                )
                .await
            {
                tracing::error!(%error,"Payment reconciliation worker failed");
            }
        }
    });
    let retention_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            match services::runtime_settings_service::RuntimeSettingsService::run_once(
                &retention_pool,
            )
            .await
            {
                Ok(deleted) if deleted > 0 => {
                    tracing::info!(deleted, "Expired audit records removed")
                }
                Ok(_) => {}
                Err(error) => tracing::error!(%error,"Audit record retention worker failed"),
            }
        }
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
        .hoop(hoops::record_filter::RequestLogger)
        .hoop(cors)
        .hoop(
            AffixList::new()
                .inject(pool)
                .inject(diesel_pool)
                .inject(casbin_service),
        )
        .hoop(hoops::RecordFilter);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Server listening on http://{}", addr);
    tracing::info!("Swagger UI available at http://{}/swagger-ui/", addr);

    let acceptor = TcpListener::new(addr).bind().await;
    Server::new(acceptor).serve(service).await;

    Ok(())
}
