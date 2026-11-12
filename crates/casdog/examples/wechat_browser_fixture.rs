//! Explicit development-only HTTP harness. No production endpoint override.
use casdog::{
    config::AppConfig,
    diesel_pool::create_diesel_pool,
    services::{InitService, PasswordService, wechat_flow::WeChatTestTransport},
};
use salvo::prelude::*;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureConfig {
    database: String,
    origin: String,
    wechat_origin: String,
    jwt_secret: String,
    admin_id: String,
    admin_name: String,
    admin_password: String,
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || args[1] != "--config" {
        return Err("expected --config FILE".into());
    }
    let bytes = std::fs::read(&args[2])?;
    if bytes.len() > 32768 {
        return Err("fixture configuration too large".into());
    }
    let fixture: FixtureConfig = serde_json::from_slice(&bytes)?;
    let origin = reqwest::Url::parse(&fixture.origin)?;
    if origin.scheme() != "http"
        || origin.host_str() != Some("127.0.0.1")
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || fixture.jwt_secret.len() < 32
    {
        return Err("invalid fixture origin".into());
    }
    let port = origin.port().ok_or("explicit fixture port required")?;
    // Set normal application configuration once, before creating Tokio workers
    // or loading AppConfig. Endpoints are never supplied through environment.
    unsafe {
        std::env::set_var("CASDOG__DATABASE__URL", &fixture.database);
        std::env::set_var("CASDOG__SERVER__HOST", "127.0.0.1");
        std::env::set_var("CASDOG__SERVER__PORT", port.to_string());
        std::env::set_var(
            "CASDOG__SERVER__PUBLIC_URL",
            fixture.origin.trim_end_matches('/'),
        );
        std::env::set_var("CASDOG__JWT__SECRET", &fixture.jwt_secret);
    }
    AppConfig::load()?;
    let transport = Arc::new(
        WeChatTestTransport::new(&fixture.wechat_origin)?
            .with_authorization_origin(&fixture.wechat_origin)?,
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .connect(&fixture.database)
        .await?;
    InitService::init_db(&pool).await?;
    let hash = PasswordService::hash_password(&fixture.admin_password, "argon2", None)?;
    sqlx::query("INSERT INTO users(id,owner,name,display_name,password_hash,password_type,is_admin) VALUES($1,'built-in',$2,'WeChat browser fixture administrator',$3,'argon2',true)").bind(&fixture.admin_id).bind(&fixture.admin_name).bind(hash).execute(&pool).await?;
    let diesel = create_diesel_pool(&fixture.database).await?;
    let service = Service::new(casdog::routes::create_router()).hoop(
        salvo::affix_state::AffixList::new()
            .inject(pool)
            .inject(diesel)
            .inject(transport),
    );
    let acceptor = TcpListener::new(format!("127.0.0.1:{port}")).bind().await;
    println!("WeChat development browser fixture ready");
    Server::new(acceptor).serve(service).await;
    Ok(())
}

fn main() {
    // current_thread also makes the one-time normal configuration initialization
    // happen without concurrent process-environment readers.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fixture runtime");
    if runtime.block_on(run()).is_err() {
        eprintln!("WeChat development browser fixture failed");
        std::process::exit(1);
    }
}
