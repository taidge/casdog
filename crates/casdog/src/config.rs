use std::sync::RwLock;

use config::{Config, ConfigError, File};
use once_cell::sync::Lazy;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub driver: String,
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: i64,
    pub issuer: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CasbinConfig {
    pub model_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub casbin: CasbinConfig,
    pub logging: LoggingConfig,
}

static CONFIG: Lazy<RwLock<Option<AppConfig>>> = Lazy::new(|| RwLock::new(None));

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(File::with_name("config/default").required(true))
            .add_source(File::with_name("config/local").required(false))
            .add_source(config::Environment::with_prefix("CASDOG").separator("__"))
            .build()?;

        let app_config: AppConfig = config.try_deserialize()?;

        let mut cfg = CONFIG.write().unwrap();
        *cfg = Some(app_config.clone());

        Ok(app_config)
    }

    pub fn get() -> AppConfig {
        CONFIG
            .read()
            .unwrap()
            .clone()
            .expect("Config not initialized. Call AppConfig::load() first.")
    }
}
