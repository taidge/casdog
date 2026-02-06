use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::config::AppConfig;
use crate::error::AppError;
use crate::services::saml_service::SamlService;

/// SAML IdP Metadata endpoint
#[endpoint(tags("SAML"), summary = "Get SAML IdP metadata")]
pub async fn saml_metadata(depot: &mut Depot) -> Result<String, AppError> {
    let config = AppConfig::get();
    let base_url = format!("http://{}:{}", config.server.host, config.server.port);

    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();

    // Get first JWT certificate for signing
    let cert: Option<(String,)> = sqlx::query_as(
        "SELECT certificate FROM certificates WHERE scope = 'JWT' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(&pool)
    .await?;

    let cert_pem = cert.map(|(c,)| c).unwrap_or_default();

    let metadata = SamlService::generate_idp_metadata(
        &format!("{}/api/saml/metadata", base_url),
        &format!("{}/api/saml/sso", base_url),
        Some(&format!("{}/api/saml/slo", base_url)),
        &cert_pem,
    )?;

    Ok(metadata)
}

/// Get SAML login URL
#[endpoint(tags("SAML"), summary = "Get SAML login")]
pub async fn get_saml_login() -> Result<&'static str, AppError> {
    // Placeholder - returns SSO endpoint info
    Ok("SAML SSO login endpoint")
}

/// SAML Assertion Consumer Service
#[endpoint(tags("SAML"), summary = "SAML ACS endpoint")]
pub async fn saml_acs() -> Result<&'static str, AppError> {
    // Placeholder for processing SAML responses from external IdPs
    Ok("SAML ACS processed")
}
