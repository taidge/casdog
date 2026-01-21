use salvo::oapi::{endpoint, ToSchema};
use salvo::prelude::*;
use serde::Serialize;

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Health check endpoint
#[endpoint(
    tags("Health"),
    responses(
        (status_code = 200, description = "Service is healthy", body = HealthResponse)
    )
)]
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
