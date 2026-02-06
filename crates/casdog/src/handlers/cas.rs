use crate::error::AppError;
use crate::services::cas_service::CasService;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

/// CAS service validate endpoint
#[endpoint(
    tags("CAS"),
    summary = "CAS service validate"
)]
pub async fn service_validate(
    depot: &mut Depot,
    ticket: QueryParam<String, true>,
    service: QueryParam<String, true>,
) -> Result<String, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let result = CasService::validate_ticket(&pool, ticket.as_str(), service.as_str()).await?;

    if result.valid {
        let user = result.user.unwrap_or_default();
        let attrs: String = result.attributes.iter().map(|(k, v)| {
            format!("<cas:{k}>{v}</cas:{k}>")
        }).collect::<Vec<_>>().join("\n            ");

        Ok(format!(r#"<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>{user}</cas:user>
    <cas:attributes>
      {attrs}
    </cas:attributes>
  </cas:authenticationSuccess>
</cas:serviceResponse>"#))
    } else {
        Ok(r#"<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationFailure code="INVALID_TICKET">Ticket validation failed</cas:authenticationFailure>
</cas:serviceResponse>"#.to_string())
    }
}

/// CAS simple validate endpoint
#[endpoint(
    tags("CAS"),
    summary = "CAS validate"
)]
pub async fn validate(
    depot: &mut Depot,
    ticket: QueryParam<String, true>,
    service: QueryParam<String, true>,
) -> Result<String, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let result = CasService::validate_ticket(&pool, ticket.as_str(), service.as_str()).await;

    match result {
        Ok(r) if r.valid => Ok(format!("yes\n{}", r.user.unwrap_or_default())),
        _ => Ok("no\n".to_string()),
    }
}
