use crate::diesel_pool::DieselPool;
use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;

use crate::error::{AppError, AppResult};
use crate::models::{
    ApplicationListResponse, ApplicationQuery, ApplicationResponse, CreateApplicationRequest,
    UpdateApplicationRequest,
};
use crate::services::AppService;

/// List applications
#[endpoint(
    tags("Applications"),
    parameters(
        ("owner" = Option<String>, Query, description = "Filter by owner"),
        ("organization" = Option<String>, Query, description = "Filter by organization"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size")
    ),
    responses(
        (status_code = 200, description = "List of applications", body = ApplicationListResponse),
        (status_code = 401, description = "Not authenticated")
    )
)]
pub async fn list_applications(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<ApplicationListResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool);

    let query = ApplicationQuery {
        owner: req.query("owner"),
        organization: req.query("organization"),
        page: req.query("page"),
        page_size: req.query("page_size"),
    };

    let response = app_service.list(query).await?;
    Ok(Json(response))
}

/// Create an application
#[endpoint(
    tags("Applications"),
    request_body(content = CreateApplicationRequest, description = "Application to create"),
    responses(
        (status_code = 200, description = "Application created", body = ApplicationResponse),
        (status_code = 400, description = "Invalid input"),
        (status_code = 409, description = "Application already exists")
    )
)]
pub async fn create_application(
    depot: &mut Depot,
    req: JsonBody<CreateApplicationRequest>,
) -> Result<Json<ApplicationResponse>, AppError> {
    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    if principal.is_application() || !principal.admin {
        return Err(AppError::Authorization(
            "A real administrator must create a trusted static application".into(),
        ));
    }
    if req.name.starts_with("dcr_") {
        return Err(AppError::Validation(
            "The dcr_ application namespace is reserved for dynamic registration".into(),
        ));
    }
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool);

    let response = app_service.create(req.into_inner()).await?;
    let pg_pool = depot
        .obtain::<sqlx::PgPool>()
        .map_err(|_| AppError::Internal("Database unavailable".into()))?;
    crate::services::key_credentials_service::mark_static_application(
        pg_pool,
        &response.id,
        &principal,
    )
    .await?;
    Ok(Json(response))
}

#[salvo::handler]
pub async fn trust_credentials(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<serde_json::Value>> {
    let principal = crate::hoops::authz::Principal::from_depot(depot)?;
    if principal.is_application() || !principal.admin {
        return Err(AppError::Authorization(
            "A real administrator must review application credentials".into(),
        ));
    }
    let body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("JSON body required".into()))?;
    let reference = body["application"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .ok_or_else(|| AppError::Validation("Application ID or owner/name required".into()))?;
    let pool = depot
        .obtain::<sqlx::PgPool>()
        .map_err(|_| AppError::Internal("Database unavailable".into()))?;
    let id: String=sqlx::query_scalar("SELECT id FROM applications WHERE NOT is_deleted AND ((strpos($1,'/')>0 AND owner||'/'||name=$1) OR (strpos($1,'/')=0 AND id=$1))")
        .bind(reference).fetch_optional(pool).await?.ok_or_else(||AppError::NotFound("Application not found".into()))?;
    crate::services::key_credentials_service::trust_application(pool, &id, &principal).await?;
    Ok(Json(serde_json::json!({"status":"ok"})))
}

/// Get an application by ID
#[endpoint(
    tags("Applications"),
    parameters(
        ("id" = String, Path, description = "Application ID")
    ),
    responses(
        (status_code = 200, description = "Application details", body = ApplicationResponse),
        (status_code = 404, description = "Application not found")
    )
)]
pub async fn get_application(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<Json<ApplicationResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool);

    let response = app_service.get_by_id(&id.into_inner()).await?;
    Ok(Json(response))
}

/// Update an application
#[endpoint(
    tags("Applications"),
    parameters(
        ("id" = String, Path, description = "Application ID")
    ),
    request_body(content = UpdateApplicationRequest, description = "Application fields to update"),
    responses(
        (status_code = 200, description = "Application updated", body = ApplicationResponse),
        (status_code = 404, description = "Application not found")
    )
)]
pub async fn update_application(
    depot: &mut Depot,
    id: PathParam<String>,
    req: JsonBody<UpdateApplicationRequest>,
) -> Result<Json<ApplicationResponse>, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool);

    let response = app_service
        .update(&id.into_inner(), req.into_inner())
        .await?;
    Ok(Json(response))
}

/// Delete an application
#[endpoint(
    tags("Applications"),
    parameters(
        ("id" = String, Path, description = "Application ID")
    ),
    responses(
        (status_code = 200, description = "Application deleted"),
        (status_code = 404, description = "Application not found")
    )
)]
pub async fn delete_application(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<&'static str, AppError> {
    let pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool);

    app_service.delete(&id.into_inner()).await?;
    Ok("Application deleted")
}
