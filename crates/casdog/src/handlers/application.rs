use salvo::oapi::endpoint;
use salvo::oapi::extract::*;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::error::AppError;
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
        .obtain::<Pool<Postgres>>()
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
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool);

    let response = app_service.create(req.into_inner()).await?;
    Ok(Json(response))
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
        .obtain::<Pool<Postgres>>()
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
        .obtain::<Pool<Postgres>>()
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
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let app_service = AppService::new(pool);

    app_service.delete(&id.into_inner()).await?;
    Ok("Application deleted")
}
