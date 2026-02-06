use crate::error::AppError;
use crate::models::{
    CreateOrganizationRequest, OrganizationListResponse, OrganizationQuery,
    OrganizationResponse, UpdateOrganizationRequest,
};
use crate::services::OrgService;
use salvo::oapi::extract::*;
use salvo::oapi::endpoint;
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

/// List organizations
#[endpoint(
    tags("Organizations"),
    parameters(
        ("owner" = Option<String>, Query, description = "Filter by owner"),
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size")
    ),
    responses(
        (status_code = 200, description = "List of organizations", body = OrganizationListResponse),
        (status_code = 401, description = "Not authenticated")
    )
)]
pub async fn list_organizations(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<Json<OrganizationListResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();
    let org_service = OrgService::new(pool);

    let query = OrganizationQuery {
        owner: req.query("owner"),
        page: req.query("page"),
        page_size: req.query("page_size"),
    };

    let response = org_service.list(query).await?;
    Ok(Json(response))
}

/// Create an organization
#[endpoint(
    tags("Organizations"),
    request_body(content = CreateOrganizationRequest, description = "Organization to create"),
    responses(
        (status_code = 200, description = "Organization created", body = OrganizationResponse),
        (status_code = 400, description = "Invalid input"),
        (status_code = 409, description = "Organization already exists")
    )
)]
pub async fn create_organization(
    depot: &mut Depot,
    req: JsonBody<CreateOrganizationRequest>,
) -> Result<Json<OrganizationResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();
    let org_service = OrgService::new(pool);

    let response = org_service.create(req.into_inner()).await?;
    Ok(Json(response))
}

/// Get an organization by ID
#[endpoint(
    tags("Organizations"),
    parameters(
        ("id" = String, Path, description = "Organization ID")
    ),
    responses(
        (status_code = 200, description = "Organization details", body = OrganizationResponse),
        (status_code = 404, description = "Organization not found")
    )
)]
pub async fn get_organization(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<Json<OrganizationResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();
    let org_service = OrgService::new(pool);

    let response = org_service.get_by_id(&id.into_inner()).await?;
    Ok(Json(response))
}

/// Update an organization
#[endpoint(
    tags("Organizations"),
    parameters(
        ("id" = String, Path, description = "Organization ID")
    ),
    request_body(content = UpdateOrganizationRequest, description = "Organization fields to update"),
    responses(
        (status_code = 200, description = "Organization updated", body = OrganizationResponse),
        (status_code = 404, description = "Organization not found")
    )
)]
pub async fn update_organization(
    depot: &mut Depot,
    id: PathParam<String>,
    req: JsonBody<UpdateOrganizationRequest>,
) -> Result<Json<OrganizationResponse>, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();
    let org_service = OrgService::new(pool);

    let response = org_service.update(&id.into_inner(), req.into_inner()).await?;
    Ok(Json(response))
}

/// Delete an organization
#[endpoint(
    tags("Organizations"),
    parameters(
        ("id" = String, Path, description = "Organization ID")
    ),
    responses(
        (status_code = 200, description = "Organization deleted"),
        (status_code = 404, description = "Organization not found")
    )
)]
pub async fn delete_organization(
    depot: &mut Depot,
    id: PathParam<String>,
) -> Result<&'static str, AppError> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();
    let org_service = OrgService::new(pool);

    org_service.delete(&id.into_inner()).await?;
    Ok("Organization deleted")
}
