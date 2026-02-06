use crate::error::{AppError, AppResult};
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use sqlx::{FromRow, Pool, Postgres};

/// Lightweight representation of an organization with only id, name, and display_name
#[derive(Debug, serde::Serialize, FromRow, salvo::oapi::ToSchema)]
pub struct OrganizationNameEntry {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Get a lightweight list of organization names only
#[endpoint(tags("Organizations"), summary = "Get organization names")]
pub async fn get_organization_names(
    depot: &mut Depot,
    owner: QueryParam<String, false>,
) -> AppResult<Json<serde_json::Value>> {
    let pool = depot.obtain::<Pool<Postgres>>().map_err(|_| {
        AppError::Internal("Database pool not available".to_string())
    })?.clone();

    let owner_val = owner.into_inner();

    let orgs = if let Some(owner) = &owner_val {
        sqlx::query_as::<_, OrganizationNameEntry>(
            "SELECT id, name, display_name FROM organizations WHERE owner = $1 AND is_deleted = FALSE ORDER BY name ASC",
        )
        .bind(owner)
        .fetch_all(&pool)
        .await?
    } else {
        sqlx::query_as::<_, OrganizationNameEntry>(
            "SELECT id, name, display_name FROM organizations WHERE is_deleted = FALSE ORDER BY name ASC",
        )
        .fetch_all(&pool)
        .await?
    };

    Ok(Json(serde_json::json!({
        "status": "ok",
        "data": orgs
    })))
}
