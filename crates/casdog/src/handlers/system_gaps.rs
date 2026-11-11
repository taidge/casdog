use salvo::prelude::*;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    services::system_gap_service::{self as operations, SystemGapConfig},
};

pub fn routes() -> Router {
    Router::new()
        .push(Router::with_path("get-upgrade-info").get(upgrade_info))
        .push(Router::with_path("upgrade-system").post(upgrade_system))
        .push(Router::with_path("scan").get(scan))
        .push(Router::with_path("sync-intranet-servers").post(sync_intranet_servers))
        .push(Router::with_path("verify-identification").post(verify_identification))
}

fn pool(depot: &Depot) -> AppResult<PgPool> {
    depot.obtain::<PgPool>().cloned().map_err(|_| AppError::Internal("Database unavailable".into()))
}
fn config(depot: &Depot) -> SystemGapConfig {
    depot.obtain::<SystemGapConfig>().cloned().unwrap_or_else(|_| SystemGapConfig::from_env())
}
fn required(req: &Request, name: &str) -> AppResult<String> {
    req.query::<String>(name)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::Validation(format!("{name} required")))
}

#[handler]
pub async fn upgrade_info(depot: &mut Depot) -> AppResult<Json<Value>> {
    if !Principal::from_depot(depot)?.global_admin() {
        return Err(operations::denied());
    }
    Ok(Json(json!({"status":"ok","data":operations::upgrade_info(&pool(depot)?,&config(depot)).await?})))
}

#[handler]
pub async fn upgrade_system(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let principal = Principal::from_depot(depot)?;
    if !principal.global_admin() {
        return Err(operations::denied());
    }
    let body: Value = req.parse_json().await.map_err(|_| AppError::Validation("JSON version required".into()))?;
    let version = body["version"].as_str().ok_or_else(|| AppError::Validation("version required".into()))?;
    let status = operations::upgrade(&pool(depot)?, &config(depot), &principal, version).await?;
    Ok(Json(json!({"status":"ok","data":status})))
}

#[handler]
pub async fn scan(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let principal = Principal::from_depot(depot)?;
    let pool = pool(depot)?;
    let provider = operations::provider(&pool, &principal, &required(req, "owner")?, &required(req, "name")?).await?;
    let target = req.query::<String>("target").unwrap_or_default();
    let result = operations::security_scan(&pool, &principal, &provider, &target).await?;
    Ok(Json(json!({"status":"ok","data":result})))
}

#[handler]
pub async fn sync_intranet_servers(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let principal = Principal::from_depot(depot)?;
    if !principal.global_admin() {
        return Err(operations::denied());
    }
    let provider =
        operations::provider(&pool(depot)?, &principal, &required(req, "owner")?, &required(req, "name")?).await?;
    let result = operations::sync_intranet_servers(&pool(depot)?, &principal, &provider).await?;
    Ok(Json(json!({"status":"ok","data":result})))
}

#[handler]
pub async fn verify_identification(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let principal = Principal::from_depot(depot)?;
    let owner =
        req.query::<String>("owner").filter(|value| !value.is_empty()).unwrap_or_else(|| principal.owner.clone());
    let name = req.query::<String>("name").filter(|value| !value.is_empty()).unwrap_or_else(|| principal.name.clone());
    let provider = req.query::<String>("provider").filter(|value| !value.is_empty());
    let result =
        operations::verify_identification(&pool(depot)?, &principal, &owner, &name, provider.as_deref()).await?;
    Ok(Json(json!({"status":"ok","data":result})))
}
