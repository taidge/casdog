use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    services::runtime_settings_service::RuntimeSettingsService,
};
use salvo::prelude::*;
use serde_json::{Value, json};

#[handler]
pub async fn get_setting(depot: &mut Depot) -> AppResult<Json<Value>> {
    let principal = Principal::from_depot(depot)?;
    if !principal.global_admin() || principal.is_application() {
        return Err(AppError::Authorization(
            "A real global administrator is required".into(),
        ));
    }
    let pool = RuntimeSettingsService::pool(depot)?;
    let current:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND owner='built-in' AND name=$2 AND is_admin AND NOT is_deleted AND NOT is_forbidden)")
        .bind(&principal.id).bind(&principal.name).fetch_one(&pool).await?;
    if !current {
        return Err(AppError::Authorization(
            "Current global administrator is unavailable".into(),
        ));
    }
    let mut data = RuntimeSettingsService::read(&pool).await?;
    if let Ok(manager) = depot.obtain::<crate::runtime_pool::RuntimePoolManager>() {
        data["runtime"] = manager
            .status(&crate::services::runtime_settings_service::RuntimeSettings::parse(&data)?);
    }
    Ok(Json(json!({"status":"ok","data":data})))
}
#[handler]
pub async fn update_setting(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let principal = Principal::from_depot(depot)?;
    let value: Value = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("Invalid settings JSON".into()))?;
    let mut result =
        RuntimeSettingsService::update(&RuntimeSettingsService::pool(depot)?, &principal, &value)
            .await?;
    if let Ok(manager) = depot.obtain::<crate::runtime_pool::RuntimePoolManager>() {
        let _ = manager.refresh().await; // persisted-but-failed remains truthful
        let status = manager
            .status(&crate::services::runtime_settings_service::RuntimeSettings::parse(&value)?);
        result["applied"] = status["poolSettingsApplied"].clone();
        result["poolSettingsApplied"] = status["poolSettingsApplied"].clone();
        result["msg"] = status["poolSettingsMessage"].clone();
        result["runtime"] = status;
    }
    Ok(Json(result))
}
