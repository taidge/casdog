use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    services::protocol_gap_service as service,
};
use salvo::prelude::*;
use serde_json::{Value, json};
use sqlx::PgPool;

fn pool(depot: &Depot) -> AppResult<PgPool> {
    depot
        .obtain::<PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database unavailable".into()))
}
async fn fields(req: &mut Request) -> AppResult<Value> {
    let mut values = if req
        .header::<String>("content-type")
        .is_some_and(|h| h.starts_with("application/json"))
    {
        let bytes = req
            .payload()
            .await
            .map_err(|_| AppError::Validation("Cannot read body".into()))?;
        if bytes.len() > 8192 {
            return Err(AppError::Validation("Request body exceeds 8 KiB".into()));
        }
        if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice::<Value>(bytes)
                .map_err(|_| AppError::Validation("JSON body required".into()))?
        }
    } else {
        let values = req
            .parse_form::<std::collections::HashMap<String, String>>()
            .await
            .unwrap_or_default();
        serde_json::to_value(values).map_err(|e| AppError::Internal(e.to_string()))?
    };
    if !values.is_object() {
        return Err(AppError::Validation("Object body required".into()));
    }
    for key in [
        "userCode",
        "user_code",
        "cancelToken",
        "cancel_token",
        "deviceCode",
        "device_code",
    ] {
        if let Some(value) = req.query::<String>(key) {
            values[key] = json!(value);
        }
    }
    Ok(values)
}
fn field<'a>(value: &'a Value, aliases: &[&str]) -> AppResult<&'a str> {
    aliases
        .iter()
        .find_map(|key| value[*key].as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Validation(format!("{} is required", aliases[0])))
}
fn admin(depot: &Depot) -> AppResult<Principal> {
    let principal = Principal::from_depot(depot)?;
    if !principal.admin {
        return Err(AppError::Authorization("Administrator required".into()));
    }
    Ok(principal)
}
fn target(req: &Request) -> AppResult<(String, String)> {
    let id = req
        .query::<String>("id")
        .ok_or_else(|| AppError::Validation("id is required".into()))?;
    let (owner, name) = id
        .split_once('/')
        .ok_or_else(|| AppError::Validation("id must be owner/name".into()))?;
    crate::handlers::parity_resources::service::identity(owner, name)?;
    Ok((owner.into(), name.into()))
}
#[handler]
pub async fn cancel_device_auth(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let value = fields(req).await?;
    service::cancel_device(
        &pool(depot)?,
        field(&value, &["userCode", "user_code"])?,
        field(&value, &["cancelToken", "cancel_token"])?,
    )
    .await?;
    Ok(Json(json!({"status":"ok","data":"Canceled"})))
}
#[handler]
pub async fn device_auth_complete(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let value = fields(req).await?;
    // The 256-bit device proof is itself a bearer credential and is consumed once.
    Ok(Json(
        service::complete_device(
            &pool(depot)?,
            field(&value, &["deviceCode", "device_code"])?,
        )
        .await?,
    ))
}
#[handler]
pub async fn device_verify(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let value = fields(req).await?;
    let principal = Principal::from_depot(depot)?;
    Ok(Json(
        service::verify_device(
            &pool(depot)?,
            &principal,
            field(&value, &["user_code", "userCode"])?,
        )
        .await?,
    ))
}
#[handler]
pub async fn device_authorize(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let value = fields(req).await?;
    let principal = Principal::from_depot(depot)?;
    let approved = value["approved"]
        .as_bool()
        .ok_or_else(|| AppError::Validation("approved boolean required".into()))?;
    let claims = depot
        .get::<crate::services::auth_service::Claims>("claims")
        .map_err(|_| AppError::Authentication("Session claims required".into()))?;
    let bearer = req
        .header::<String>("Authorization")
        .and_then(|value| value.strip_prefix("Bearer ").map(str::to_owned))
        .ok_or_else(|| AppError::Authentication("Session bearer required".into()))?;
    service::authorize_device(
        &pool(depot)?,
        &principal,
        field(&value, &["user_code", "device_code", "userCode"])?,
        approved,
        claims,
        &bearer,
    )
    .await?;
    Ok(Json(json!({"status":"ok"})))
}
#[handler]
pub async fn get_openclaw_session_transcript(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<Value>> {
    let principal = admin(depot)?;
    let (owner, name) = target(req)?;
    Ok(Json(
        json!({"status":"ok","data":service::transcript(&pool(depot)?,&principal,&owner,&name).await?}),
    ))
}
#[handler]
pub async fn sync_mcp_tool(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let principal = admin(depot)?;
    let (owner, name) = target(req)?;
    let bytes = req
        .payload()
        .await
        .map_err(|_| AppError::Validation("Cannot read server body".into()))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(AppError::Validation("Server body exceeds 2 MiB".into()));
    }
    if !bytes.is_empty() {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|_| AppError::Validation("JSON server body required".into()))?;
        if !value.is_object() {
            return Err(AppError::Validation("Object server body required".into()));
        }
        for (field, expected) in [("owner", owner.as_str()), ("name", name.as_str())] {
            if value
                .get(field)
                .is_some_and(|value| value.as_str() != Some(expected))
            {
                return Err(AppError::Validation("Server identity mismatch".into()));
            }
        }
        let saved = crate::handlers::parity_resources::service::get(
            &pool(depot)?,
            crate::handlers::parity_resources::service::Kind::Server,
            &owner,
            &name,
        )
        .await?
        .ok_or_else(|| AppError::NotFound("Server not found".into()))?;
        for field in ["url", "token"] {
            if value[field].as_str().is_some_and(|value| {
                !value.is_empty() && value != "***" && saved[field].as_str() != Some(value)
            }) {
                return Err(AppError::Validation(
                    "Save server configuration before synchronizing tools".into(),
                ));
            }
        }
    }
    let cleared = req
        .query::<String>("isCleared")
        .is_some_and(|value| value == "1" || value == "true");
    Ok(Json(
        service::sync_mcp(&pool(depot)?, &principal, &owner, &name, cleared).await?,
    ))
}
