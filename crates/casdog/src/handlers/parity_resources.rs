use crate::error::{AppError, AppResult};
use crate::hoops::authz::Principal;
use salvo::prelude::*;
use serde_json::{Value, json};
use sqlx::PgPool;

#[path = "../services/parity_marketplace_service.rs"]
pub mod marketplace;
#[path = "../services/parity_openclaw_service.rs"]
pub mod openclaw;
#[path = "../services/parity_resource_service.rs"]
pub mod service;
use service::{Kind, ListOptions, text};

pub fn routes() -> Router {
    Router::new()
        .push(Router::with_path("get-agents").get(get_agents))
        .push(Router::with_path("get-agent").get(get_agent))
        .push(Router::with_path("add-agent").post(add_agent))
        .push(Router::with_path("update-agent").post(update_agent))
        .push(Router::with_path("delete-agent").post(delete_agent))
        .push(Router::with_path("get-entries").get(get_entries))
        .push(Router::with_path("get-entry").get(get_entry))
        .push(Router::with_path("add-entry").post(add_entry))
        .push(Router::with_path("update-entry").post(update_entry))
        .push(Router::with_path("delete-entry").post(delete_entry))
        .push(Router::with_path("get-keys").get(get_keys))
        .push(Router::with_path("get-key").get(get_key))
        .push(Router::with_path("add-key").post(add_key))
        .push(Router::with_path("update-key").post(update_key))
        .push(Router::with_path("delete-key").post(delete_key))
        .push(Router::with_path("get-servers").get(get_servers))
        .push(Router::with_path("get-server").get(get_server))
        .push(Router::with_path("add-server").post(add_server))
        .push(Router::with_path("update-server").post(update_server))
        .push(Router::with_path("delete-server").post(delete_server))
        .push(Router::with_path("get-global-keys").get(get_global_keys))
        .push(Router::with_path("get-mcp-access-token").get(get_mcp_access_token))
        .push(Router::with_path("get-online-servers").get(get_online_servers))
        .push(Router::with_path("get-integrations").get(get_integrations))
        .push(Router::with_path("get-integration").get(get_integration))
        .push(Router::with_path("install-integration").post(install_integration))
        .push(Router::with_path("delete-integration").post(delete_integration))
        .push(Router::with_path("get-marketplace-index").get(get_marketplace_index))
        .push(Router::with_path("get-marketplace-bundle").get(get_marketplace_bundle))
        .push(Router::with_path("get-openclaw-session-graph").get(get_openclaw_session_graph))
}

fn context(depot: &Depot) -> AppResult<(PgPool, Principal)> {
    let principal = Principal::from_depot(depot)?;
    if !principal.admin {
        return Err(service::denied());
    }
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("Database unavailable".into()))?
        .clone();
    Ok((pool, principal))
}
async fn body(req: &mut Request) -> AppResult<Value> {
    let bytes = req
        .payload()
        .await
        .map_err(|_| AppError::Validation("Cannot read body".into()))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(AppError::Validation("Resource body too large".into()));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| AppError::Validation("JSON body required".into()))?;
    if !value.is_object() {
        return Err(AppError::Validation("Object body required".into()));
    }
    Ok(value)
}
fn target(req: &Request, value: Option<&Value>) -> AppResult<(String, String)> {
    if let Some(id) = req.query::<String>("id") {
        let (owner, name) = id
            .split_once('/')
            .ok_or_else(|| AppError::Validation("id must be owner/name".into()))?;
        service::identity(owner, name)?;
        return Ok((owner.to_string(), name.to_string()));
    }
    let value = value.ok_or_else(|| AppError::Validation("id is required".into()))?;
    let (owner, name) = (text(value, "owner"), text(value, "name"));
    service::identity(owner, name)?;
    Ok((owner.to_string(), name.to_string()))
}
async fn list_resource(
    depot: &Depot,
    req: &Request,
    kind: Kind,
    global: bool,
) -> AppResult<Json<Value>> {
    let (pool, principal) = context(depot)?;
    if global && !principal.global_admin() {
        return Err(service::denied());
    }
    let owner = if global {
        None
    } else {
        Some(
            req.query::<String>("owner")
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| principal.owner.clone()),
        )
    };
    let limit = req
        .query::<String>("pageSize")
        .map(|s| {
            s.parse::<i64>()
                .map_err(|_| AppError::Validation("Invalid pageSize".into()))
        })
        .transpose()?;
    let page = req
        .query::<String>("p")
        .unwrap_or_else(|| "1".into())
        .parse::<i64>()
        .map_err(|_| AppError::Validation("Invalid page".into()))?;
    if page < 1 || limit.is_some_and(|n| n <= 0 || n > 1000) {
        return Err(AppError::Validation(
            "page must be positive and pageSize between 1 and 1000".into(),
        ));
    }
    let offset = (page - 1)
        .checked_mul(limit.unwrap_or(0))
        .ok_or_else(|| AppError::Validation("Page offset overflow".into()))?;
    let order = req
        .query::<String>("sortOrder")
        .unwrap_or_else(|| "descend".into());
    if !["ascend", "descend", "asc", "desc"].contains(&order.as_str()) {
        return Err(AppError::Validation("Invalid sortOrder".into()));
    }
    let options = ListOptions {
        owner,
        field: req.query::<String>("field").filter(|s| !s.is_empty()),
        value: req.query::<String>("value").unwrap_or_default(),
        sort: req
            .query::<String>("sortField")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "createdTime".into()),
        descending: matches!(order.as_str(), "descend" | "desc"),
        limit,
        offset,
    };
    let (data, total) = service::list(&pool, &principal, kind, options).await?;
    Ok(Json(json!({"status":"ok","data":data,"data2":total})))
}
async fn get_resource(depot: &Depot, req: &Request, kind: Kind) -> AppResult<Json<Value>> {
    let (pool, principal) = context(depot)?;
    let (owner, name) = target(req, None)?;
    service::authorize(&principal, &owner)?;
    let data = service::get(&pool, kind, &owner, &name)
        .await?
        .map(|v| service::masked(kind, v, false));
    Ok(Json(json!({"status":"ok","data":data})))
}
async fn save_resource(
    depot: &Depot,
    req: &mut Request,
    kind: Kind,
    update: bool,
) -> AppResult<Json<Value>> {
    let (pool, principal) = context(depot)?;
    let value = body(req).await?;
    let (owner, name) = target(req, Some(&value))?;
    let result = service::save(&pool, &principal, kind, &owner, &name, value, update).await?;
    Ok(Json(json!({"status":"ok","data":result.is_some()})))
}
async fn delete_resource(depot: &Depot, req: &mut Request, kind: Kind) -> AppResult<Json<Value>> {
    let (pool, principal) = context(depot)?;
    let value = body(req).await?;
    let (owner, name) = target(req, Some(&value))?;
    let result = service::delete(&pool, &principal, kind, &owner, &name).await?;
    Ok(Json(json!({"status":"ok","data":result})))
}

#[handler]
pub async fn get_agents(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    list_resource(depot, req, Kind::Agent, false).await
}

#[handler]
pub async fn get_agent(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    get_resource(depot, req, Kind::Agent).await
}

#[handler]
pub async fn add_agent(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    save_resource(depot, req, Kind::Agent, false).await
}

#[handler]
pub async fn update_agent(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    save_resource(depot, req, Kind::Agent, true).await
}

#[handler]
pub async fn delete_agent(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    delete_resource(depot, req, Kind::Agent).await
}

#[handler]
pub async fn get_entries(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    list_resource(depot, req, Kind::Entry, false).await
}

#[handler]
pub async fn get_entry(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    get_resource(depot, req, Kind::Entry).await
}

#[handler]
pub async fn add_entry(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    save_resource(depot, req, Kind::Entry, false).await
}

#[handler]
pub async fn update_entry(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    save_resource(depot, req, Kind::Entry, true).await
}

#[handler]
pub async fn delete_entry(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    delete_resource(depot, req, Kind::Entry).await
}

#[handler]
pub async fn get_keys(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    list_resource(depot, req, Kind::Key, false).await
}

#[handler]
pub async fn get_key(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    get_resource(depot, req, Kind::Key).await
}

#[handler]
pub async fn add_key(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    save_resource(depot, req, Kind::Key, false).await
}

#[handler]
pub async fn update_key(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    save_resource(depot, req, Kind::Key, true).await
}

#[handler]
pub async fn delete_key(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    delete_resource(depot, req, Kind::Key).await
}

#[handler]
pub async fn get_servers(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    list_resource(depot, req, Kind::Server, false).await
}

#[handler]
pub async fn get_server(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    get_resource(depot, req, Kind::Server).await
}

#[handler]
pub async fn add_server(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    save_resource(depot, req, Kind::Server, false).await
}

#[handler]
pub async fn update_server(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    save_resource(depot, req, Kind::Server, true).await
}

#[handler]
pub async fn delete_server(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    delete_resource(depot, req, Kind::Server).await
}

#[handler]
pub async fn get_global_keys(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    list_resource(depot, req, Kind::Key, true).await
}

#[handler]
pub async fn get_mcp_access_token(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let principal = Principal::from_depot(depot)?;
    let claims = depot
        .get::<crate::services::auth_service::Claims>("claims")
        .map_err(|_| AppError::Authentication("Validated session required".into()))?;
    let bearer = req
        .header::<String>("Authorization")
        .and_then(|value| value.strip_prefix("Bearer ").map(str::to_string))
        .ok_or_else(|| AppError::Authentication("Session bearer required".into()))?;
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("Database unavailable".into()))?;
    let owner = req
        .query::<String>("owner")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| principal.owner.clone());
    if owner != principal.owner && !principal.global_admin() {
        return Err(service::denied());
    }
    let name = req
        .query::<String>("applicationName")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("applicationName is required".into()))?;
    let app = service::application(pool, &owner, &name).await?;
    let mut tx = pool.begin().await?;
    service::validate_mcp_session_conn(&mut *tx, &principal, claims, &bearer).await?;
    crate::services::CheckService::check_login_permission_conn(
        &mut *tx,
        &principal.id,
        text(&app, "id"),
    )
    .await?;
    // An opaque, database-backed read token deliberately cannot authenticate as an admin session JWT.
    let token = service::random_secret();
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO tokens(id,owner,name,application,organization,user_id,access_token,expires_in,scope,token_type,code_is_used) VALUES($1,$2,$3,$4,$5,$6,$7,900,'read','Bearer',true)")
        .bind(&id).bind(text(&app,"owner")).bind(format!("mcp-{id}")).bind(text(&app,"name")).bind(&owner).bind(&principal.id).bind(&token).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"ok","data":token})))
}

#[handler]
pub async fn get_online_servers(depot: &mut Depot) -> AppResult<Json<Value>> {
    context(depot)?;
    let bytes = marketplace::fetch("https://mcp.casdoor.org/registry.json").await?;
    let data: Value = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Validation("Invalid MCP registry response".into()))?;
    Ok(Json(json!({"status":"ok","data":data})))
}
#[handler]
pub async fn get_integrations(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    list_resource(depot, req, Kind::Integration, false).await
}
#[handler]
pub async fn get_integration(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    get_resource(depot, req, Kind::Integration).await
}
#[handler]
pub async fn get_marketplace_index(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    context(depot)?;
    let mut data = marketplace::index(&marketplace::base_url()).await?;
    if !req
        .header::<String>("Accept-Language")
        .unwrap_or_default()
        .starts_with("zh")
    {
        data["integrations"]
            .as_array_mut()
            .unwrap()
            .retain(|item| text(item, "region") != "cn");
    }
    Ok(Json(json!({"status":"ok","data":data})))
}
#[handler]
pub async fn get_marketplace_bundle(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<Value>> {
    context(depot)?;
    let id = req
        .query::<String>("integrationId")
        .ok_or_else(|| AppError::Validation("integrationId is required".into()))?;
    let version = req.query::<String>("version").unwrap_or_default();
    let (_, data) = marketplace::bundle(&marketplace::base_url(), &id, &version).await?;
    Ok(Json(json!({"status":"ok","data":data})))
}
#[handler]
pub async fn install_integration(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let (pool, principal) = context(depot)?;
    let request = body(req).await?;
    service::authorize(&principal, text(&request, "owner"))?;
    let (item, bundle) = marketplace::bundle(
        &marketplace::base_url(),
        text(&request, "integrationId"),
        text(&request, "version"),
    )
    .await?;
    let data = marketplace::install(&pool, &principal, &request, &item, &bundle).await?;
    Ok(Json(json!({"status":"ok","data":data})))
}
#[handler]
pub async fn delete_integration(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let (pool, principal) = context(depot)?;
    let request = body(req).await?;
    let (owner, name) = target(req, Some(&request))?;
    let data = marketplace::uninstall(&pool, &principal, &owner, &name).await?;
    Ok(Json(json!({"status":"ok","data":data})))
}

#[handler]
pub async fn get_openclaw_session_graph(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<Value>> {
    let (pool, principal) = context(depot)?;
    let (owner, name) = target(req, None)?;
    let graph = openclaw::graph(&pool, &principal, &owner, &name).await?;
    Ok(Json(json!({"status":"ok","data":graph})))
}
