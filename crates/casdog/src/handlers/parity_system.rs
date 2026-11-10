use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
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
fn forbidden() -> AppError {
    AppError::Authorization("Operation unavailable for this tenant".into())
}
pub fn routes() -> Router {
    Router::new()
        .push(Router::with_path("get-global-forms").get(global_forms))
        .push(Router::with_path("is-session-duplicated").get(session_duplicated))
        .push(Router::with_path("get-idp-discovery").get(idp_discovery))
}
#[handler]
pub async fn global_forms(depot: &mut Depot) -> AppResult<Json<Value>> {
    let principal = Principal::from_depot(depot)?;
    if !principal.global_admin() {
        return Err(forbidden());
    }
    let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('owner',owner,'name',name,'displayName',display_name,'formItems',form_items,'isEnabled',is_enabled) FROM forms WHERE NOT is_deleted ORDER BY owner,name").fetch_all(&pool(depot)?).await?;
    Ok(Json(json!({"status":"ok","data":rows})))
}
#[handler]
pub async fn session_duplicated(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = Principal::from_depot(depot)?;
    let id = req
        .query::<String>("sessionPkId")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Validation("sessionPkId required".into()))?;
    let supplied = req
        .query::<String>("sessionId")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Validation("sessionId required".into()))?;
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT owner,user_id,session_id FROM sessions WHERE id=$1 OR owner||'/'||name=$1 LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&pool(depot)?)
    .await?;
    let duplicated = match row {
        None => false,
        Some((owner, user, current)) => {
            if !p.global_admin() && (owner != p.owner || user != p.id) {
                return Err(forbidden());
            }
            current != supplied
        }
    };
    Ok(Json(json!({"status":"ok","data":duplicated})))
}
#[handler]
pub async fn idp_discovery(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = Principal::from_depot(depot)?;
    if !p.admin {
        return Err(forbidden());
    }
    let issuer = req
        .query::<String>("issuer")
        .ok_or_else(|| AppError::Validation("issuer required".into()))?;
    let configured: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM providers WHERE issuer_url=$1 AND ($2 OR owner=$3))",
    )
    .bind(&issuer)
    .bind(p.global_admin())
    .bind(&p.owner)
    .fetch_one(&pool(depot)?)
    .await?;
    if !configured {
        return Err(forbidden());
    }
    let url =
        reqwest::Url::parse(&issuer).map_err(|_| AppError::Validation("Invalid issuer".into()))?;
    if (url.scheme() != "https" && !(p.global_admin() && url.scheme() == "http"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AppError::Validation("Issuer must be an HTTPS URL".into()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| AppError::Validation("Issuer host required".into()))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| AppError::Validation(e.to_string()))?
        .collect();
    if addresses.is_empty()
        || (!p.global_admin()
            && addresses.iter().any(|a| match a.ip() {
                std::net::IpAddr::V4(ip) => {
                    ip.is_private()
                        || ip.is_loopback()
                        || ip.is_link_local()
                        || ip.is_unspecified()
                        || ip.is_multicast()
                        || ip.octets()[0] == 0
                }
                std::net::IpAddr::V6(ip) => {
                    ip.is_loopback()
                        || ip.is_unspecified()
                        || ip.is_multicast()
                        || (ip.segments()[0] & 0xfe00) == 0xfc00
                        || (ip.segments()[0] & 0xffc0) == 0xfe80
                        || ip.to_ipv4_mapped().is_some()
                }
            }))
    {
        return Err(forbidden());
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve_to_addrs(host, &addresses)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let mut response = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ))
        .send()
        .await
        .map_err(|e| AppError::Validation(e.to_string()))?;
    if !response.status().is_success() {
        return Err(AppError::Validation("Discovery request failed".into()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| AppError::Validation(e.to_string()))?
    {
        if bytes.len() + chunk.len() > 1_048_576 {
            return Err(AppError::Validation("Discovery response too large".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    let metadata: Value = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Validation("Invalid discovery document".into()))?;
    if metadata.get("issuer").and_then(Value::as_str) != Some(issuer.as_str()) {
        return Err(AppError::Validation("Discovery issuer mismatch".into()));
    }
    Ok(Json(json!({"status":"ok","data":metadata})))
}

/// One-time bootstrap is available only while the canonical administrator has
/// neither a password nor a previous login; the user row serializes contenders.
#[handler]
pub async fn init_admin_status(depot: &mut Depot) -> AppResult<Json<Value>> {
    let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE owner='built-in' AND name='admin' AND NOT is_deleted AND NOT is_forbidden AND password_hash='' AND COALESCE(last_signin_time,'')='')").fetch_one(&pool(depot)?).await?;
    Ok(Json(json!({"status":"ok","data":pending})))
}
#[handler]
pub async fn init_admin_password(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    if req.header::<String>("origin").as_deref()
        != Some(super::social_login::public_origin()?.as_str())
    {
        return Err(forbidden());
    }
    let password = if req
        .header::<String>("content-type")
        .is_some_and(|v| v.starts_with("application/json"))
    {
        let b: Value = req
            .parse_json()
            .await
            .map_err(|_| AppError::Validation("JSON password required".into()))?;
        b["password"].as_str().unwrap_or_default().to_string()
    } else {
        req.form::<String>("password").await.unwrap_or_default()
    };
    if password.len() > 1024 || password.chars().any(char::is_whitespace) {
        return Err(AppError::Validation(
            "Password must not contain whitespace or exceed 1024 bytes".into(),
        ));
    }
    let pg = pool(depot)?;
    let mut tx = pg.begin().await?;
    let id:Option<String>=sqlx::query_scalar("SELECT id FROM users WHERE owner='built-in' AND name='admin' AND NOT is_deleted AND NOT is_forbidden AND password_hash='' AND COALESCE(last_signin_time,'')='' FOR UPDATE").fetch_optional(&mut *tx).await?;
    let id = id.ok_or_else(forbidden)?;
    let options: Option<Value> = sqlx::query_scalar(
        "SELECT password_options FROM organizations WHERE name='built-in' AND NOT is_deleted",
    )
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    crate::services::CheckService::check_password_complexity(&password, options.as_ref())?;
    let hash = crate::services::PasswordService::hash_password(&password, "argon2", None)?;
    sqlx::query("UPDATE users SET password_hash=$1,password_type='argon2',password_salt=NULL,need_update_password=false,last_change_password_time=$2,updated_at=NOW() WHERE id=$3").bind(hash).bind(chrono::Utc::now().to_rfc3339()).bind(&id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM tokens WHERE user_id=$1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=$1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO user_session_epochs(user_id,invalid_before) VALUES($1,clock_timestamp()) ON CONFLICT(user_id) DO UPDATE SET invalid_before=EXCLUDED.invalid_before").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"ok","data":true})))
}
