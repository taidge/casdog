use base64::Engine;
use salvo::oapi::ToSchema;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::Deserialize;
use sqlx::{Pool, Postgres};

use crate::diesel_pool::DieselPool;
use crate::error::{AppError, AppResult};
use crate::services::{AppService, ProviderDispatchService};

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendEmailRequest {
    pub to: Option<String>,
    pub subject: Option<String>,
    pub title: Option<String>,
    pub content: String,
    pub sender: Option<String>,
    pub provider: Option<String>,
    pub receivers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendSmsRequest {
    pub to: Option<String>,
    pub content: String,
    pub provider: Option<String>,
    pub receivers: Option<Vec<String>>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendNotificationRequest {
    pub to: Option<String>,
    pub content: String,
    pub notification_type: Option<String>,
    pub provider: Option<String>,
    pub receivers: Option<Vec<String>>,
    pub title: Option<String>,
}

fn request_receivers(primary: &Option<String>, receivers: &Option<Vec<String>>) -> Vec<String> {
    if let Some(receivers) = receivers {
        let filtered: Vec<String> = receivers
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !filtered.is_empty() {
            return filtered;
        }
    }

    primary
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| vec![value.to_string()])
        .unwrap_or_default()
}

fn decode_basic_credentials(req: &Request) -> Option<(String, String)> {
    let header = req.header::<String>("Authorization")?;
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let mut parts = decoded.splitn(2, ':');
    let username = parts.next()?.to_string();
    let password = parts.next()?.to_string();
    Some((username, password))
}

async fn ensure_service_auth(
    depot: &mut Depot,
    req: &Request,
) -> AppResult<Option<(String, String)>> {
    if depot.get::<String>("user_id").is_ok() {
        let principal = crate::hoops::authz::Principal::from_depot(depot)?;
        if !principal.admin {
            return Err(AppError::Authorization(
                "Messaging requires administrator or application credentials".into(),
            ));
        }
        depot.insert("messaging_global", principal.global_admin());
        depot.insert("messaging_owner", principal.owner);
        return Ok(None);
    }

    let (client_id, client_secret) =
        if let Some((client_id, client_secret)) = decode_basic_credentials(req) {
            (client_id, client_secret)
        } else {
            let client_id = req
                .query::<String>("clientId")
                .ok_or_else(|| AppError::Authentication("Missing credentials".to_string()))?;
            let client_secret = req
                .query::<String>("clientSecret")
                .ok_or_else(|| AppError::Authentication("Missing credentials".to_string()))?;
            (client_id, client_secret)
        };

    let diesel_pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let application = AppService::new(diesel_pool)
        .get_by_client_id(&client_id)
        .await?;
    if client_secret.is_empty() || application.client_secret != client_secret {
        return Err(AppError::Authentication(
            "Invalid client_secret".to_string(),
        ));
    }

    depot.insert("messaging_global", false);
    depot.insert("messaging_owner", application.organization.clone());
    depot.insert("messaging_providers", application.providers.clone());
    Ok(Some((application.id, application.name)))
}

/// Resolve first, then authorize the exact provider before any external delivery.
async fn authorized_provider(
    depot: &Depot,
    pool: &Pool<Postgres>,
    service: &ProviderDispatchService,
    category: &str,
    requested: Option<&str>,
    application: Option<&str>,
    rule: Option<&str>,
    country: Option<&str>,
) -> AppResult<String> {
    let global = depot
        .get::<bool>("messaging_global")
        .copied()
        .unwrap_or(false);
    let owner = depot
        .get::<String>("messaging_owner")
        .map_err(|_| AppError::Authentication("Missing messaging identity".into()))?;
    let scoped_default: Option<String> = if !global && requested.is_none() && application.is_none()
    {
        Some(sqlx::query_scalar("SELECT id FROM providers WHERE owner=$1 AND lower(category)=lower($2) ORDER BY created_at DESC LIMIT 1")
            .bind(owner).bind(category).fetch_optional(pool).await?
            .ok_or_else(|| AppError::NotFound("No provider configured for this tenant".into()))?)
    } else {
        None
    };
    let resolved = service
        .resolve_provider(
            category,
            requested.or(scoped_default.as_deref()),
            application,
            rule,
            country,
        )
        .await?;
    if !global && resolved.provider.owner != *owner {
        return Err(AppError::Authorization(
            "Provider belongs to another tenant".into(),
        ));
    }
    if application.is_some() {
        let approved = if let Ok(Some(serde_json::Value::Array(items))) =
            depot.get::<Option<serde_json::Value>>("messaging_providers")
        {
            let full_name = format!("{}/{}", resolved.provider.owner, resolved.provider.name);
            items.iter().any(|item| {
                item.get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| {
                        name == resolved.provider.id
                            || name == resolved.provider.name
                            || name == full_name
                    })
            })
        } else {
            false
        };
        if !approved {
            return Err(AppError::Authorization(
                "Provider is not configured for this application".into(),
            ));
        }
    }
    Ok(resolved.provider.id)
}

#[endpoint(tags("Messaging"), summary = "Send email")]
pub async fn send_email(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SendEmailRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let app_identity = ensure_service_auth(depot, req).await?;
    let req = body.into_inner();
    let receivers = request_receivers(&req.to, &req.receivers);
    let diesel_pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let service = ProviderDispatchService::new(pool.clone()).with_diesel_pool(diesel_pool);
    let provider_ref = authorized_provider(
        depot,
        &pool,
        &service,
        "Email",
        req.provider.as_deref(),
        app_identity.as_ref().map(|(id, _)| id.as_str()),
        None,
        None,
    )
    .await?;
    let subject = req
        .title
        .clone()
        .or(req.subject.clone())
        .unwrap_or_else(|| "Casdog notification".to_string());
    let delivery = service
        .send_email(
            Some(provider_ref.as_str()),
            app_identity.as_ref().map(|(id, _)| id.as_str()),
            None,
            &receivers,
            &subject,
            &req.content,
            req.sender.as_deref(),
        )
        .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": format!("Email sent via {} to {}", delivery.provider.name, delivery.receivers.join(", ")),
        "title": Some(subject),
        "sender": req.sender,
        "provider": delivery.provider.name,
        "providerType": delivery.provider.provider_type,
        "application": app_identity.map(|(_, name)| name),
        "receivers": delivery.receivers,
    })))
}

#[endpoint(tags("Messaging"), summary = "Send SMS")]
pub async fn send_sms(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SendSmsRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let app_identity = ensure_service_auth(depot, req).await?;
    let req = body.into_inner();
    let receivers = request_receivers(&req.to, &req.receivers);
    let diesel_pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let service = ProviderDispatchService::new(pool.clone()).with_diesel_pool(diesel_pool);
    let provider_ref = authorized_provider(
        depot,
        &pool,
        &service,
        "SMS",
        req.provider.as_deref(),
        app_identity.as_ref().map(|(id, _)| id.as_str()),
        req.method.as_deref(),
        req.country_code.as_deref(),
    )
    .await?;
    let delivery = service
        .send_sms(
            Some(provider_ref.as_str()),
            app_identity.as_ref().map(|(id, _)| id.as_str()),
            req.method.as_deref(),
            req.country_code.as_deref(),
            &receivers,
            &req.content,
        )
        .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": format!("SMS sent via {} to {}", delivery.provider.name, delivery.receivers.join(", ")),
        "provider": delivery.provider.name,
        "providerType": delivery.provider.provider_type,
        "organizationId": req.organization_id,
        "application": app_identity.map(|(_, name)| name),
        "receivers": delivery.receivers,
    })))
}

#[endpoint(tags("Messaging"), summary = "Send notification")]
pub async fn send_notification(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SendNotificationRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let app_identity = ensure_service_auth(depot, req).await?;
    let req = body.into_inner();
    let receivers = request_receivers(&req.to, &req.receivers);
    let diesel_pool = depot
        .obtain::<DieselPool>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let pool = depot
        .obtain::<Pool<Postgres>>()
        .map_err(|_| AppError::Internal("Database pool not available".to_string()))?
        .clone();
    let service = ProviderDispatchService::new(pool.clone()).with_diesel_pool(diesel_pool);
    let provider_ref = authorized_provider(
        depot,
        &pool,
        &service,
        "Notification",
        req.provider.as_deref(),
        app_identity.as_ref().map(|(id, _)| id.as_str()),
        None,
        None,
    )
    .await?;
    let title = req
        .title
        .clone()
        .or(req.notification_type.clone())
        .unwrap_or_else(|| "Casdog notification".to_string());
    let delivery = service
        .send_notification(
            Some(provider_ref.as_str()),
            app_identity.as_ref().map(|(id, _)| id.as_str()),
            &receivers,
            &title,
            &req.content,
        )
        .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": format!("Notification sent via {}", delivery.provider.name),
        "provider": delivery.provider.name,
        "providerType": delivery.provider.provider_type,
        "notificationType": req.notification_type,
        "title": title,
        "application": app_identity.map(|(_, name)| name),
        "receivers": delivery.receivers,
    })))
}
