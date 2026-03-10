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
    if application.client_secret != client_secret {
        return Err(AppError::Authentication(
            "Invalid client_secret".to_string(),
        ));
    }

    Ok(Some((application.id, application.name)))
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
    let service = ProviderDispatchService::new(pool).with_diesel_pool(diesel_pool);
    let subject = req
        .title
        .clone()
        .or(req.subject.clone())
        .unwrap_or_else(|| "Casdog notification".to_string());
    let delivery = service
        .send_email(
            req.provider.as_deref(),
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
    let service = ProviderDispatchService::new(pool).with_diesel_pool(diesel_pool);
    let delivery = service
        .send_sms(
            req.provider.as_deref(),
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
    let service = ProviderDispatchService::new(pool).with_diesel_pool(diesel_pool);
    let title = req
        .title
        .clone()
        .or(req.notification_type.clone())
        .unwrap_or_else(|| "Casdog notification".to_string());
    let delivery = service
        .send_notification(
            req.provider.as_deref(),
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
