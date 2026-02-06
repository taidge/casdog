use salvo::oapi::ToSchema;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::Deserialize;

use crate::error::AppResult;

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendEmailRequest {
    pub to: String,
    pub subject: String,
    pub content: String,
    pub sender: Option<String>,
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendSmsRequest {
    pub to: String,
    pub content: String,
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendNotificationRequest {
    pub to: String,
    pub content: String,
    pub notification_type: Option<String>,
    pub provider: Option<String>,
}

#[endpoint(tags("Messaging"), summary = "Send email")]
pub async fn send_email(body: JsonBody<SendEmailRequest>) -> AppResult<Json<serde_json::Value>> {
    let req = body.into_inner();
    // In production, use the configured email provider
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": format!("Email sent to {}", req.to)
    })))
}

#[endpoint(tags("Messaging"), summary = "Send SMS")]
pub async fn send_sms(body: JsonBody<SendSmsRequest>) -> AppResult<Json<serde_json::Value>> {
    let req = body.into_inner();
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": format!("SMS sent to {}", req.to)
    })))
}

#[endpoint(tags("Messaging"), summary = "Send notification")]
pub async fn send_notification(
    body: JsonBody<SendNotificationRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let req = body.into_inner();
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": format!("Notification sent to {}", req.to)
    })))
}
