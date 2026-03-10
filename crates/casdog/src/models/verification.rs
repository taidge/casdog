use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Verification {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub remote_addr: Option<String>,
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub verification_type: String, // email, phone
    #[sqlx(rename = "user_id")]
    pub user_id: String,
    pub provider: String,
    pub receiver: String,
    pub code: String,
    pub is_used: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendVerificationCodeRequest {
    #[serde(rename = "type")]
    pub verification_type: String, // email, phone
    pub dest: String, // email address or phone number
    pub application: Option<String>,
    pub check_user: Option<bool>,
    pub provider: Option<String>,
    pub method: Option<String>,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyCodeRequest {
    #[serde(rename = "type")]
    pub verification_type: String,
    pub dest: String,
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyCodeResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerificationResponse {
    pub id: String,
    pub owner: String,
    pub created_at: DateTime<Utc>,
    #[serde(rename = "type")]
    pub verification_type: String,
    pub user: String,
    pub provider: String,
    pub receiver: String,
    pub is_used: bool,
}

impl From<Verification> for VerificationResponse {
    fn from(v: Verification) -> Self {
        Self {
            id: v.id,
            owner: v.owner,
            created_at: v.created_at,
            verification_type: v.verification_type,
            user: v.user_id,
            provider: v.provider,
            receiver: v.receiver,
            is_used: v.is_used,
        }
    }
}

// Captcha
#[derive(Debug, Serialize, ToSchema)]
pub struct CaptchaResponse {
    pub captcha_id: String,
    pub captcha_image: Option<String>, // Base64 encoded image or local SVG data URI
    pub external: bool,
    pub provider: Option<String>,
    pub captcha_type: Option<String>,
    pub site_key: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyCaptchaRequest {
    pub captcha_id: String,
    pub captcha_code: Option<String>,
    pub captcha_token: Option<String>,
    pub application: Option<String>,
    pub provider: Option<String>,
}

// Email/Phone retrieval
#[derive(Debug, Deserialize, ToSchema)]
pub struct GetEmailAndPhoneRequest {
    pub organization: String,
    pub username: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EmailAndPhoneResponse {
    pub email: Option<String>,
    pub phone: Option<String>,
}

// Reset email or phone
#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetEmailOrPhoneRequest {
    #[serde(rename = "type")]
    pub reset_type: String, // email, phone
    pub dest: String,
    pub code: String,
}
