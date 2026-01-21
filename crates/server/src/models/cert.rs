use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Certificate {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub display_name: String,
    pub scope: String, // JWT, SAML
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub cert_type: String, // x509
    pub crypto_algorithm: String, // RS256, ES256
    pub bit_size: i32,
    pub expire_in_years: i32,
    pub certificate: String, // Public key/certificate
    pub private_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCertificateRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub scope: String,
    #[serde(rename = "type")]
    pub cert_type: String,
    pub crypto_algorithm: String,
    pub bit_size: i32,
    pub expire_in_years: i32,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCertificateRequest {
    pub display_name: Option<String>,
    pub scope: Option<String>,
    pub expire_in_years: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CertificateResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub display_name: String,
    pub scope: String,
    #[serde(rename = "type")]
    pub cert_type: String,
    pub crypto_algorithm: String,
    pub bit_size: i32,
    pub expire_in_years: i32,
    pub certificate: String,
}

impl From<Certificate> for CertificateResponse {
    fn from(c: Certificate) -> Self {
        Self {
            id: c.id,
            owner: c.owner,
            name: c.name,
            created_at: c.created_at,
            display_name: c.display_name,
            scope: c.scope,
            cert_type: c.cert_type,
            crypto_algorithm: c.crypto_algorithm,
            bit_size: c.bit_size,
            expire_in_years: c.expire_in_years,
            certificate: c.certificate,
        }
    }
}
