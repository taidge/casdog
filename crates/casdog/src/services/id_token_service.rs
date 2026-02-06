use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use crate::models::Certificate;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

pub struct IdTokenService;

impl IdTokenService {
    /// Build and sign an OIDC ID Token using the application's certificate
    pub async fn generate_id_token(
        pool: &PgPool,
        user_id: &str,
        user_name: &str,
        client_id: &str,
        nonce: Option<&str>,
        access_token: Option<&str>,
        cert_name: Option<&str>,
    ) -> AppResult<String> {
        let config = AppConfig::get();
        let issuer = format!("http://{}:{}", config.server.host, config.server.port);

        // Fetch user details
        let user: Option<(String, String, Option<String>, Option<String>, Option<String>)> =
            sqlx::query_as(
                "SELECT id, name, email, phone, avatar FROM users WHERE id = $1 AND is_deleted = FALSE",
            )
            .bind(user_id)
            .fetch_optional(pool)
            .await?;

        let (uid, uname, email, phone, avatar) = user.unwrap_or_else(|| {
            (user_id.to_string(), user_name.to_string(), None, None, None)
        });

        let now = Utc::now();
        let exp = now + Duration::hours(config.jwt.expiration_hours);

        // Compute at_hash if access_token provided
        let at_hash = access_token.map(|at| {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(at.as_bytes());
            let half = &hash[..hash.len() / 2];
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, half)
        });

        let claims = IdTokenClaims {
            iss: issuer,
            sub: uid,
            aud: client_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nonce: nonce.map(|s| s.to_string()),
            at_hash,
            name: Some(uname.clone()),
            preferred_username: Some(uname),
            email: email.clone(),
            email_verified: email.as_ref().map(|_| true),
            phone_number: phone.clone(),
            phone_number_verified: phone.as_ref().map(|_| false),
            picture: avatar,
        };

        // Try to find a certificate for signing
        let cert = if let Some(cert_name) = cert_name {
            sqlx::query_as::<_, Certificate>(
                "SELECT * FROM certificates WHERE name = $1"
            )
            .bind(cert_name)
            .fetch_optional(pool)
            .await?
        } else {
            sqlx::query_as::<_, Certificate>(
                "SELECT * FROM certificates WHERE scope = 'JWT' ORDER BY created_at DESC LIMIT 1"
            )
            .fetch_optional(pool)
            .await?
        };

        match cert {
            Some(cert) => Self::sign_with_cert(&claims, &cert),
            None => {
                // Fallback to HMAC signing with JWT secret
                let header = Header::new(Algorithm::HS256);
                let token = encode(
                    &header,
                    &claims,
                    &EncodingKey::from_secret(config.jwt.secret.as_bytes()),
                )?;
                Ok(token)
            }
        }
    }

    fn sign_with_cert(claims: &IdTokenClaims, cert: &Certificate) -> AppResult<String> {
        match cert.crypto_algorithm.as_str() {
            "RS256" => Self::sign_rsa(claims, cert, Algorithm::RS256),
            "RS384" => Self::sign_rsa(claims, cert, Algorithm::RS384),
            "RS512" => Self::sign_rsa(claims, cert, Algorithm::RS512),
            "ES256" => Self::sign_ec(claims, cert, Algorithm::ES256),
            "ES384" => Self::sign_ec(claims, cert, Algorithm::ES384),
            _ => Err(AppError::Internal(format!(
                "Unsupported signing algorithm: {}",
                cert.crypto_algorithm
            ))),
        }
    }

    fn sign_rsa(claims: &IdTokenClaims, cert: &Certificate, alg: Algorithm) -> AppResult<String> {
        let mut header = Header::new(alg);
        header.kid = Some(cert.name.clone());

        let key = EncodingKey::from_rsa_pem(cert.private_key.as_bytes())
            .map_err(|e| AppError::Internal(format!("Failed to parse RSA key: {}", e)))?;

        let token = encode(&header, claims, &key)?;
        Ok(token)
    }

    fn sign_ec(claims: &IdTokenClaims, cert: &Certificate, alg: Algorithm) -> AppResult<String> {
        let mut header = Header::new(alg);
        header.kid = Some(cert.name.clone());

        let key = EncodingKey::from_ec_pem(cert.private_key.as_bytes())
            .map_err(|e| AppError::Internal(format!("Failed to parse EC key: {}", e)))?;

        let token = encode(&header, claims, &key)?;
        Ok(token)
    }
}
