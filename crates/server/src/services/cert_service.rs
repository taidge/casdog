use crate::error::{AppError, AppResult};
use crate::models::{Certificate, CertificateResponse, CreateCertificateRequest, Jwk, UpdateCertificateRequest};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub struct CertService;

impl CertService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<CertificateResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let (certs, total): (Vec<Certificate>, i64) = if let Some(owner) = owner {
            let certs = sqlx::query_as::<_, Certificate>(
                r#"SELECT * FROM certificates WHERE owner = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"#
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM certificates WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?;

            (certs, total.0)
        } else {
            let certs = sqlx::query_as::<_, Certificate>(
                r#"SELECT * FROM certificates ORDER BY created_at DESC LIMIT $1 OFFSET $2"#
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM certificates")
                .fetch_one(pool)
                .await?;

            (certs, total.0)
        };

        Ok((certs.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<CertificateResponse> {
        let cert = sqlx::query_as::<_, Certificate>("SELECT * FROM certificates WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?;
        Ok(cert.into())
    }

    pub async fn get_by_name(pool: &PgPool, owner: &str, name: &str) -> AppResult<Certificate> {
        let cert = sqlx::query_as::<_, Certificate>(
            "SELECT * FROM certificates WHERE owner = $1 AND name = $2"
        )
        .bind(owner)
        .bind(name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Certificate '{}/{}' not found", owner, name)))?;
        Ok(cert)
    }

    pub async fn create(pool: &PgPool, req: CreateCertificateRequest) -> AppResult<CertificateResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let (certificate, private_key) = Self::generate_key_pair(&req.crypto_algorithm, req.bit_size)?;

        let cert = sqlx::query_as::<_, Certificate>(
            r#"INSERT INTO certificates (
                id, owner, name, created_at, display_name, scope, type,
                crypto_algorithm, bit_size, expire_in_years, certificate, private_key
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *"#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(now)
        .bind(&req.display_name)
        .bind(&req.scope)
        .bind(&req.cert_type)
        .bind(&req.crypto_algorithm)
        .bind(req.bit_size)
        .bind(req.expire_in_years)
        .bind(&certificate)
        .bind(&private_key)
        .fetch_one(pool)
        .await?;

        Ok(cert.into())
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateCertificateRequest,
    ) -> AppResult<CertificateResponse> {
        let cert = sqlx::query_as::<_, Certificate>(
            r#"UPDATE certificates SET
                display_name = COALESCE($2, display_name),
                scope = COALESCE($3, scope),
                expire_in_years = COALESCE($4, expire_in_years)
            WHERE id = $1 RETURNING *"#,
        )
        .bind(id)
        .bind(&req.display_name)
        .bind(&req.scope)
        .bind(&req.expire_in_years)
        .fetch_one(pool)
        .await?;

        Ok(cert.into())
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM certificates WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub fn generate_key_pair(algorithm: &str, bit_size: i32) -> AppResult<(String, String)> {
        match algorithm {
            "RS256" | "RS384" | "RS512" => Self::generate_rsa_key_pair(bit_size as usize),
            "ES256" | "ES384" | "ES512" => Self::generate_ec_key_pair(algorithm),
            _ => Err(AppError::Validation(format!("Unsupported algorithm: {}", algorithm))),
        }
    }

    fn generate_rsa_key_pair(bit_size: usize) -> AppResult<(String, String)> {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        use rsa::RsaPrivateKey;

        let bit_size = if bit_size == 0 { 2048 } else { bit_size };
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bit_size)
            .map_err(|e| AppError::Internal(format!("RSA key generation failed: {}", e)))?;

        let private_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| AppError::Internal(format!("RSA private key PEM encoding failed: {}", e)))?;

        let public_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| AppError::Internal(format!("RSA public key PEM encoding failed: {}", e)))?;

        Ok((public_pem, private_pem.to_string()))
    }

    fn generate_ec_key_pair(_algorithm: &str) -> AppResult<(String, String)> {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePrivateKey;

        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let private_pem = signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| AppError::Internal(format!("EC private key PEM encoding failed: {}", e)))?;

        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        // Encode public key as PEM using SEC1 format
        let public_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                point.as_bytes()
            )
        );

        Ok((public_pem, private_pem.to_string()))
    }

    /// Extract a JWK from a certificate record
    pub fn get_jwk_from_cert(cert: &Certificate) -> AppResult<Jwk> {
        match cert.crypto_algorithm.as_str() {
            "RS256" | "RS384" | "RS512" => Self::rsa_cert_to_jwk(cert),
            "ES256" | "ES384" | "ES512" => Self::ec_cert_to_jwk(cert),
            _ => Err(AppError::Internal(format!(
                "Unsupported algorithm for JWK: {}",
                cert.crypto_algorithm
            ))),
        }
    }

    fn rsa_cert_to_jwk(cert: &Certificate) -> AppResult<Jwk> {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::RsaPrivateKey;

        let private_key = RsaPrivateKey::from_pkcs8_pem(&cert.private_key)
            .map_err(|e| AppError::Internal(format!("Failed to parse RSA private key: {}", e)))?;
        let public_key = private_key.to_public_key();

        let n = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            public_key.n().to_bytes_be(),
        );
        let e = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            public_key.e().to_bytes_be(),
        );

        Ok(Jwk {
            kty: "RSA".to_string(),
            alg: cert.crypto_algorithm.clone(),
            use_: "sig".to_string(),
            kid: cert.name.clone(),
            n: Some(n),
            e: Some(e),
            x: None,
            y: None,
            crv: None,
        })
    }

    fn ec_cert_to_jwk(cert: &Certificate) -> AppResult<Jwk> {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::DecodePrivateKey;

        let signing_key = SigningKey::from_pkcs8_pem(&cert.private_key)
            .map_err(|e| AppError::Internal(format!("Failed to parse EC private key: {}", e)))?;
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let x = point.x().ok_or_else(|| AppError::Internal("EC key missing x coordinate".to_string()))?;
        let y = point.y().ok_or_else(|| AppError::Internal("EC key missing y coordinate".to_string()))?;

        Ok(Jwk {
            kty: "EC".to_string(),
            alg: cert.crypto_algorithm.clone(),
            use_: "sig".to_string(),
            kid: cert.name.clone(),
            n: None,
            e: None,
            x: Some(base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                x.as_slice(),
            )),
            y: Some(base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                y.as_slice(),
            )),
            crv: Some("P-256".to_string()),
        })
    }
}
