use crate::error::AppResult;
use crate::models::{Certificate, CertificateResponse, CreateCertificateRequest, UpdateCertificateRequest};
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

    pub async fn create(pool: &PgPool, req: CreateCertificateRequest) -> AppResult<CertificateResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Generate a placeholder key pair (in production, use proper crypto)
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

    fn generate_key_pair(_algorithm: &str, _bit_size: i32) -> AppResult<(String, String)> {
        // Placeholder - in production use proper crypto library
        // For now, return placeholder values
        Ok((
            "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----".to_string(),
            "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----".to_string(),
        ))
    }
}
