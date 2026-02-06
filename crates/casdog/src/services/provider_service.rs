use crate::error::AppResult;
use crate::models::{
    CreateProviderRequest, Provider, ProviderResponse, UpdateProviderRequest,
};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub struct ProviderService;

impl ProviderService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> AppResult<(Vec<ProviderResponse>, i64)> {
        let offset = (page - 1) * page_size;

        let (providers, total): (Vec<Provider>, i64) = if let Some(owner) = owner {
            let providers = sqlx::query_as::<_, Provider>(
                r#"SELECT * FROM providers WHERE owner = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"#
            )
            .bind(owner)
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM providers WHERE owner = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?;

            (providers, total.0)
        } else {
            let providers = sqlx::query_as::<_, Provider>(
                r#"SELECT * FROM providers ORDER BY created_at DESC LIMIT $1 OFFSET $2"#
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM providers")
                .fetch_one(pool)
                .await?;

            (providers, total.0)
        };

        Ok((providers.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<ProviderResponse> {
        let provider = sqlx::query_as::<_, Provider>("SELECT * FROM providers WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?;
        Ok(provider.into())
    }

    pub async fn create(pool: &PgPool, req: CreateProviderRequest) -> AppResult<ProviderResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let provider = sqlx::query_as::<_, Provider>(
            r#"INSERT INTO providers (
                id, owner, name, created_at, updated_at, display_name, category, type,
                sub_type, method, client_id, client_secret, host, port, disable_ssl,
                endpoint, bucket, domain, region_id, sign_name, template_code, app_id,
                metadata, issuer_url, provider_url, enable_sign_authn_request
            ) VALUES (
                $1, $2, $3, $4, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, false
            ) RETURNING *"#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(now)
        .bind(&req.display_name)
        .bind(&req.category)
        .bind(&req.provider_type)
        .bind(&req.sub_type)
        .bind(&req.method)
        .bind(&req.client_id)
        .bind(&req.client_secret)
        .bind(&req.host)
        .bind(&req.port)
        .bind(req.disable_ssl.unwrap_or(false))
        .bind(&req.endpoint)
        .bind(&req.bucket)
        .bind(&req.domain)
        .bind(&req.region_id)
        .bind(&req.sign_name)
        .bind(&req.template_code)
        .bind(&req.app_id)
        .bind(&req.metadata)
        .bind(&req.issuer_url)
        .bind(&req.provider_url)
        .fetch_one(pool)
        .await?;

        Ok(provider.into())
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateProviderRequest,
    ) -> AppResult<ProviderResponse> {
        let now = Utc::now();

        let provider = sqlx::query_as::<_, Provider>(
            r#"UPDATE providers SET
                updated_at = $2,
                display_name = COALESCE($3, display_name),
                category = COALESCE($4, category),
                type = COALESCE($5, type),
                sub_type = COALESCE($6, sub_type),
                method = COALESCE($7, method),
                client_id = COALESCE($8, client_id),
                client_secret = COALESCE($9, client_secret),
                host = COALESCE($10, host),
                port = COALESCE($11, port),
                disable_ssl = COALESCE($12, disable_ssl),
                endpoint = COALESCE($13, endpoint),
                bucket = COALESCE($14, bucket),
                domain = COALESCE($15, domain),
                region_id = COALESCE($16, region_id),
                sign_name = COALESCE($17, sign_name),
                template_code = COALESCE($18, template_code),
                app_id = COALESCE($19, app_id),
                metadata = COALESCE($20, metadata),
                issuer_url = COALESCE($21, issuer_url),
                provider_url = COALESCE($22, provider_url)
            WHERE id = $1 RETURNING *"#,
        )
        .bind(id)
        .bind(now)
        .bind(&req.display_name)
        .bind(&req.category)
        .bind(&req.provider_type)
        .bind(&req.sub_type)
        .bind(&req.method)
        .bind(&req.client_id)
        .bind(&req.client_secret)
        .bind(&req.host)
        .bind(&req.port)
        .bind(&req.disable_ssl)
        .bind(&req.endpoint)
        .bind(&req.bucket)
        .bind(&req.domain)
        .bind(&req.region_id)
        .bind(&req.sign_name)
        .bind(&req.template_code)
        .bind(&req.app_id)
        .bind(&req.metadata)
        .bind(&req.issuer_url)
        .bind(&req.provider_url)
        .fetch_one(pool)
        .await?;

        Ok(provider.into())
    }

    /// Get a provider by name, returning the full Provider entity (includes secrets)
    pub async fn get_by_name_internal(pool: &PgPool, name: &str) -> AppResult<Provider> {
        let provider = sqlx::query_as::<_, Provider>("SELECT * FROM providers WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| {
                crate::error::AppError::NotFound(format!("Provider '{}' not found", name))
            })?;
        Ok(provider)
    }

    /// Get a provider by name, returning the public ProviderResponse
    pub async fn get_by_name(pool: &PgPool, name: &str) -> AppResult<ProviderResponse> {
        let provider = Self::get_by_name_internal(pool, name).await?;
        Ok(provider.into())
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM providers WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
