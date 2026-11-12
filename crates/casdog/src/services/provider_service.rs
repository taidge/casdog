use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreateProviderRequest, Provider, ProviderResponse, UpdateProviderRequest};

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
                r#"SELECT * FROM providers ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
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

    pub async fn get_by_id_internal(pool: &PgPool, id: &str) -> AppResult<Provider> {
        let provider = sqlx::query_as::<_, Provider>("SELECT * FROM providers WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Provider '{}' not found", id)))?;
        Ok(provider)
    }

    pub async fn create(pool: &PgPool, req: CreateProviderRequest) -> AppResult<ProviderResponse> {
        let object = serde_json::to_value(req)
            .map_err(|_| AppError::Validation("Invalid provider configuration".into()))?
            .as_object()
            .cloned()
            .unwrap_or_default();
        Ok(Self::create_configuration(pool, object).await?.into())
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateProviderRequest,
    ) -> AppResult<ProviderResponse> {
        let object = serde_json::to_value(req)
            .map_err(|_| AppError::Validation("Invalid provider configuration".into()))?
            .as_object()
            .cloned()
            .unwrap_or_default();
        Ok(Self::update_configuration(pool, id, object, None)
            .await?
            .into())
    }

    pub async fn create_configuration(
        pool: &PgPool,
        mut object: serde_json::Map<String, serde_json::Value>,
    ) -> AppResult<Provider> {
        object.retain(|key, _| {
            Self::configuration_columns().contains(&key.as_str())
                || matches!(
                    key.as_str(),
                    "owner" | "name" | "display_name" | "category" | "type"
                )
        });
        crate::services::provider_configuration_service::prepare_patch(None, &mut object)?;
        for key in ["owner", "name", "display_name", "category", "type"] {
            if !object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| !s.is_empty())
            {
                return Err(AppError::Validation(
                    "Provider identity and category/type are required".into(),
                ));
            }
        }
        object.insert("id".into(), serde_json::json!(Uuid::new_v4().to_string()));
        let mut tx = pool.begin().await?;
        let columns = object.keys().map(String::as_str).collect::<Vec<_>>();
        let quoted = columns
            .iter()
            .map(|key| format!("\"{key}\""))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "INSERT INTO providers ({quoted}) SELECT {quoted} FROM jsonb_populate_record(NULL::providers,$1) RETURNING *"
        );
        let provider: Provider = sqlx::query_as(&sql)
            .bind(serde_json::Value::Object(object))
            .fetch_one(&mut *tx)
            .await?;
        crate::services::provider_configuration_service::validate(&provider)?;
        tx.commit().await?;
        Ok(provider)
    }

    /// Caller authorization and immutable owner/name are preserved. Markers and
    /// partial metadata resolve against the current row under this write lock.
    pub async fn update_configuration(
        pool: &PgPool,
        id: &str,
        mut object: serde_json::Map<String, serde_json::Value>,
        expected_owner: Option<&str>,
    ) -> AppResult<Provider> {
        object.retain(|key, _| Self::configuration_columns().contains(&key.as_str()));
        let mut tx = pool.begin().await?;
        let current: Provider = sqlx::query_as("SELECT * FROM providers WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound("Provider not found".into()))?;
        if expected_owner.is_some_and(|owner| owner != current.owner) {
            return Err(AppError::Conflict(
                "Provider ownership changed; reload before updating".into(),
            ));
        }
        crate::services::provider_configuration_service::prepare_patch(
            Some(&current),
            &mut object,
        )?;
        let columns = object.keys().map(String::as_str).collect::<Vec<_>>();
        let mut setters = columns
            .iter()
            .map(|key| format!("\"{key}\"=(jsonb_populate_record(NULL::providers,$2)).\"{key}\""))
            .collect::<Vec<_>>();
        setters.push("updated_at=clock_timestamp()".into());
        let sql = format!(
            "UPDATE providers SET {} WHERE id=$1 RETURNING *",
            setters.join(",")
        );
        let provider: Provider = sqlx::query_as(&sql)
            .bind(id)
            .bind(serde_json::Value::Object(object))
            .fetch_one(&mut *tx)
            .await?;
        crate::services::provider_configuration_service::validate(&provider)?;
        tx.commit().await?;
        Ok(provider)
    }

    fn configuration_columns() -> &'static [&'static str] {
        &[
            "display_name",
            "category",
            "type",
            "sub_type",
            "content",
            "scopes",
            "method",
            "client_id",
            "client_secret",
            "client_id2",
            "client_secret2",
            "cert",
            "custom_auth_url",
            "custom_token_url",
            "custom_user_info_url",
            "custom_logo",
            "user_mapping",
            "http_headers",
            "host",
            "port",
            "disable_ssl",
            "title",
            "receiver",
            "endpoint",
            "intranet_endpoint",
            "bucket",
            "domain",
            "path_prefix",
            "region_id",
            "sign_name",
            "template_code",
            "app_id",
            "metadata",
            "idp",
            "issuer_url",
            "enable_sign_authn_request",
            "provider_url",
        ]
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
