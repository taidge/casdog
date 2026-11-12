use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::Serialize;
use sqlx::{PgConnection, PgPool};

use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    models::Provider,
};

#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkApproval {
    pub provider_id: String,
    pub allow_private: bool,
    pub stale: bool,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
}

fn denied() -> AppError {
    AppError::Authorization(
        "Private provider network approval requires a current global administrator".into(),
    )
}

pub(crate) async fn administrator(conn: &mut PgConnection, actor: &Principal) -> AppResult<()> {
    if actor.is_application() || !actor.global_admin() {
        return Err(denied());
    }
    // Keep a concurrent role/account/organization revocation from racing the
    // creation of a durable network exception.
    let active: Option<String> = sqlx::query_scalar(
        "SELECT u.id FROM users u JOIN organizations o ON o.name=u.owner \
         WHERE u.id=$1 AND u.owner='built-in' AND u.is_admin AND NOT u.is_deleted \
         AND NOT u.is_forbidden AND NOT o.is_deleted AND NOT o.disable_signin \
         FOR SHARE OF u,o",
    )
    .bind(&actor.id)
    .fetch_optional(conn)
    .await?;
    active.ok_or_else(denied).map(|_| ())
}

async fn provider(conn: &mut PgConnection, id: &str, write: bool) -> AppResult<Provider> {
    let query = if write {
        "SELECT * FROM providers WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM providers WHERE id=$1 FOR SHARE"
    };
    sqlx::query_as(query)
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| AppError::NotFound("Provider not found".into()))
}

fn eligible(record: &Provider) -> AppResult<()> {
    if super::providers::http_delivery::is_custom_http(record) {
        return super::provider_configuration_service::validate(record);
    }
    if record.category.eq_ignore_ascii_case("OAuth") && record.provider_type == "OIDC" {
        let issuer = record
            .domain
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .or(record
                .issuer_url
                .as_deref()
                .filter(|v| !v.trim().is_empty()));
        if let Some(issuer) = issuer {
            let url = super::providers::oauth_provider::validate_url(issuer)?;
            if url.query().is_some() {
                return Err(AppError::Validation(
                    "OIDC issuer cannot have a query".into(),
                ));
            }
            return super::providers::oauth_provider::validate_oauth_configuration(record);
        }
    }
    if record.category.eq_ignore_ascii_case("OAuth") && record.provider_type == "Okta" {
        if ![&record.domain, &record.issuer_url, &record.custom_auth_url]
            .iter()
            .any(|value| {
                value
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
            })
        {
            return Err(AppError::Validation(
                "Configure an explicit Okta issuer before approving private network access".into(),
            ));
        }
        crate::services::providers::oauth_provider::okta_base(record)?;
        return crate::services::providers::oauth_provider::validate_oauth_configuration(record);
    }
    if !record.category.eq_ignore_ascii_case("OAuth")
        || [
            &record.custom_auth_url,
            &record.custom_token_url,
            &record.custom_user_info_url,
        ]
        .iter()
        .any(|url| url.as_deref().is_none_or(|url| url.trim().is_empty()))
    {
        return Err(AppError::Validation(
            "Private network approval requires an OAuth provider with explicit authorization, token and user-info URLs".into(),
        ));
    }
    crate::services::providers::oauth_provider::validate_oauth_configuration(record)
}

/// Durable exceptions follow the effective transport configuration, never the
/// display name or owner spelling. The existing OAuth stamp remains unchanged.
pub fn configuration_stamp(record: &Provider) -> String {
    if record.category.eq_ignore_ascii_case("OAuth") {
        return super::providers::oauth_provider::configuration_stamp(record);
    }
    let value = serde_json::json!({
        "v": 1, "id": record.id, "owner": record.owner, "name": record.name,
        "category": record.category, "type": record.provider_type,
        "endpoint": record.endpoint, "provider_url": record.provider_url,
        "client_id": record.client_id, "client_secret": record.client_secret,
        "client_id2": record.client_id2, "client_secret2": record.client_secret2,
        "method": record.method, "issuer_url": record.issuer_url,
        "user_mapping": record.user_mapping, "http_headers": record.http_headers,
        "metadata": record.metadata, "receiver": record.receiver, "title": record.title,
        "app_id": record.app_id, "sign_name": record.sign_name,
        "template_code": record.template_code,
    });
    super::system_gap_service::digest(value.to_string().as_bytes())
}

async fn status(conn: &mut PgConnection, record: &Provider) -> AppResult<NetworkApproval> {
    let approval: Option<(String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT configuration_stamp,approved_by,approved_at \
         FROM oauth_provider_network_approvals WHERE provider_id=$1",
    )
    .bind(&record.id)
    .fetch_optional(conn)
    .await?;
    let (allow_private, stale, approved_by, approved_at) = match approval {
        Some((stamp, actor, time)) => {
            let current = stamp == configuration_stamp(record);
            (current, !current, Some(actor), Some(time))
        }
        None => (false, false, None, None),
    };
    Ok(NetworkApproval {
        provider_id: record.id.clone(),
        allow_private,
        stale,
        approved_by,
        approved_at,
    })
}

/// Call after loading/locking the current provider inside the caller's login
/// transaction. Approval is never cached across callback or MFA checkpoints.
pub async fn allowed_conn(conn: &mut PgConnection, record: &Provider) -> AppResult<bool> {
    let stamp = configuration_stamp(record);
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oauth_provider_network_approvals \
         WHERE provider_id=$1 AND configuration_stamp=$2)",
    )
    .bind(&record.id)
    .bind(stamp)
    .fetch_one(conn)
    .await?)
}

pub async fn get(pool: &PgPool, actor: &Principal, id: &str) -> AppResult<NetworkApproval> {
    let mut tx = pool.begin().await?;
    administrator(&mut tx, actor).await?;
    let record = provider(&mut tx, id, false).await?;
    let result = status(&mut tx, &record).await?;
    tx.commit().await?;
    Ok(result)
}

pub async fn approve(pool: &PgPool, actor: &Principal, id: &str) -> AppResult<NetworkApproval> {
    let mut tx = pool.begin().await?;
    administrator(&mut tx, actor).await?;
    let record = provider(&mut tx, id, true).await?;
    eligible(&record)?;
    let stamp = configuration_stamp(&record);
    sqlx::query(
        "INSERT INTO oauth_provider_network_approvals(provider_id,configuration_stamp,generation,approved_by) \
         VALUES($1,$2,$3,$4) ON CONFLICT(provider_id) DO UPDATE SET \
         configuration_stamp=EXCLUDED.configuration_stamp,generation=EXCLUDED.generation,\
         approved_by=EXCLUDED.approved_by,approved_at=clock_timestamp()",
    )
    .bind(&record.id)
    .bind(stamp)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&actor.id)
    .execute(&mut *tx)
    .await?;
    let result = status(&mut tx, &record).await?;
    tx.commit().await?;
    Ok(result)
}

pub async fn revoke(pool: &PgPool, actor: &Principal, id: &str) -> AppResult<NetworkApproval> {
    let mut tx = pool.begin().await?;
    administrator(&mut tx, actor).await?;
    let record = provider(&mut tx, id, true).await?;
    sqlx::query("DELETE FROM oauth_provider_network_approvals WHERE provider_id=$1")
        .bind(&record.id)
        .execute(&mut *tx)
        .await?;
    let result = status(&mut tx, &record).await?;
    tx.commit().await?;
    Ok(result)
}
