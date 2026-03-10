use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;
use crate::models::ConsentRecord;

pub struct ConsentService;

impl ConsentService {
    pub async fn grant(
        pool: &PgPool,
        user_id: &str,
        application_id: &str,
        scopes: &[String],
    ) -> AppResult<ConsentRecord> {
        let mut merged = Self::get_scopes(pool, user_id, application_id).await?;
        for scope in scopes {
            if !merged.iter().any(|existing| existing == scope) {
                merged.push(scope.clone());
            }
        }
        merged.sort();
        merged.dedup();

        let now = Utc::now();
        let record = sqlx::query_as::<_, ConsentRecord>(
            r#"
            INSERT INTO consent_records (id, user_id, application_id, granted_scopes, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $5)
            ON CONFLICT (user_id, application_id) DO UPDATE
            SET granted_scopes = EXCLUDED.granted_scopes,
                updated_at = EXCLUDED.updated_at
            RETURNING id, user_id, application_id, granted_scopes, created_at, updated_at
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(application_id)
        .bind(serde_json::json!(merged))
        .bind(now)
        .fetch_one(pool)
        .await?;

        Ok(record)
    }

    pub async fn revoke(
        pool: &PgPool,
        user_id: &str,
        application_id: &str,
        scopes: &[String],
    ) -> AppResult<Vec<String>> {
        let revoke_set: std::collections::HashSet<&str> =
            scopes.iter().map(String::as_str).collect();
        let remaining: Vec<String> = Self::get_scopes(pool, user_id, application_id)
            .await?
            .into_iter()
            .filter(|scope| !revoke_set.contains(scope.as_str()))
            .collect();

        if remaining.is_empty() {
            sqlx::query("DELETE FROM consent_records WHERE user_id = $1 AND application_id = $2")
                .bind(user_id)
                .bind(application_id)
                .execute(pool)
                .await?;
        } else {
            sqlx::query(
                "UPDATE consent_records SET granted_scopes = $1, updated_at = NOW() WHERE user_id = $2 AND application_id = $3",
            )
            .bind(serde_json::json!(remaining))
            .bind(user_id)
            .bind(application_id)
            .execute(pool)
            .await?;
        }

        Ok(remaining)
    }

    pub async fn get_scopes(
        pool: &PgPool,
        user_id: &str,
        application_id: &str,
    ) -> AppResult<Vec<String>> {
        let record = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT granted_scopes FROM consent_records WHERE user_id = $1 AND application_id = $2",
        )
        .bind(user_id)
        .bind(application_id)
        .fetch_optional(pool)
        .await?;

        Ok(record
            .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
            .unwrap_or_default())
    }
}
