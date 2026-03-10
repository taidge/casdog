use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{CreateRuleRequest, Rule, RuleListResponse, RuleResponse, UpdateRuleRequest};

pub struct RuleService;

impl RuleService {
    pub async fn list(
        pool: &PgPool,
        owner: Option<&str>,
        include_global: bool,
        page: i64,
        page_size: i64,
    ) -> AppResult<RuleListResponse> {
        let offset = (page - 1) * page_size;

        let (rules, total) = match (owner, include_global) {
            (Some(owner), true) => {
                let rules: Vec<Rule> = sqlx::query_as(
                    r#"
                    SELECT * FROM rules
                    WHERE is_deleted = false AND (owner = $1 OR owner = 'admin')
                    ORDER BY updated_at DESC
                    LIMIT $2 OFFSET $3
                    "#,
                )
                .bind(owner)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let total: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM rules WHERE is_deleted = false AND (owner = $1 OR owner = 'admin')",
                )
                .bind(owner)
                .fetch_one(pool)
                .await?;

                (rules, total)
            }
            (Some(owner), false) => {
                let rules: Vec<Rule> = sqlx::query_as(
                    r#"
                    SELECT * FROM rules
                    WHERE owner = $1 AND is_deleted = false
                    ORDER BY updated_at DESC
                    LIMIT $2 OFFSET $3
                    "#,
                )
                .bind(owner)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let total: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM rules WHERE owner = $1 AND is_deleted = false",
                )
                .bind(owner)
                .fetch_one(pool)
                .await?;

                (rules, total)
            }
            (None, _) => {
                let rules: Vec<Rule> = sqlx::query_as(
                    r#"
                    SELECT * FROM rules
                    WHERE is_deleted = false
                    ORDER BY updated_at DESC
                    LIMIT $1 OFFSET $2
                    "#,
                )
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let total: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM rules WHERE is_deleted = false")
                        .fetch_one(pool)
                        .await?;

                (rules, total)
            }
        };

        Ok(RuleListResponse {
            data: rules.into_iter().map(Into::into).collect(),
            total,
            page,
            page_size,
        })
    }

    pub async fn get_by_id(pool: &PgPool, id: &str) -> AppResult<RuleResponse> {
        let rule: Rule = sqlx::query_as("SELECT * FROM rules WHERE id = $1 AND is_deleted = false")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| AppError::NotFound("Rule not found".to_string()))?;

        Ok(rule.into())
    }

    pub async fn create(pool: &PgPool, req: CreateRuleRequest) -> AppResult<RuleResponse> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let rule: Rule = sqlx::query_as(
            r#"
            INSERT INTO rules (
                id, owner, name, rule_type, expressions, action, status_code, reason,
                is_verbose, is_deleted, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, $10, $11)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&req.owner)
        .bind(&req.name)
        .bind(&req.rule_type)
        .bind(req.expressions.unwrap_or_else(|| serde_json::json!([])))
        .bind(req.action.unwrap_or_else(|| "Block".to_string()))
        .bind(req.status_code.unwrap_or(403))
        .bind(
            req.reason
                .unwrap_or_else(|| "Request blocked by rule".to_string()),
        )
        .bind(req.is_verbose.unwrap_or(false))
        .bind(now)
        .bind(now)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
                AppError::Conflict(format!(
                    "Rule '{} / {}' already exists",
                    req.owner, req.name
                ))
            }
            _ => AppError::Database(e),
        })?;

        Ok(rule.into())
    }

    pub async fn update(
        pool: &PgPool,
        id: &str,
        req: UpdateRuleRequest,
    ) -> AppResult<RuleResponse> {
        let mut rule: Rule =
            sqlx::query_as("SELECT * FROM rules WHERE id = $1 AND is_deleted = false")
                .bind(id)
                .fetch_optional(pool)
                .await?
                .ok_or_else(|| AppError::NotFound("Rule not found".to_string()))?;

        if let Some(v) = req.owner {
            rule.owner = v;
        }
        if let Some(v) = req.name {
            rule.name = v;
        }
        if let Some(v) = req.rule_type {
            rule.rule_type = v;
        }
        if let Some(v) = req.expressions {
            rule.expressions = v;
        }
        if let Some(v) = req.action {
            rule.action = v;
        }
        if let Some(v) = req.status_code {
            rule.status_code = v;
        }
        if let Some(v) = req.reason {
            rule.reason = v;
        }
        if let Some(v) = req.is_verbose {
            rule.is_verbose = v;
        }
        rule.updated_at = Utc::now();

        let updated: Rule = sqlx::query_as(
            r#"
            UPDATE rules SET
                owner = $1,
                name = $2,
                rule_type = $3,
                expressions = $4,
                action = $5,
                status_code = $6,
                reason = $7,
                is_verbose = $8,
                updated_at = $9
            WHERE id = $10
            RETURNING *
            "#,
        )
        .bind(&rule.owner)
        .bind(&rule.name)
        .bind(&rule.rule_type)
        .bind(&rule.expressions)
        .bind(&rule.action)
        .bind(rule.status_code)
        .bind(&rule.reason)
        .bind(rule.is_verbose)
        .bind(rule.updated_at)
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(updated.into())
    }

    pub async fn delete(pool: &PgPool, id: &str) -> AppResult<()> {
        let affected = sqlx::query(
            "UPDATE rules SET is_deleted = true, updated_at = $1 WHERE id = $2 AND is_deleted = false",
        )
        .bind(Utc::now())
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(AppError::NotFound("Rule not found".to_string()));
        }

        Ok(())
    }
}
