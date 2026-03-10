use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RuleExpression {
    pub name: Option<String>,
    pub operator: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Rule {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub rule_type: String,
    pub expressions: serde_json::Value,
    pub action: String,
    pub status_code: i32,
    pub reason: String,
    pub is_verbose: bool,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRuleRequest {
    pub owner: String,
    pub name: String,
    pub rule_type: String,
    pub expressions: Option<serde_json::Value>,
    pub action: Option<String>,
    pub status_code: Option<i32>,
    pub reason: Option<String>,
    pub is_verbose: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRuleRequest {
    pub owner: Option<String>,
    pub name: Option<String>,
    pub rule_type: Option<String>,
    pub expressions: Option<serde_json::Value>,
    pub action: Option<String>,
    pub status_code: Option<i32>,
    pub reason: Option<String>,
    pub is_verbose: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub rule_type: String,
    pub expressions: serde_json::Value,
    pub action: String,
    pub status_code: i32,
    pub reason: String,
    pub is_verbose: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Rule> for RuleResponse {
    fn from(rule: Rule) -> Self {
        Self {
            id: rule.id,
            owner: rule.owner,
            name: rule.name,
            rule_type: rule.rule_type,
            expressions: rule.expressions,
            action: rule.action,
            status_code: rule.status_code,
            reason: rule.reason,
            is_verbose: rule.is_verbose,
            created_at: rule.created_at,
            updated_at: rule.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleListResponse {
    pub data: Vec<RuleResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
