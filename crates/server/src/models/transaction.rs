use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Transaction {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub provider_id: Option<String>,
    pub category: Option<String>,
    pub transaction_type: String,
    pub product_id: Option<String>,
    pub user_id: Option<String>,
    pub application: Option<String>,
    pub amount: f64,
    pub currency: Option<String>,
    pub balance: f64,
    pub state: String,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTransactionRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub provider_id: Option<String>,
    pub category: Option<String>,
    pub transaction_type: Option<String>,
    pub product_id: Option<String>,
    pub user_id: Option<String>,
    pub application: Option<String>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub balance: Option<f64>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTransactionRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub provider_id: Option<String>,
    pub category: Option<String>,
    pub transaction_type: Option<String>,
    pub product_id: Option<String>,
    pub user_id: Option<String>,
    pub application: Option<String>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub balance: Option<f64>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TransactionResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub provider_id: Option<String>,
    pub category: Option<String>,
    pub transaction_type: String,
    pub product_id: Option<String>,
    pub user_id: Option<String>,
    pub application: Option<String>,
    pub amount: f64,
    pub currency: Option<String>,
    pub balance: f64,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Transaction> for TransactionResponse {
    fn from(t: Transaction) -> Self {
        Self {
            id: t.id,
            owner: t.owner,
            name: t.name,
            display_name: t.display_name,
            description: t.description,
            provider_id: t.provider_id,
            category: t.category,
            transaction_type: t.transaction_type,
            product_id: t.product_id,
            user_id: t.user_id,
            application: t.application,
            amount: t.amount,
            currency: t.currency,
            balance: t.balance,
            state: t.state,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TransactionListResponse {
    pub data: Vec<TransactionResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
