use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Payment {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub provider_id: Option<String>,
    pub payment_type: String,
    pub product_id: Option<String>,
    pub product_name: Option<String>,
    pub user_id: Option<String>,
    pub amount: f64,
    pub currency: Option<String>,
    pub state: String,
    pub message: Option<String>,
    pub out_order_id: Option<String>,
    pub pay_url: Option<String>,
    pub invoice_url: Option<String>,
    pub return_url: Option<String>,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePaymentRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub provider_id: Option<String>,
    pub payment_type: Option<String>,
    pub product_id: Option<String>,
    pub product_name: Option<String>,
    pub user_id: Option<String>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub state: Option<String>,
    pub message: Option<String>,
    pub out_order_id: Option<String>,
    pub pay_url: Option<String>,
    pub invoice_url: Option<String>,
    pub return_url: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePaymentRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub provider_id: Option<String>,
    pub payment_type: Option<String>,
    pub product_id: Option<String>,
    pub product_name: Option<String>,
    pub user_id: Option<String>,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub state: Option<String>,
    pub message: Option<String>,
    pub out_order_id: Option<String>,
    pub pay_url: Option<String>,
    pub invoice_url: Option<String>,
    pub return_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub provider_id: Option<String>,
    pub payment_type: String,
    pub product_id: Option<String>,
    pub product_name: Option<String>,
    pub user_id: Option<String>,
    pub amount: f64,
    pub currency: Option<String>,
    pub state: String,
    pub message: Option<String>,
    pub out_order_id: Option<String>,
    pub pay_url: Option<String>,
    pub invoice_url: Option<String>,
    pub return_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Payment> for PaymentResponse {
    fn from(p: Payment) -> Self {
        Self {
            id: p.id,
            owner: p.owner,
            name: p.name,
            display_name: p.display_name,
            description: p.description,
            provider_id: p.provider_id,
            payment_type: p.payment_type,
            product_id: p.product_id,
            product_name: p.product_name,
            user_id: p.user_id,
            amount: p.amount,
            currency: p.currency,
            state: p.state,
            message: p.message,
            out_order_id: p.out_order_id,
            pay_url: p.pay_url,
            invoice_url: p.invoice_url,
            return_url: p.return_url,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentListResponse {
    pub data: Vec<PaymentResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
