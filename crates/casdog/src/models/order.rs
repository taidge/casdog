use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Order {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub provider: Option<String>,
    pub product_name: Option<String>,
    pub product_display_name: Option<String>,
    pub quantity: i32,
    pub price: f64,
    pub currency: Option<String>,
    pub state: String,
    pub tag: Option<String>,
    pub invoice_url: Option<String>,
    pub payment_id: Option<String>,
    pub payment_name: Option<String>,
    pub return_url: Option<String>,
    pub user: Option<String>,
    pub plan_name: Option<String>,
    pub pricing_name: Option<String>,
    pub error_text: Option<String>,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOrderRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub provider: Option<String>,
    pub product_name: Option<String>,
    pub product_display_name: Option<String>,
    pub quantity: Option<i32>,
    pub price: Option<f64>,
    pub currency: Option<String>,
    pub state: Option<String>,
    pub tag: Option<String>,
    pub invoice_url: Option<String>,
    pub payment_id: Option<String>,
    pub payment_name: Option<String>,
    pub return_url: Option<String>,
    pub user: Option<String>,
    pub plan_name: Option<String>,
    pub pricing_name: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOrderRequest {
    pub display_name: Option<String>,
    pub provider: Option<String>,
    pub product_name: Option<String>,
    pub product_display_name: Option<String>,
    pub quantity: Option<i32>,
    pub price: Option<f64>,
    pub currency: Option<String>,
    pub state: Option<String>,
    pub tag: Option<String>,
    pub invoice_url: Option<String>,
    pub payment_id: Option<String>,
    pub payment_name: Option<String>,
    pub return_url: Option<String>,
    pub user: Option<String>,
    pub plan_name: Option<String>,
    pub pricing_name: Option<String>,
    pub error_text: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrderResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub provider: Option<String>,
    pub product_name: Option<String>,
    pub product_display_name: Option<String>,
    pub quantity: i32,
    pub price: f64,
    pub currency: Option<String>,
    pub state: String,
    pub tag: Option<String>,
    pub invoice_url: Option<String>,
    pub payment_id: Option<String>,
    pub payment_name: Option<String>,
    pub return_url: Option<String>,
    pub user: Option<String>,
    pub plan_name: Option<String>,
    pub pricing_name: Option<String>,
    pub error_text: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Order> for OrderResponse {
    fn from(o: Order) -> Self {
        Self {
            id: o.id,
            owner: o.owner,
            name: o.name,
            display_name: o.display_name,
            provider: o.provider,
            product_name: o.product_name,
            product_display_name: o.product_display_name,
            quantity: o.quantity,
            price: o.price,
            currency: o.currency,
            state: o.state,
            tag: o.tag,
            invoice_url: o.invoice_url,
            payment_id: o.payment_id,
            payment_name: o.payment_name,
            return_url: o.return_url,
            user: o.user,
            plan_name: o.plan_name,
            pricing_name: o.pricing_name,
            error_text: o.error_text,
            created_at: o.created_at,
            updated_at: o.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrderListResponse {
    pub data: Vec<OrderResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
