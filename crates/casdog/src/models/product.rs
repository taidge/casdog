use chrono::{DateTime, Utc};
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Product {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub image: Option<String>,
    pub detail: Option<String>,
    pub currency: Option<String>,
    pub price: f64,
    pub quantity: i32,
    pub sold: i32,
    pub tag: Option<String>,
    pub state: String,
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProductRequest {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub image: Option<String>,
    pub detail: Option<String>,
    pub currency: Option<String>,
    pub price: Option<f64>,
    pub quantity: Option<i32>,
    pub tag: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProductRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub detail: Option<String>,
    pub currency: Option<String>,
    pub price: Option<f64>,
    pub quantity: Option<i32>,
    pub tag: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProductResponse {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub image: Option<String>,
    pub detail: Option<String>,
    pub currency: Option<String>,
    pub price: f64,
    pub quantity: i32,
    pub sold: i32,
    pub tag: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Product> for ProductResponse {
    fn from(p: Product) -> Self {
        Self {
            id: p.id,
            owner: p.owner,
            name: p.name,
            display_name: p.display_name,
            description: p.description,
            image: p.image,
            detail: p.detail,
            currency: p.currency,
            price: p.price,
            quantity: p.quantity,
            sold: p.sold,
            tag: p.tag,
            state: p.state,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProductListResponse {
    pub data: Vec<ProductResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}
