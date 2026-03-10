use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{AppError, AppResult};
use crate::models::Provider;

/// Request structure for payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayRequest {
    pub product_name: String,
    pub product_display_name: String,
    pub provider_name: String,
    pub price: f64,
    pub currency: String,
    pub quantity: i32,
    pub return_url: String,
    pub order_id: String,
    pub payer_name: Option<String>,
    pub payer_email: Option<String>,
}

/// Response structure for payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayResponse {
    pub pay_url: String,
    pub order_id: String,
}

/// Result structure for payment notification/webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyResult {
    pub order_id: String,
    pub payment_status: String, // "Paid", "Failed", "Pending"
    pub payment_name: String,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub invoice_url: Option<String>,
    pub raw_state: Option<String>,
}

/// Trait for payment providers
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// Create a payment and return the payment URL
    async fn pay(&self, req: &PayRequest) -> AppResult<PayResponse>;

    /// Handle payment notification/webhook
    async fn notify(
        &self,
        body: &[u8],
        headers: &HashMap<String, String>,
        expected_order_id: Option<&str>,
    ) -> AppResult<NotifyResult>;

    /// Get invoice/receipt for a completed payment
    async fn get_invoice(&self, order_id: &str) -> AppResult<String>;
}

/// Factory function to create payment providers
pub fn build_payment_provider(provider: &Provider) -> AppResult<Box<dyn PaymentProvider>> {
    let provider_type = provider
        .provider_type
        .chars()
        .filter(|ch| !matches!(ch, ' ' | '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect::<String>();

    match provider_type.as_str() {
        "stripe" => Ok(Box::new(super::stripe_payment::StripePaymentProvider::new(
            provider.client_secret.clone().ok_or_else(|| {
                AppError::Config("Stripe provider client_secret is required".to_string())
            })?,
            provider.metadata.clone(),
        ))),
        "paypal" => Ok(Box::new(super::paypal_payment::PayPalPaymentProvider::new(
            provider.client_id.clone().ok_or_else(|| {
                AppError::Config("PayPal provider client_id is required".to_string())
            })?,
            provider.client_secret.clone().ok_or_else(|| {
                AppError::Config("PayPal provider client_secret is required".to_string())
            })?,
            provider
                .host
                .clone()
                .unwrap_or_else(|| "sandbox".to_string()),
            provider.metadata.clone(),
        ))),
        "balance" => Ok(Box::new(
            super::balance_payment::BalancePaymentProvider::new(),
        )),
        "dummy" => Ok(Box::new(super::dummy_payment::DummyPaymentProvider::new())),
        _ => Err(AppError::Config(format!(
            "Unsupported payment provider type: {}",
            provider.provider_type
        ))),
    }
}
