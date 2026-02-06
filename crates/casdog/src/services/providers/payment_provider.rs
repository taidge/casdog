use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

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
}

/// Trait for payment providers
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// Create a payment and return the payment URL
    async fn pay(&self, req: &PayRequest) -> AppResult<PayResponse>;

    /// Handle payment notification/webhook
    async fn notify(&self, body: &[u8], order_id: &str) -> AppResult<NotifyResult>;

    /// Get invoice/receipt for a completed payment
    async fn get_invoice(&self, order_id: &str) -> AppResult<String>;
}

/// Factory function to create payment providers
pub fn get_payment_provider(
    provider_type: &str,
    client_id: &str,
    client_secret: &str,
    host: &str,
) -> AppResult<Box<dyn PaymentProvider>> {
    match provider_type.to_lowercase().as_str() {
        "stripe" => {
            let provider =
                super::stripe_payment::StripePaymentProvider::new(client_secret.to_string());
            Ok(Box::new(provider))
        }
        "paypal" => {
            let provider = super::paypal_payment::PayPalPaymentProvider::new(
                client_id.to_string(),
                client_secret.to_string(),
                host.to_string(),
            );
            Ok(Box::new(provider))
        }
        "balance" => {
            let provider = super::balance_payment::BalancePaymentProvider::new();
            Ok(Box::new(provider))
        }
        "dummy" => {
            let provider = super::dummy_payment::DummyPaymentProvider::new();
            Ok(Box::new(provider))
        }
        _ => Err(AppError::Config(format!(
            "Unsupported payment provider type: {}",
            provider_type
        ))),
    }
}
