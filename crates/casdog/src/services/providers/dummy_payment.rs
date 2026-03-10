use async_trait::async_trait;
use std::collections::HashMap;

use crate::error::AppResult;
use crate::services::providers::payment_provider::{
    NotifyResult, PayRequest, PayResponse, PaymentProvider,
};

/// Dummy/test payment provider
/// Always succeeds and returns mock URLs for testing
pub struct DummyPaymentProvider {
    // No configuration needed
}

impl DummyPaymentProvider {
    /// Create a new dummy payment provider
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DummyPaymentProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PaymentProvider for DummyPaymentProvider {
    async fn pay(&self, req: &PayRequest) -> AppResult<PayResponse> {
        // Return a mock payment URL
        let pay_url = format!(
            "https://dummy-payment.example.com/pay?order_id={}&amount={}&currency={}",
            req.order_id,
            req.price * req.quantity as f64,
            req.currency
        );

        tracing::info!(
            "Dummy payment created: order_id={}, amount={} {}",
            req.order_id,
            req.price * req.quantity as f64,
            req.currency
        );

        Ok(PayResponse {
            pay_url,
            order_id: req.order_id.clone(),
        })
    }

    async fn notify(
        &self,
        _body: &[u8],
        _headers: &HashMap<String, String>,
        expected_order_id: Option<&str>,
    ) -> AppResult<NotifyResult> {
        // Always return success
        tracing::info!(
            "Dummy payment notification: order_id={}",
            expected_order_id.unwrap_or_default()
        );

        Ok(NotifyResult {
            order_id: expected_order_id.unwrap_or_default().to_string(),
            payment_status: "Paid".to_string(),
            payment_name: "Dummy".to_string(),
            amount: None,
            currency: None,
            invoice_url: None,
            raw_state: Some("paid".to_string()),
        })
    }

    async fn get_invoice(&self, order_id: &str) -> AppResult<String> {
        // Return a mock invoice
        let invoice = serde_json::json!({
            "order_id": order_id,
            "payment_method": "Dummy Payment (Test)",
            "status": "Completed",
            "amount": "0.00",
            "currency": "USD",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "note": "This is a test payment using the dummy provider"
        });

        Ok(invoice.to_string())
    }
}
