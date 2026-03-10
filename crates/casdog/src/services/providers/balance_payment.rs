use async_trait::async_trait;
use std::collections::HashMap;

use crate::error::AppResult;
use crate::services::providers::payment_provider::{
    NotifyResult, PayRequest, PayResponse, PaymentProvider,
};

/// Internal balance payment provider
/// This provider deducts payment from the user's internal balance
pub struct BalancePaymentProvider {
    // No external dependencies needed
}

impl BalancePaymentProvider {
    /// Create a new balance payment provider
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for BalancePaymentProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PaymentProvider for BalancePaymentProvider {
    async fn pay(&self, req: &PayRequest) -> AppResult<PayResponse> {
        // For balance payment, we don't need an external payment URL
        // The payment is handled internally by deducting from user's balance
        // We return a local confirmation URL

        // In a real implementation, you would:
        // 1. Check if user has sufficient balance
        // 2. Deduct the amount from user's balance
        // 3. Create a transaction record
        // For now, we just return a success response

        let pay_url = format!(
            "{}/payment/balance/confirm?order_id={}",
            req.return_url.trim_end_matches('/'),
            req.order_id
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
        // For balance payment, the notification is handled internally
        // We assume the payment is completed immediately
        Ok(NotifyResult {
            order_id: expected_order_id.unwrap_or_default().to_string(),
            payment_status: "Paid".to_string(),
            payment_name: "Balance".to_string(),
            amount: None,
            currency: None,
            invoice_url: None,
            raw_state: Some("paid".to_string()),
        })
    }

    async fn get_invoice(&self, order_id: &str) -> AppResult<String> {
        // Return a JSON representation of the balance transaction
        let invoice = serde_json::json!({
            "order_id": order_id,
            "payment_method": "Internal Balance",
            "status": "Completed",
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        Ok(invoice.to_string())
    }
}
