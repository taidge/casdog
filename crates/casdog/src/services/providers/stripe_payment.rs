use crate::error::{AppError, AppResult};
use crate::services::providers::payment_provider::{
    NotifyResult, PayRequest, PayResponse, PaymentProvider,
};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Stripe payment provider
pub struct StripePaymentProvider {
    client: Client,
    secret_key: String,
}

#[derive(Debug, Serialize)]
struct CreateCheckoutSessionRequest {
    payment_method_types: Vec<String>,
    line_items: Vec<LineItem>,
    mode: String,
    success_url: String,
    cancel_url: String,
    client_reference_id: String,
    customer_email: Option<String>,
}

#[derive(Debug, Serialize)]
struct LineItem {
    price_data: PriceData,
    quantity: i32,
}

#[derive(Debug, Serialize)]
struct PriceData {
    currency: String,
    product_data: ProductData,
    unit_amount: i64, // Amount in cents
}

#[derive(Debug, Serialize)]
struct ProductData {
    name: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CheckoutSession {
    id: String,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StripeEvent {
    #[serde(rename = "type")]
    event_type: String,
    data: StripeEventData,
}

#[derive(Debug, Deserialize)]
struct StripeEventData {
    object: serde_json::Value,
}

impl StripePaymentProvider {
    /// Create a new Stripe payment provider
    pub fn new(secret_key: String) -> Self {
        Self {
            client: Client::new(),
            secret_key,
        }
    }

    /// Get Stripe API base URL
    fn get_api_url(&self) -> &str {
        "https://api.stripe.com/v1"
    }
}

#[async_trait]
impl PaymentProvider for StripePaymentProvider {
    async fn pay(&self, req: &PayRequest) -> AppResult<PayResponse> {
        let url = format!("{}/checkout/sessions", self.get_api_url());

        // Convert price to cents
        let unit_amount = (req.price * 100.0) as i64;

        let session_data = CreateCheckoutSessionRequest {
            payment_method_types: vec!["card".to_string()],
            line_items: vec![LineItem {
                price_data: PriceData {
                    currency: req.currency.to_lowercase(),
                    product_data: ProductData {
                        name: req.product_display_name.clone(),
                        description: Some(req.product_name.clone()),
                    },
                    unit_amount,
                },
                quantity: req.quantity,
            }],
            mode: "payment".to_string(),
            success_url: req.return_url.clone(),
            cancel_url: req.return_url.clone(),
            client_reference_id: req.order_id.clone(),
            customer_email: req.payer_email.clone(),
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.secret_key)
            .form(&session_data)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Stripe API request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Internal(format!(
                "Stripe API failed with status {}: {}",
                status, body
            )));
        }

        let session: CheckoutSession = response.json().await.map_err(|e| {
            AppError::Internal(format!("Failed to parse Stripe response: {}", e))
        })?;

        let pay_url = session
            .url
            .ok_or_else(|| AppError::Internal("Stripe session URL not found".to_string()))?;

        Ok(PayResponse {
            pay_url,
            order_id: req.order_id.clone(),
        })
    }

    async fn notify(&self, body: &[u8], order_id: &str) -> AppResult<NotifyResult> {
        // Parse Stripe webhook event
        let body_str = std::str::from_utf8(body)
            .map_err(|e| AppError::Internal(format!("Invalid UTF-8 in webhook body: {}", e)))?;

        let event: StripeEvent = serde_json::from_str(body_str)
            .map_err(|e| AppError::Internal(format!("Failed to parse Stripe event: {}", e)))?;

        // Determine payment status based on event type
        let payment_status = match event.event_type.as_str() {
            "checkout.session.completed" => "Paid",
            "checkout.session.expired" => "Failed",
            "checkout.session.async_payment_succeeded" => "Paid",
            "checkout.session.async_payment_failed" => "Failed",
            _ => "Pending",
        };

        Ok(NotifyResult {
            order_id: order_id.to_string(),
            payment_status: payment_status.to_string(),
            payment_name: "Stripe".to_string(),
        })
    }

    async fn get_invoice(&self, order_id: &str) -> AppResult<String> {
        // In a real implementation, you would fetch the invoice from Stripe
        // For now, return a placeholder URL
        Ok(format!(
            "https://dashboard.stripe.com/invoices/{}",
            order_id
        ))
    }
}
