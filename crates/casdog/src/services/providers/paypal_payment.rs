use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::services::providers::payment_provider::{
    NotifyResult, PayRequest, PayResponse, PaymentProvider,
};

/// PayPal payment provider
pub struct PayPalPaymentProvider {
    client: Client,
    client_id: String,
    client_secret: String,
    api_base: String,
}

#[derive(Debug, Serialize)]
struct CreateOrderRequest {
    intent: String,
    purchase_units: Vec<PurchaseUnit>,
    application_context: ApplicationContext,
}

#[derive(Debug, Serialize)]
struct PurchaseUnit {
    reference_id: String,
    description: String,
    amount: Amount,
}

#[derive(Debug, Serialize)]
struct Amount {
    currency_code: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct ApplicationContext {
    return_url: String,
    cancel_url: String,
}

#[derive(Debug, Deserialize)]
struct CreateOrderResponse {
    id: String,
    links: Vec<Link>,
}

#[derive(Debug, Deserialize)]
struct Link {
    href: String,
    rel: String,
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_in: u64,
}

impl PayPalPaymentProvider {
    /// Create a new PayPal payment provider
    pub fn new(client_id: String, client_secret: String, sandbox: String) -> Self {
        let api_base = if sandbox.to_lowercase() == "sandbox" || sandbox.to_lowercase() == "true" {
            "https://api-m.sandbox.paypal.com".to_string()
        } else {
            "https://api-m.paypal.com".to_string()
        };

        Self {
            client: Client::new(),
            client_id,
            client_secret,
            api_base,
        }
    }

    /// Get OAuth2 access token
    async fn get_access_token(&self) -> AppResult<String> {
        let url = format!("{}/v1/oauth2/token", self.api_base);

        let auth = format!("{}:{}", self.client_id, self.client_secret);
        let auth_encoded = general_purpose::STANDARD.encode(auth.as_bytes());

        let mut form = std::collections::HashMap::new();
        form.insert("grant_type", "client_credentials");

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Basic {}", auth_encoded))
            .form(&form)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PayPal auth request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Internal(format!(
                "PayPal auth failed with status {}: {}",
                status, body
            )));
        }

        let token_response: AccessTokenResponse = response.json().await.map_err(|e| {
            AppError::Internal(format!("Failed to parse PayPal auth response: {}", e))
        })?;

        Ok(token_response.access_token)
    }
}

#[async_trait]
impl PaymentProvider for PayPalPaymentProvider {
    async fn pay(&self, req: &PayRequest) -> AppResult<PayResponse> {
        // Get access token
        let access_token = self.get_access_token().await?;

        let url = format!("{}/v2/checkout/orders", self.api_base);

        let total_amount = req.price * req.quantity as f64;

        let order_request = CreateOrderRequest {
            intent: "CAPTURE".to_string(),
            purchase_units: vec![PurchaseUnit {
                reference_id: req.order_id.clone(),
                description: req.product_display_name.clone(),
                amount: Amount {
                    currency_code: req.currency.to_uppercase(),
                    value: format!("{:.2}", total_amount),
                },
            }],
            application_context: ApplicationContext {
                return_url: req.return_url.clone(),
                cancel_url: req.return_url.clone(),
            },
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(&access_token)
            .header("Content-Type", "application/json")
            .json(&order_request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PayPal API request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Internal(format!(
                "PayPal API failed with status {}: {}",
                status, body
            )));
        }

        let order_response: CreateOrderResponse = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse PayPal response: {}", e)))?;

        // Find the approval URL
        let approval_link = order_response
            .links
            .iter()
            .find(|link| link.rel == "approve")
            .ok_or_else(|| AppError::Internal("PayPal approval link not found".to_string()))?;

        Ok(PayResponse {
            pay_url: approval_link.href.clone(),
            order_id: order_response.id,
        })
    }

    async fn notify(&self, body: &[u8], order_id: &str) -> AppResult<NotifyResult> {
        // Parse PayPal webhook event
        let body_str = std::str::from_utf8(body)
            .map_err(|e| AppError::Internal(format!("Invalid UTF-8 in webhook body: {}", e)))?;

        let event: serde_json::Value = serde_json::from_str(body_str)
            .map_err(|e| AppError::Internal(format!("Failed to parse PayPal event: {}", e)))?;

        // Determine payment status based on event type
        let event_type = event["event_type"].as_str().unwrap_or("");
        let payment_status = match event_type {
            "CHECKOUT.ORDER.APPROVED" => "Paid",
            "PAYMENT.CAPTURE.COMPLETED" => "Paid",
            "PAYMENT.CAPTURE.DENIED" => "Failed",
            "CHECKOUT.ORDER.VOIDED" => "Failed",
            _ => "Pending",
        };

        Ok(NotifyResult {
            order_id: order_id.to_string(),
            payment_status: payment_status.to_string(),
            payment_name: "PayPal".to_string(),
        })
    }

    async fn get_invoice(&self, order_id: &str) -> AppResult<String> {
        // Get access token
        let access_token = self.get_access_token().await?;

        let url = format!("{}/v2/checkout/orders/{}", self.api_base, order_id);

        let response = self
            .client
            .get(&url)
            .bearer_auth(&access_token)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PayPal API request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Internal(format!(
                "PayPal API failed with status {}: {}",
                status, body
            )));
        }

        let order_details = response
            .text()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read PayPal response: {}", e)))?;

        Ok(order_details)
    }
}
