use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    webhook_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PayPalProviderMetadata {
    #[serde(default, alias = "webhookId", alias = "webhook_id")]
    webhook_id: Option<String>,
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
}

#[derive(Debug, Serialize)]
struct VerifyWebhookRequest<'a> {
    auth_algo: &'a str,
    cert_url: &'a str,
    transmission_id: &'a str,
    transmission_sig: &'a str,
    transmission_time: &'a str,
    webhook_id: &'a str,
    webhook_event: &'a serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct VerifyWebhookResponse {
    verification_status: String,
}

impl PayPalPaymentProvider {
    /// Create a new PayPal payment provider
    pub fn new(
        client_id: String,
        client_secret: String,
        sandbox: String,
        metadata: Option<String>,
    ) -> Self {
        let api_base = if sandbox.to_lowercase() == "sandbox" || sandbox.to_lowercase() == "true" {
            "https://api-m.sandbox.paypal.com".to_string()
        } else {
            "https://api-m.paypal.com".to_string()
        };
        let webhook_id = metadata
            .as_deref()
            .and_then(|raw| serde_json::from_str::<PayPalProviderMetadata>(raw).ok())
            .and_then(|parsed| parsed.webhook_id);

        Self {
            client: Client::new(),
            client_id,
            client_secret,
            api_base,
            webhook_id,
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

    async fn verify_signature(
        &self,
        headers: &HashMap<String, String>,
        webhook_event: &serde_json::Value,
    ) -> AppResult<()> {
        let Some(webhook_id) = self.webhook_id.as_deref() else {
            return Ok(());
        };

        let transmission_id = headers.get("paypal-transmission-id").ok_or_else(|| {
            AppError::Authentication("Missing PayPal transmission id".to_string())
        })?;
        let transmission_time = headers.get("paypal-transmission-time").ok_or_else(|| {
            AppError::Authentication("Missing PayPal transmission time".to_string())
        })?;
        let transmission_sig = headers.get("paypal-transmission-sig").ok_or_else(|| {
            AppError::Authentication("Missing PayPal transmission signature".to_string())
        })?;
        let cert_url = headers.get("paypal-cert-url").ok_or_else(|| {
            AppError::Authentication("Missing PayPal certificate URL".to_string())
        })?;
        let auth_algo = headers
            .get("paypal-auth-algo")
            .ok_or_else(|| AppError::Authentication("Missing PayPal auth algorithm".to_string()))?;

        let access_token = self.get_access_token().await?;
        let url = format!(
            "{}/v1/notifications/verify-webhook-signature",
            self.api_base
        );
        let payload = VerifyWebhookRequest {
            auth_algo,
            cert_url,
            transmission_id,
            transmission_sig,
            transmission_time,
            webhook_id,
            webhook_event,
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(&access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "PayPal signature verification request failed: {}",
                    e
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AppError::Authentication(format!(
                "PayPal webhook verification failed with status {}: {}",
                status, body
            )));
        }

        let verification: VerifyWebhookResponse = response.json().await.map_err(|e| {
            AppError::Internal(format!(
                "Failed to parse PayPal webhook verification response: {}",
                e
            ))
        })?;
        if verification.verification_status != "SUCCESS" {
            return Err(AppError::Authentication(format!(
                "PayPal webhook verification returned '{}'",
                verification.verification_status
            )));
        }

        Ok(())
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

    async fn notify(
        &self,
        body: &[u8],
        headers: &HashMap<String, String>,
        expected_order_id: Option<&str>,
    ) -> AppResult<NotifyResult> {
        // Parse PayPal webhook event
        let event: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| AppError::Internal(format!("Failed to parse PayPal event: {}", e)))?;
        self.verify_signature(headers, &event).await?;

        // Determine payment status based on event type
        let event_type = event["event_type"].as_str().unwrap_or("");
        let payment_status = match event_type {
            "CHECKOUT.ORDER.APPROVED" => "Paid",
            "PAYMENT.CAPTURE.COMPLETED" => "Paid",
            "PAYMENT.CAPTURE.DENIED" => "Failed",
            "CHECKOUT.ORDER.VOIDED" => "Failed",
            _ => "Pending",
        };
        let provider_order_id = event["resource"]["supplementary_data"]["related_ids"]["order_id"]
            .as_str()
            .or_else(|| event["resource"]["id"].as_str())
            .unwrap_or_default()
            .to_string();
        if let Some(expected_order_id) = expected_order_id {
            let matches_expected = provider_order_id == expected_order_id
                || event["resource"]["supplementary_data"]["related_ids"]["capture_id"]
                    .as_str()
                    .map(|value| value == expected_order_id)
                    .unwrap_or(false);
            if !matches_expected {
                return Err(AppError::Authentication(
                    "PayPal webhook order reference does not match payment".to_string(),
                ));
            }
        }

        let amount = event["resource"]["amount"]["value"]
            .as_str()
            .or_else(|| event["resource"]["purchase_units"][0]["amount"]["value"].as_str())
            .and_then(|value| value.parse::<f64>().ok());
        let currency = event["resource"]["amount"]["currency_code"]
            .as_str()
            .or_else(|| event["resource"]["purchase_units"][0]["amount"]["currency_code"].as_str())
            .map(ToOwned::to_owned);

        Ok(NotifyResult {
            order_id: provider_order_id,
            payment_status: payment_status.to_string(),
            payment_name: "PayPal".to_string(),
            amount,
            currency,
            invoice_url: None,
            raw_state: Some(event_type.to_string()),
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
