use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::error::{AppError, AppResult};
use crate::services::providers::payment_provider::{
    NotifyResult, PayRequest, PayResponse, PaymentProvider,
};

/// Stripe payment provider
pub struct StripePaymentProvider {
    client: Client,
    secret_key: String,
    webhook_secret: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct StripeProviderMetadata {
    #[serde(
        default,
        alias = "webhookSecret",
        alias = "webhook_secret",
        alias = "signingSecret",
        alias = "signing_secret"
    )]
    webhook_secret: Option<String>,
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
    object: StripeCheckoutSessionObject,
}

#[derive(Debug, Deserialize)]
struct StripeCheckoutSessionObject {
    id: String,
    client_reference_id: Option<String>,
    amount_total: Option<i64>,
    currency: Option<String>,
    payment_status: Option<String>,
    status: Option<String>,
    invoice: Option<String>,
}

impl StripePaymentProvider {
    /// Create a new Stripe payment provider
    pub fn new(secret_key: String, metadata: Option<String>) -> Self {
        let webhook_secret = metadata
            .as_deref()
            .and_then(|raw| serde_json::from_str::<StripeProviderMetadata>(raw).ok())
            .and_then(|parsed| parsed.webhook_secret);
        Self {
            client: Client::new(),
            secret_key,
            webhook_secret,
        }
    }

    /// Get Stripe API base URL
    fn get_api_url(&self) -> &str {
        "https://api.stripe.com/v1"
    }

    fn verify_signature(&self, headers: &HashMap<String, String>, body: &[u8]) -> AppResult<()> {
        let Some(secret) = self.webhook_secret.as_deref() else {
            return Ok(());
        };

        let signature_header = headers.get("stripe-signature").ok_or_else(|| {
            AppError::Authentication("Missing Stripe-Signature header".to_string())
        })?;
        let mut timestamp = None;
        let mut signature = None;

        for part in signature_header.split(',') {
            let mut parts = part.trim().splitn(2, '=');
            let key = parts.next().unwrap_or_default().trim();
            let value = parts.next().unwrap_or_default().trim();
            match key {
                "t" => timestamp = Some(value.to_string()),
                "v1" => signature = Some(value.to_string()),
                _ => {}
            }
        }

        let timestamp = timestamp.ok_or_else(|| {
            AppError::Authentication("Invalid Stripe-Signature header".to_string())
        })?;
        let signature = signature.ok_or_else(|| {
            AppError::Authentication("Invalid Stripe-Signature header".to_string())
        })?;

        let mut payload = Vec::with_capacity(timestamp.len() + 1 + body.len());
        payload.extend_from_slice(timestamp.as_bytes());
        payload.push(b'.');
        payload.extend_from_slice(body);

        let expected = compute_hmac_sha256_hex(secret.as_bytes(), &payload);
        if expected != signature {
            return Err(AppError::Authentication(
                "Stripe webhook signature verification failed".to_string(),
            ));
        }

        Ok(())
    }
}

fn compute_hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;
    let mut normalized_key = if key.len() > BLOCK_SIZE {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    normalized_key.resize(BLOCK_SIZE, 0);

    let mut inner_key_pad = vec![0x36; BLOCK_SIZE];
    let mut outer_key_pad = vec![0x5c; BLOCK_SIZE];
    for (index, key_byte) in normalized_key.iter().enumerate() {
        inner_key_pad[index] ^= key_byte;
        outer_key_pad[index] ^= key_byte;
    }

    let mut inner = Sha256::new();
    inner.update(&inner_key_pad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_key_pad);
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

#[async_trait]
impl PaymentProvider for StripePaymentProvider {
    async fn pay(&self, req: &PayRequest) -> AppResult<PayResponse> {
        let url = format!("{}/checkout/sessions", self.get_api_url());

        // Convert price to cents
        let unit_amount = (req.price * 100.0) as i64;

        let mut params = vec![
            ("payment_method_types[0]".to_string(), "card".to_string()),
            (
                "line_items[0][price_data][currency]".to_string(),
                req.currency.to_lowercase(),
            ),
            (
                "line_items[0][price_data][product_data][name]".to_string(),
                req.product_display_name.clone(),
            ),
            (
                "line_items[0][price_data][product_data][description]".to_string(),
                req.product_name.clone(),
            ),
            (
                "line_items[0][price_data][unit_amount]".to_string(),
                unit_amount.to_string(),
            ),
            (
                "line_items[0][quantity]".to_string(),
                req.quantity.to_string(),
            ),
            ("mode".to_string(), "payment".to_string()),
            ("success_url".to_string(), req.return_url.clone()),
            ("cancel_url".to_string(), req.return_url.clone()),
            ("client_reference_id".to_string(), req.order_id.clone()),
            ("metadata[order_id]".to_string(), req.order_id.clone()),
        ];
        if let Some(email) = req.payer_email.as_ref().filter(|value| !value.is_empty()) {
            params.push(("customer_email".to_string(), email.clone()));
        }

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.secret_key)
            .form(&params)
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

        let session: CheckoutSession = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse Stripe response: {}", e)))?;

        let pay_url = session
            .url
            .ok_or_else(|| AppError::Internal("Stripe session URL not found".to_string()))?;

        Ok(PayResponse {
            pay_url,
            order_id: session.id,
        })
    }

    async fn notify(
        &self,
        body: &[u8],
        headers: &HashMap<String, String>,
        expected_order_id: Option<&str>,
    ) -> AppResult<NotifyResult> {
        self.verify_signature(headers, body)?;

        // Parse Stripe webhook event
        let event: StripeEvent = serde_json::from_slice(body)
            .map_err(|e| AppError::Internal(format!("Failed to parse Stripe event: {}", e)))?;
        if let Some(expected_order_id) = expected_order_id {
            let matches_expected = event.data.object.id == expected_order_id
                || event
                    .data
                    .object
                    .client_reference_id
                    .as_deref()
                    .map(|value| value == expected_order_id)
                    .unwrap_or(false);
            if !matches_expected {
                return Err(AppError::Authentication(
                    "Stripe webhook order reference does not match payment".to_string(),
                ));
            }
        }

        // Determine payment status based on event type
        let payment_status = match event.event_type.as_str() {
            "checkout.session.completed"
                if event.data.object.payment_status.as_deref() == Some("paid") =>
            {
                "Paid"
            }
            "checkout.session.expired" => "Failed",
            "checkout.session.async_payment_succeeded" => "Paid",
            "checkout.session.async_payment_failed" => "Failed",
            _ => "Pending",
        };

        Ok(NotifyResult {
            order_id: event.data.object.id,
            payment_status: payment_status.to_string(),
            payment_name: "Stripe".to_string(),
            amount: event
                .data
                .object
                .amount_total
                .map(|value| value as f64 / 100.0),
            currency: event.data.object.currency.map(|value| value.to_uppercase()),
            invoice_url: event.data.object.invoice,
            raw_state: event
                .data
                .object
                .payment_status
                .or(event.data.object.status)
                .or(Some(event.event_type)),
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
