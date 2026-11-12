use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

use crate::error::{AppError, AppResult};
use crate::services::providers::payment_provider::{
    NotifyResult, PayRequest, PayResponse, PaymentProvider,
};

/// Stripe payment provider
pub struct StripePaymentProvider {
    client: Client,
    secret_key: String,
    webhook_secret: Option<String>,
    api_base: String,
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
    invoice: Option<serde_json::Value>,
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
            api_base: "https://api.stripe.com/v1".into(),
        }
    }

    /// Supply an HTTPS gateway or loopback transport for embedded integrations
    /// and transport regression tests. The provider factory uses Stripe's
    /// official endpoint; requests cannot override it through provider metadata.
    pub fn with_api_base(mut self, base: &str) -> AppResult<Self> {
        let parsed = reqwest::Url::parse(base)
            .map_err(|_| AppError::Config("Invalid Stripe gateway URL".into()))?;
        let loopback = parsed.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !(parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback))
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(AppError::Config(
                "Stripe gateway requires HTTPS or a loopback HTTP transport".into(),
            ));
        }
        self.api_base = parsed.as_str().trim_end_matches('/').to_owned();
        Ok(self)
    }

    /// Get Stripe API base URL
    fn get_api_url(&self) -> &str {
        &self.api_base
    }

    fn verify_signature(&self, headers: &HashMap<String, String>, body: &[u8]) -> AppResult<()> {
        let secret = self
            .webhook_secret
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                AppError::Authentication("Stripe webhook verification is not configured".into())
            })?;

        let signature_header = headers.get("stripe-signature").ok_or_else(|| {
            AppError::Authentication("Missing Stripe-Signature header".to_string())
        })?;
        let mut timestamp = None;
        let mut signatures = Vec::new();

        for part in signature_header.split(',') {
            let mut parts = part.trim().splitn(2, '=');
            let key = parts.next().unwrap_or_default().trim();
            let value = parts.next().unwrap_or_default().trim();
            match key {
                "t" => timestamp = Some(value.to_string()),
                "v1" => signatures.push(value.to_string()),
                _ => {}
            }
        }

        let timestamp = timestamp.ok_or_else(|| {
            AppError::Authentication("Invalid Stripe-Signature header".to_string())
        })?;
        let signed_at = timestamp
            .parse::<i64>()
            .map_err(|_| AppError::Authentication("Invalid Stripe signature timestamp".into()))?;
        if chrono::Utc::now().timestamp().abs_diff(signed_at) > 300 {
            return Err(AppError::Authentication(
                "Stripe webhook signature timestamp is outside the allowed window".into(),
            ));
        }

        let mut payload = Vec::with_capacity(timestamp.len() + 1 + body.len());
        payload.extend_from_slice(timestamp.as_bytes());
        payload.push(b'.');
        payload.extend_from_slice(body);

        let expected = compute_hmac_sha256_hex(secret.as_bytes(), &payload);
        if !signatures
            .iter()
            .any(|signature| bool::from(expected.as_bytes().ct_eq(signature.as_bytes())))
        {
            return Err(AppError::Authentication(
                "Stripe webhook signature verification failed".to_string(),
            ));
        }

        Ok(())
    }
}

/// Stripe charge units differ from payout units and sometimes from ISO units.
/// Source: https://docs.stripe.com/currencies#zero-decimal and #special-cases.
/// The local ledger stores hundredths. Three-decimal currencies need a separate
/// precision migration and are rejected explicitly, never guessed as cents.
fn stripe_charge_scale(currency: &str) -> AppResult<(i64, bool)> {
    if currency.len() != 3 || !currency.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(AppError::Validation(
            "Stripe currency must be a three-letter code".into(),
        ));
    }
    match currency.to_ascii_uppercase().as_str() {
        "BHD"|"IQD"|"JOD"|"KWD"|"LYD"|"OMR"|"TND"=>Err(AppError::Validation("Three-decimal Stripe currencies are not supported by the current two-decimal account ledger".into())),
        "BIF"|"CLP"|"DJF"|"GNF"|"JPY"|"KMF"|"KRW"|"MGA"|"PYG"|"RWF"|"VND"|"VUV"|"XAF"|"XOF"|"XPF"=>Ok((1,true)),
        // Both currencies require API values ending in 00, despite having no
        // fractional major units. HUF/TWD remain ordinary two-decimal charges;
        // their whole-unit restrictions apply only to payouts.
        "ISK"|"UGX"=>Ok((100,true)),
        _=>Ok((100,false)),
    }
}

fn stripe_amount_to_minor(amount: f64, currency: &str) -> AppResult<i64> {
    let (scale, whole) = stripe_charge_scale(currency)?;
    let minor = amount * scale as f64;
    if !amount.is_finite()
        || !(0.0..=9_000_000_000_000.0).contains(&amount)
        || (whole && (amount.round() - amount).abs() > 0.000001)
        || (minor.round() - minor).abs() > 0.000001
    {
        return Err(AppError::Validation(format!(
            "Amount cannot be represented exactly in Stripe {} charge units",
            currency.to_ascii_uppercase()
        )));
    }
    Ok(minor.round() as i64)
}

fn stripe_amount_from_minor(minor: i64, currency: &str) -> AppResult<f64> {
    let (scale, whole) = stripe_charge_scale(currency)?;
    if minor < 0 || (whole && minor % scale != 0) {
        return Err(AppError::Authentication(
            "Stripe notification contains an invalid fractional or negative amount".into(),
        ));
    }
    let amount = minor as f64 / scale as f64;
    if amount > 9_000_000_000_000.0 {
        return Err(AppError::Authentication(
            "Stripe notification amount exceeds the supported ledger range".into(),
        ));
    }
    Ok(amount)
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

        if req.quantity <= 0 {
            return Err(AppError::Validation(
                "Payment quantity must be positive".into(),
            ));
        }
        let unit_amount = stripe_amount_to_minor(req.price, &req.currency)?;

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
            .header("Idempotency-Key", &req.order_id)
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
            let message = format!("Stripe API failed with status {}: {}", status, body);
            return Err(if status.is_client_error() && status.as_u16() != 409 {
                AppError::Validation(message)
            } else {
                AppError::Internal(message)
            });
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

        let amount = match (
            event.data.object.amount_total,
            event.data.object.currency.as_deref(),
        ) {
            (Some(amount), Some(currency)) => Some(stripe_amount_from_minor(amount, currency)?),
            (Some(_), None) => {
                return Err(AppError::Authentication(
                    "Stripe amount requires a currency".into(),
                ));
            }
            _ => None,
        };
        Ok(NotifyResult {
            order_id: event.data.object.id,
            payment_status: payment_status.to_string(),
            payment_name: "Stripe".to_string(),
            amount,
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
        if order_id.starts_with("http://") || order_id.starts_with("https://") {
            return Ok(order_id.to_string());
        }

        if order_id.starts_with("in_") {
            return self.retrieve_invoice_url(order_id).await;
        }

        let url = format!(
            "{}/checkout/sessions/{}?expand[]=invoice",
            self.get_api_url(),
            urlencoding::encode(order_id)
        );
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.secret_key)
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
                "Stripe checkout session lookup failed with status {}: {}",
                status, body
            )));
        }

        let session: CheckoutSession = response.json().await.map_err(|e| {
            AppError::Internal(format!("Failed to parse Stripe session response: {}", e))
        })?;
        if let Some(invoice_url) = invoice_url_from_value(session.invoice.as_ref()) {
            return Ok(invoice_url);
        }
        if let Some(invoice_id) = session.invoice.as_ref().and_then(|value| value.as_str()) {
            return self.retrieve_invoice_url(invoice_id).await;
        }

        Err(AppError::NotFound(format!(
            "Stripe checkout session '{}' has no invoice",
            order_id
        )))
    }
}

impl StripePaymentProvider {
    async fn retrieve_invoice_url(&self, invoice_id: &str) -> AppResult<String> {
        let url = format!(
            "{}/invoices/{}",
            self.get_api_url(),
            urlencoding::encode(invoice_id)
        );
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.secret_key)
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
                "Stripe invoice lookup failed with status {}: {}",
                status, body
            )));
        }

        let invoice: serde_json::Value = response.json().await.map_err(|e| {
            AppError::Internal(format!("Failed to parse Stripe invoice response: {}", e))
        })?;
        invoice_url_from_value(Some(&invoice)).ok_or_else(|| {
            AppError::NotFound(format!(
                "Stripe invoice '{}' has no hosted_invoice_url or invoice_pdf",
                invoice_id
            ))
        })
    }
}

fn invoice_url_from_value(value: Option<&serde_json::Value>) -> Option<String> {
    let value = value?;
    if let Some(invoice_id) = value.as_str() {
        return Some(invoice_id.to_string()).filter(|id| id.starts_with("http"));
    }
    value
        .get("hosted_invoice_url")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("invoice_pdf").and_then(serde_json::Value::as_str))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
