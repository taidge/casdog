use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{AppError, AppResult};
use crate::services::providers::payment_provider::{
    NotifyResult, PayRequest, PayResponse, PaymentProvider, RemotePayment, validate_checkout_url,
};

// PayPal uses major-unit decimal strings. JPY, HUF and TWD do not accept
// decimals: https://developer.paypal.com/api/codes/currency .
fn paypal_format_amount(amount: f64, currency: &str) -> AppResult<String> {
    let currency = currency.to_ascii_uppercase();
    if !matches!(
        currency.as_str(),
        "AUD"
            | "BRL"
            | "CAD"
            | "CNY"
            | "CZK"
            | "DKK"
            | "EUR"
            | "HKD"
            | "HUF"
            | "ILS"
            | "JPY"
            | "MYR"
            | "MXN"
            | "TWD"
            | "NZD"
            | "NOK"
            | "PHP"
            | "PLN"
            | "GBP"
            | "RUB"
            | "SGD"
            | "SEK"
            | "CHF"
            | "THB"
            | "USD"
    ) {
        return Err(AppError::Validation(
            "Currency is not supported by PayPal checkout".into(),
        ));
    }
    crate::services::ProductService::validate_price(amount, true)?;
    if matches!(currency.as_str(), "JPY" | "HUF" | "TWD") {
        if amount.fract() != 0.0 {
            return Err(AppError::Validation(
                "PayPal requires a whole-unit amount for this currency".into(),
            ));
        }
        Ok(format!("{amount:.0}"))
    } else {
        Ok(format!("{amount:.2}"))
    }
}

fn paypal_parse_amount(value: &str, currency: &str) -> AppResult<f64> {
    if value.is_empty()
        || value.len() > 32
        || !value.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return Err(AppError::Authentication(
            "PayPal returned an invalid monetary value".into(),
        ));
    }
    let amount = value
        .parse::<f64>()
        .map_err(|_| AppError::Authentication("PayPal returned an invalid amount".into()))?;
    paypal_format_amount(amount, currency)?;
    Ok(amount)
}

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
    custom_id: String,
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
    pub fn with_api_base(mut self, base: &str) -> AppResult<Self> {
        let url = reqwest::Url::parse(base)
            .map_err(|_| AppError::Config("Invalid PayPal gateway".into()))?;
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(AppError::Config(
                "PayPal gateway requires HTTPS or loopback HTTP".into(),
            ));
        }
        self.api_base = url.as_str().trim_end_matches('/').to_owned();
        Ok(self)
    }

    fn remote_order(
        order: &serde_json::Value,
        external_id: &str,
        local_id: &str,
    ) -> AppResult<RemotePayment> {
        if order["id"].as_str() != Some(external_id)
            || order["intent"].as_str().is_some_and(|s| s != "CAPTURE")
        {
            return Err(AppError::Authentication(
                "PayPal order reference or intent does not match checkout".into(),
            ));
        }
        let units = order["purchase_units"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or_else(|| {
                AppError::Authentication("PayPal checkout must contain one purchase unit".into())
            })?;
        let unit = &units[0];
        if unit["custom_id"]
            .as_str()
            .or_else(|| unit["reference_id"].as_str())
            != Some(local_id)
        {
            return Err(AppError::Authentication(
                "PayPal order belongs to another payment".into(),
            ));
        }
        let state = order["status"].as_str().unwrap_or("");
        let money = if state == "COMPLETED" {
            let captures = unit["payments"]["captures"]
                .as_array()
                .filter(|v| v.len() == 1)
                .ok_or_else(|| {
                    AppError::Authentication(
                        "PayPal capture details are required to confirm settlement".into(),
                    )
                })?;
            let capture = &captures[0];
            if capture["status"].as_str() != Some("COMPLETED") || capture["final_capture"] == false
            {
                return Ok(RemotePayment {
                    result: NotifyResult {
                        order_id: external_id.into(),
                        payment_status: "Pending".into(),
                        payment_name: "PayPal".into(),
                        amount: None,
                        currency: None,
                        invoice_url: None,
                        raw_state: Some("CAPTURE_PENDING".into()),
                    },
                    pay_url: None,
                    capture_required: false,
                });
            }
            &capture["amount"]
        } else {
            &unit["amount"]
        };
        let currency = money["currency_code"]
            .as_str()
            .ok_or_else(|| AppError::Authentication("PayPal currency is missing".into()))?
            .to_ascii_uppercase();
        let value = money["value"]
            .as_str()
            .ok_or_else(|| AppError::Authentication("PayPal amount is missing".into()))?;
        let amount = paypal_parse_amount(value, &currency)?;
        let status = match state {
            "COMPLETED" => "Paid",
            "VOIDED" => "Canceled",
            "EXPIRED" => "Timeout",
            _ => "Pending",
        };
        let pay_url = order["links"]
            .as_array()
            .and_then(|links| {
                links
                    .iter()
                    .find(|link| matches!(link["rel"].as_str(), Some("approve" | "payer-action")))
            })
            .and_then(|link| link["href"].as_str())
            .map(str::to_owned);
        if let Some(url) = pay_url.as_deref() {
            validate_checkout_url("paypal", url)?;
        }
        Ok(RemotePayment {
            result: NotifyResult {
                order_id: external_id.into(),
                payment_status: status.into(),
                payment_name: "PayPal".into(),
                amount: Some(amount),
                currency: Some(currency),
                invoice_url: None,
                raw_state: Some(state.into()),
            },
            pay_url,
            capture_required: state == "APPROVED",
        })
    }

    async fn order_request(
        &self,
        external_id: &str,
        local_id: &str,
        capture_key: Option<&str>,
    ) -> AppResult<RemotePayment> {
        if external_id.is_empty()
            || external_id.len() > 36
            || !external_id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return Err(AppError::Conflict(
                "A confirmed PayPal order reference is required".into(),
            ));
        }
        let token = self.get_access_token().await?;
        let url = format!(
            "{}/v2/checkout/orders/{}{}",
            self.api_base,
            external_id,
            if capture_key.is_some() {
                "/capture"
            } else {
                ""
            }
        );
        let request = if let Some(key) = capture_key {
            self.client
                .post(url)
                .header("PayPal-Request-Id", key)
                .header("Prefer", "return=representation")
                .json(&serde_json::json!({}))
        } else {
            self.client.get(url)
        };
        let response = request
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PayPal order request failed: {e}")))?;
        if !response.status().is_success() {
            return Err(AppError::Conflict(format!(
                "PayPal order state could not be confirmed ({})",
                response.status()
            )));
        }
        let order: serde_json::Value = response
            .json()
            .await
            .map_err(|_| AppError::Authentication("Invalid PayPal order response".into()))?;
        Self::remote_order(&order, external_id, local_id)
    }
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
        let webhook_id = self
            .webhook_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                AppError::Authentication("PayPal webhook verification is not configured".into())
            })?;

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
    async fn query_payment(&self, external_id: &str, local_id: &str) -> AppResult<RemotePayment> {
        self.order_request(external_id, local_id, None).await
    }

    async fn capture_payment(
        &self,
        external_id: &str,
        local_id: &str,
        request_id: &str,
    ) -> AppResult<RemotePayment> {
        self.order_request(external_id, local_id, Some(request_id))
            .await
    }
    async fn pay(&self, req: &PayRequest) -> AppResult<PayResponse> {
        let total_amount = req.price * req.quantity as f64;
        if req.quantity <= 0 {
            return Err(AppError::Validation(
                "Payment quantity must be positive".into(),
            ));
        }
        let formatted = paypal_format_amount(total_amount, &req.currency)?;
        let access_token = self.get_access_token().await?;
        let url = format!("{}/v2/checkout/orders", self.api_base);

        let order_request = CreateOrderRequest {
            intent: "CAPTURE".to_string(),
            purchase_units: vec![PurchaseUnit {
                reference_id: req.order_id.clone(),
                custom_id: req.order_id.clone(),
                description: req.product_display_name.clone(),
                amount: Amount {
                    currency_code: req.currency.to_uppercase(),
                    value: formatted,
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
            .header("PayPal-Request-Id", &req.order_id)
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
            let message = format!("PayPal API failed with status {}: {}", status, body);
            return Err(if status.is_client_error() && status.as_u16() != 409 {
                AppError::Validation(message)
            } else {
                AppError::Internal(message)
            });
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
        validate_checkout_url("paypal", &approval_link.href)?;

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
            // Approval authorizes a future capture; funds have not settled yet.
            "CHECKOUT.ORDER.APPROVED" => "Pending",
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
