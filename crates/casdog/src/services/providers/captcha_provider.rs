use async_trait::async_trait;

use crate::error::{AppError, AppResult};

/// Trait for CAPTCHA verification providers
#[async_trait]
pub trait CaptchaProviderTrait: Send + Sync {
    async fn verify(&self, token: &str, remote_ip: Option<&str>) -> AppResult<bool>;
}

/// Google reCAPTCHA v2/v3 provider
pub struct ReCaptchaProvider {
    secret_key: String,
}

impl ReCaptchaProvider {
    pub fn new(secret_key: String) -> Self {
        Self { secret_key }
    }
}

#[async_trait]
impl CaptchaProviderTrait for ReCaptchaProvider {
    async fn verify(&self, token: &str, remote_ip: Option<&str>) -> AppResult<bool> {
        let client = reqwest::Client::new();
        let mut params = vec![("secret", self.secret_key.as_str()), ("response", token)];
        if let Some(ip) = remote_ip {
            params.push(("remoteip", ip));
        }

        let resp = client
            .post("https://www.google.com/recaptcha/api/siteverify")
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("reCAPTCHA verification failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("reCAPTCHA parse failed: {}", e)))?;

        Ok(json["success"].as_bool().unwrap_or(false))
    }
}

/// hCaptcha provider
pub struct HCaptchaProvider {
    secret_key: String,
}

impl HCaptchaProvider {
    pub fn new(secret_key: String) -> Self {
        Self { secret_key }
    }
}

#[async_trait]
impl CaptchaProviderTrait for HCaptchaProvider {
    async fn verify(&self, token: &str, remote_ip: Option<&str>) -> AppResult<bool> {
        let client = reqwest::Client::new();
        let mut params = vec![("secret", self.secret_key.as_str()), ("response", token)];
        if let Some(ip) = remote_ip {
            params.push(("remoteip", ip));
        }

        let resp = client
            .post("https://hcaptcha.com/siteverify")
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("hCaptcha verification failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("hCaptcha parse failed: {}", e)))?;

        Ok(json["success"].as_bool().unwrap_or(false))
    }
}

/// Cloudflare Turnstile provider
pub struct TurnstileProvider {
    secret_key: String,
}

impl TurnstileProvider {
    pub fn new(secret_key: String) -> Self {
        Self { secret_key }
    }
}

#[async_trait]
impl CaptchaProviderTrait for TurnstileProvider {
    async fn verify(&self, token: &str, remote_ip: Option<&str>) -> AppResult<bool> {
        let client = reqwest::Client::new();
        let mut body = serde_json::json!({
            "secret": self.secret_key,
            "response": token,
        });
        if let Some(ip) = remote_ip {
            body["remoteip"] = serde_json::Value::String(ip.to_string());
        }

        let resp = client
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Turnstile verification failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Turnstile parse failed: {}", e)))?;

        Ok(json["success"].as_bool().unwrap_or(false))
    }
}

/// Factory to create a captcha provider from provider record
pub fn create_captcha_provider(sub_type: &str, secret_key: &str) -> Box<dyn CaptchaProviderTrait> {
    match sub_type {
        "reCAPTCHA" | "recaptcha" => Box::new(ReCaptchaProvider::new(secret_key.to_string())),
        "hCaptcha" | "hcaptcha" => Box::new(HCaptchaProvider::new(secret_key.to_string())),
        "Turnstile" | "turnstile" | "Cloudflare Turnstile" => {
            Box::new(TurnstileProvider::new(secret_key.to_string()))
        }
        _ => Box::new(ReCaptchaProvider::new(secret_key.to_string())),
    }
}
