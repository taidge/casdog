use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::notification_provider::NotificationProvider;
use crate::error::{AppError, AppResult};

pub struct DingTalkNotifyProvider {
    webhook_url: String,
    secret: Option<String>,
}

impl DingTalkNotifyProvider {
    pub fn new(webhook_url: String, secret: Option<String>) -> Self {
        Self {
            webhook_url,
            secret,
        }
    }

    fn signed_webhook_url(&self) -> AppResult<String> {
        let Some(secret) = self
            .secret
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(self.webhook_url.clone());
        };

        let timestamp = Utc::now().timestamp_millis().to_string();
        let string_to_sign = format!("{}\n{}", timestamp, secret);
        let sign = base64::engine::general_purpose::STANDARD.encode(compute_hmac_sha256(
            secret.as_bytes(),
            string_to_sign.as_bytes(),
        ));
        let mut url = Url::parse(&self.webhook_url)
            .map_err(|e| AppError::Internal(format!("Invalid DingTalk webhook URL: {}", e)))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("timestamp", &timestamp);
            pairs.append_pair("sign", &sign);
        }
        Ok(url.to_string())
    }
}

#[derive(Deserialize)]
struct DingTalkResponse {
    errcode: Option<i64>,
    errmsg: Option<String>,
}

#[derive(Serialize)]
struct DingTalkMessage {
    msgtype: String,
    markdown: DingTalkMarkdown,
}

#[derive(Serialize)]
struct DingTalkMarkdown {
    title: String,
    text: String,
}

fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;

    let mut key_padded = vec![0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        key_padded[..hash.len()].copy_from_slice(&hash);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = vec![0x36u8; BLOCK_SIZE];
    let mut opad = vec![0x5cu8; BLOCK_SIZE];
    for idx in 0..BLOCK_SIZE {
        ipad[idx] ^= key_padded[idx];
        opad[idx] ^= key_padded[idx];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_hash);
    outer.finalize().to_vec()
}

#[async_trait]
impl NotificationProvider for DingTalkNotifyProvider {
    async fn send(&self, title: &str, content: &str, _receiver: &str) -> AppResult<()> {
        let client = Client::new();
        let url = self.signed_webhook_url()?;

        let text = format!("## {}\n\n{}", title, content);

        let payload = DingTalkMessage {
            msgtype: "markdown".to_string(),
            markdown: DingTalkMarkdown {
                title: title.to_string(),
                text,
            },
        };

        let resp = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("DingTalk send failed: {}", e)))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(AppError::Internal(format!(
                "DingTalk webhook error ({}): {}",
                status, body
            )));
        }
        if let Ok(response) = serde_json::from_str::<DingTalkResponse>(&body) {
            if response.errcode.unwrap_or(0) != 0 {
                return Err(AppError::Internal(format!(
                    "DingTalk webhook rejected request: {}",
                    response
                        .errmsg
                        .unwrap_or_else(|| "unknown DingTalk error".to_string())
                )));
            }
        }

        Ok(())
    }

    fn provider_type(&self) -> &str {
        "DingTalk"
    }
}
