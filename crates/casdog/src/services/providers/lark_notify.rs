use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::notification_provider::NotificationProvider;
use crate::error::{AppError, AppResult};

pub struct LarkNotifyProvider {
    webhook_url: String,
    secret: Option<String>,
}

impl LarkNotifyProvider {
    pub fn new(webhook_url: String, secret: Option<String>) -> Self {
        Self {
            webhook_url,
            secret,
        }
    }

    fn signed_payload_fields(&self) -> (Option<String>, Option<String>) {
        let Some(secret) = self
            .secret
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return (None, None);
        };

        let timestamp = Utc::now().timestamp().to_string();
        let string_to_sign = format!("{}\n{}", timestamp, secret);
        let sign = base64::engine::general_purpose::STANDARD
            .encode(compute_hmac_sha256(string_to_sign.as_bytes(), b""));
        (Some(timestamp), Some(sign))
    }
}

#[derive(Deserialize)]
struct LarkResponse {
    code: Option<i64>,
    msg: Option<String>,
    #[serde(rename = "StatusCode")]
    status_code: Option<i64>,
    #[serde(rename = "StatusMessage")]
    status_message: Option<String>,
}

#[derive(Serialize)]
struct LarkMessage {
    msg_type: String,
    content: LarkContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sign: Option<String>,
}

#[derive(Serialize)]
struct LarkContent {
    post: LarkPost,
}

#[derive(Serialize)]
struct LarkPost {
    zh_cn: LarkPostContent,
}

#[derive(Serialize)]
struct LarkPostContent {
    title: String,
    content: Vec<Vec<LarkContentItem>>,
}

#[derive(Serialize)]
struct LarkContentItem {
    tag: String,
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
impl NotificationProvider for LarkNotifyProvider {
    async fn send(&self, title: &str, content: &str, _receiver: &str) -> AppResult<()> {
        let client = Client::new();

        let (timestamp, sign) = self.signed_payload_fields();

        let payload = LarkMessage {
            msg_type: "post".to_string(),
            content: LarkContent {
                post: LarkPost {
                    zh_cn: LarkPostContent {
                        title: title.to_string(),
                        content: vec![vec![LarkContentItem {
                            tag: "text".to_string(),
                            text: content.to_string(),
                        }]],
                    },
                },
            },
            timestamp,
            sign,
        };

        let resp = client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Lark send failed: {}", e)))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(AppError::Internal(format!(
                "Lark webhook error ({}): {}",
                status, body
            )));
        }
        if let Ok(response) = serde_json::from_str::<LarkResponse>(&body) {
            if response.code.unwrap_or(response.status_code.unwrap_or(0)) != 0 {
                return Err(AppError::Internal(format!(
                    "Lark webhook rejected request: {}",
                    response
                        .msg
                        .or(response.status_message)
                        .unwrap_or_else(|| "unknown Lark error".to_string())
                )));
            }
        }

        Ok(())
    }

    fn provider_type(&self) -> &str {
        "Lark"
    }
}
