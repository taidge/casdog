use std::collections::HashMap;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use crate::error::{AppError, AppResult};

pub struct TelegramProvider {
    bot_token: String,
}

impl TelegramProvider {
    pub fn new(bot_token: String, _secret: String) -> Self {
        Self { bot_token }
    }
}

#[async_trait]
impl OAuthProviderTrait for TelegramProvider {
    fn get_auth_url(&self, redirect_uri: &str, _state: &str, _scope: Option<&str>) -> String {
        // Telegram Login Widget doesn't have a standard OAuth URL
        // This returns a placeholder that should be replaced with the widget HTML
        format!(
            "https://oauth.telegram.org/auth?bot_id={}&origin={}&return_to={}",
            self.bot_token.split(':').next().unwrap_or(""),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(redirect_uri),
        )
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> AppResult<String> {
        verify_telegram_auth_data(code, &self.bot_token)?;
        Ok(code.to_string())
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let params = parse_telegram_auth_data(access_token)?;
        verify_telegram_params(&params, &self.bot_token)?;
        let id = params
            .get("id")
            .ok_or_else(|| AppError::Internal("No id in Telegram auth data".to_string()))?;
        let username = params.get("username").cloned();
        let first_name = params.get("first_name").cloned().unwrap_or_default();
        let last_name = params.get("last_name").cloned().unwrap_or_default();
        let photo_url = params.get("photo_url").cloned();

        let display_name = if !last_name.is_empty() {
            format!("{} {}", first_name, last_name)
        } else {
            first_name
        };

        Ok(ProviderUserInfo {
            id: id.clone(),
            username: username.unwrap_or(id.clone()),
            display_name,
            email: None, // Telegram doesn't provide email
            avatar_url: photo_url,
            provider_type: "Telegram".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Telegram"
    }
}

fn parse_telegram_auth_data(raw: &str) -> AppResult<HashMap<String, String>> {
    let mut params = HashMap::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let mut parts = pair.splitn(2, '=');
        let key = parts
            .next()
            .ok_or_else(|| AppError::Validation("Invalid Telegram auth data".to_string()))?;
        let value = parts.next().unwrap_or_default();
        let key = urlencoding::decode(key)
            .map_err(|e| AppError::Validation(format!("Invalid Telegram auth key: {}", e)))?
            .into_owned();
        let value = urlencoding::decode(value)
            .map_err(|e| AppError::Validation(format!("Invalid Telegram auth value: {}", e)))?
            .into_owned();
        params.insert(key, value);
    }
    Ok(params)
}

fn verify_telegram_auth_data(raw: &str, bot_token: &str) -> AppResult<()> {
    let params = parse_telegram_auth_data(raw)?;
    verify_telegram_params(&params, bot_token)
}

fn verify_telegram_params(params: &HashMap<String, String>, bot_token: &str) -> AppResult<()> {
    let received_hash = params
        .get("hash")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Authentication("Missing Telegram auth hash".to_string()))?;
    let auth_date = params
        .get("auth_date")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| AppError::Authentication("Missing Telegram auth_date".to_string()))?;
    let now = chrono::Utc::now().timestamp();
    if auth_date > now + 300 || now.saturating_sub(auth_date) > 86_400 {
        return Err(AppError::Authentication(
            "Telegram auth data is expired".to_string(),
        ));
    }

    let mut pairs: Vec<String> = params
        .iter()
        .filter(|(key, _)| key.as_str() != "hash")
        .map(|(key, value)| format!("{}={}", key, value))
        .collect();
    pairs.sort();
    let data_check_string = pairs.join("\n");
    let secret_key = Sha256::digest(bot_token.as_bytes());
    let expected_hash = hmac_sha256_hex(&secret_key, data_check_string.as_bytes());
    if !constant_time_eq_hex(&expected_hash, received_hash) {
        return Err(AppError::Authentication(
            "Invalid Telegram auth hash".to_string(),
        ));
    }

    Ok(())
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
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

fn constant_time_eq_hex(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
