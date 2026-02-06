use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct WeChatProvider {
    app_id: String,
    app_secret: String,
}

impl WeChatProvider {
    pub fn new(app_id: String, app_secret: String) -> Self {
        Self { app_id, app_secret }
    }
}

#[derive(Deserialize)]
struct WeChatTokenResponse {
    access_token: Option<String>,
    openid: Option<String>,
    errcode: Option<i32>,
    errmsg: Option<String>,
}

#[derive(Deserialize)]
struct WeChatUser {
    openid: String,
    nickname: Option<String>,
    headimgurl: Option<String>,
    unionid: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for WeChatProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("snsapi_login");
        format!(
            "https://open.weixin.qq.com/connect/qrconnect?appid={}&redirect_uri={}&response_type=code&scope={}&state={}#wechat_redirect",
            urlencoding::encode(&self.app_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(scope),
            urlencoding::encode(state),
        )
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://api.weixin.qq.com/sns/oauth2/access_token")
            .query(&[
                ("appid", self.app_id.as_str()),
                ("secret", self.app_secret.as_str()),
                ("code", code),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("WeChat token exchange failed: {}", e)))?;

        let token_resp: WeChatTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("WeChat token parse failed: {}", e)))?;

        if let Some(errcode) = token_resp.errcode {
            let errmsg = token_resp.errmsg.unwrap_or_default();
            return Err(AppError::Internal(format!("WeChat error {}: {}", errcode, errmsg)));
        }

        // WeChat returns both access_token and openid, we'll combine them
        let access_token = token_resp.access_token
            .ok_or_else(|| AppError::Internal("No access_token in WeChat response".to_string()))?;
        let openid = token_resp.openid
            .ok_or_else(|| AppError::Internal("No openid in WeChat response".to_string()))?;

        // Store both as JSON for later use
        Ok(serde_json::json!({
            "access_token": access_token,
            "openid": openid
        }).to_string())
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        // Parse the combined token
        let token_data: serde_json::Value = serde_json::from_str(access_token)
            .map_err(|e| AppError::Internal(format!("Invalid WeChat token format: {}", e)))?;

        let token = token_data["access_token"]
            .as_str()
            .ok_or_else(|| AppError::Internal("Missing access_token".to_string()))?;
        let openid = token_data["openid"]
            .as_str()
            .ok_or_else(|| AppError::Internal("Missing openid".to_string()))?;

        let client = reqwest::Client::new();
        let resp = client
            .get("https://api.weixin.qq.com/sns/userinfo")
            .query(&[
                ("access_token", token),
                ("openid", openid),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("WeChat user info failed: {}", e)))?;

        let user: WeChatUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("WeChat user parse failed: {}", e)))?;

        Ok(ProviderUserInfo {
            id: user.unionid.clone().unwrap_or(user.openid.clone()),
            username: user.openid,
            display_name: user.nickname.unwrap_or_default(),
            email: None, // WeChat doesn't provide email
            avatar_url: user.headimgurl,
            provider_type: "WeChat".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "WeChat"
    }
}
