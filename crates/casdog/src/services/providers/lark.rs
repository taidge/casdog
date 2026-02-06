use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct LarkProvider {
    app_id: String,
    app_secret: String,
}

impl LarkProvider {
    pub fn new(app_id: String, app_secret: String) -> Self {
        Self { app_id, app_secret }
    }
}

#[derive(Deserialize)]
struct LarkTokenResponse {
    code: i32,
    msg: String,
    data: Option<LarkTokenData>,
}

#[derive(Deserialize)]
struct LarkTokenData {
    access_token: String,
}

#[derive(Deserialize)]
struct LarkUserResponse {
    code: i32,
    msg: String,
    data: Option<LarkUserData>,
}

#[derive(Deserialize)]
struct LarkUserData {
    open_id: String,
    name: String,
    en_name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for LarkProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, _scope: Option<&str>) -> String {
        format!(
            "https://open.feishu.cn/open-apis/authen/v1/index?app_id={}&redirect_uri={}&state={}",
            urlencoding::encode(&self.app_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        )
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();

        let resp = client
            .post("https://open.feishu.cn/open-apis/authen/v1/access_token")
            .json(&serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "app_id": self.app_id,
                "app_secret": self.app_secret,
            }))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Lark token exchange failed: {}", e)))?;

        let token_resp: LarkTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Lark token parse failed: {}", e)))?;

        if token_resp.code != 0 {
            return Err(AppError::Internal(format!("Lark error: {}", token_resp.msg)));
        }

        token_resp.data
            .map(|d| d.access_token)
            .ok_or_else(|| AppError::Internal("No access token in Lark response".to_string()))
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();

        let resp = client
            .get("https://open.feishu.cn/open-apis/authen/v1/user_info")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Lark user info failed: {}", e)))?;

        let user_resp: LarkUserResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Lark user parse failed: {}", e)))?;

        if user_resp.code != 0 {
            return Err(AppError::Internal(format!("Lark error: {}", user_resp.msg)));
        }

        let user = user_resp.data
            .ok_or_else(|| AppError::Internal("No user data in Lark response".to_string()))?;

        Ok(ProviderUserInfo {
            id: user.open_id.clone(),
            username: user.email.clone().unwrap_or(user.open_id),
            display_name: user.name,
            email: user.email,
            avatar_url: user.avatar_url,
            provider_type: "Lark".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Lark"
    }
}
