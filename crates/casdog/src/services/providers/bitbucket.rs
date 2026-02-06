use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct BitbucketProvider {
    client_id: String,
    client_secret: String,
}

impl BitbucketProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self { client_id, client_secret }
    }
}

#[derive(Deserialize)]
struct BitbucketTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct BitbucketUser {
    account_id: String,
    username: String,
    display_name: String,
    links: Option<BitbucketLinks>,
}

#[derive(Deserialize)]
struct BitbucketLinks {
    avatar: Option<BitbucketAvatar>,
}

#[derive(Deserialize)]
struct BitbucketAvatar {
    href: Option<String>,
}

#[derive(Deserialize)]
struct BitbucketEmail {
    email: String,
    is_primary: bool,
}

#[derive(Deserialize)]
struct BitbucketEmailResponse {
    values: Vec<BitbucketEmail>,
}

#[async_trait]
impl OAuthProviderTrait for BitbucketProvider {
    fn get_auth_url(&self, redirect_uri: &str, state: &str, scope: Option<&str>) -> String {
        let scope = scope.unwrap_or("account email");
        format!(
            "https://bitbucket.org/site/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        let client = reqwest::Client::new();

        // Bitbucket requires Basic Auth
        let auth = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{}:{}", self.client_id, self.client_secret));

        let resp = client
            .post("https://bitbucket.org/site/oauth2/access_token")
            .header("Authorization", format!("Basic {}", auth))
            .form(&[
                ("code", code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Bitbucket token exchange failed: {}", e)))?;

        let token_resp: BitbucketTokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Bitbucket token parse failed: {}", e)))?;

        Ok(token_resp.access_token)
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        let client = reqwest::Client::new();

        // Get user info
        let resp = client
            .get("https://api.bitbucket.org/2.0/user")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Bitbucket user info failed: {}", e)))?;

        let user: BitbucketUser = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Bitbucket user parse failed: {}", e)))?;

        // Get email (separate API call)
        let email = match client
            .get("https://api.bitbucket.org/2.0/user/emails")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
        {
            Ok(email_resp) => {
                email_resp.json::<BitbucketEmailResponse>()
                    .await
                    .ok()
                    .and_then(|e| e.values.into_iter().find(|email| email.is_primary))
                    .map(|email| email.email)
            }
            Err(_) => None,
        };

        let avatar_url = user.links
            .and_then(|l| l.avatar)
            .and_then(|a| a.href);

        Ok(ProviderUserInfo {
            id: user.account_id,
            username: user.username,
            display_name: user.display_name,
            email,
            avatar_url,
            provider_type: "Bitbucket".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Bitbucket"
    }
}
