use crate::error::{AppError, AppResult};
use super::oauth_provider::{OAuthProviderTrait, ProviderUserInfo};
use async_trait::async_trait;
use serde::Deserialize;

pub struct SteamProvider {
    api_key: String,
    _realm: String,
}

impl SteamProvider {
    pub fn new(api_key: String, realm: String) -> Self {
        Self {
            api_key,
            _realm: realm,
        }
    }
}

#[derive(Deserialize)]
struct SteamPlayerResponse {
    response: SteamPlayersData,
}

#[derive(Deserialize)]
struct SteamPlayersData {
    players: Vec<SteamPlayer>,
}

#[derive(Deserialize)]
struct SteamPlayer {
    steamid: String,
    personaname: String,
    profileurl: Option<String>,
    avatar: Option<String>,
    avatarfull: Option<String>,
}

#[async_trait]
impl OAuthProviderTrait for SteamProvider {
    fn get_auth_url(&self, redirect_uri: &str, _state: &str, _scope: Option<&str>) -> String {
        format!(
            "https://steamcommunity.com/openid/login?openid.mode=checkid_setup&openid.ns=http://specs.openid.net/auth/2.0&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to={}&openid.realm={}",
            urlencoding::encode(redirect_uri),
            urlencoding::encode(redirect_uri),
        )
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AppResult<String> {
        // For Steam OpenID, the "code" is actually the callback URL with OpenID params
        // Extract the claimed_id which contains the Steam ID

        // Verify the OpenID response
        let client = reqwest::Client::new();
        let verify_url = format!(
            "https://steamcommunity.com/openid/login?{}",
            code.replace("openid.mode=id_res", "openid.mode=check_authentication")
        );

        let resp = client
            .get(&verify_url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Steam verification failed: {}", e)))?;

        let response_text = resp
            .text()
            .await
            .map_err(|e| AppError::Internal(format!("Steam response read failed: {}", e)))?;

        if !response_text.contains("is_valid:true") {
            return Err(AppError::Internal("Steam OpenID verification failed".to_string()));
        }

        // Extract Steam ID from the claimed_id parameter
        let steam_id = code
            .split("openid.claimed_id=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .and_then(|s| s.rsplit('/').next())
            .ok_or_else(|| AppError::Internal("Failed to extract Steam ID".to_string()))?;

        Ok(steam_id.to_string())
    }

    async fn get_user_info(&self, access_token: &str) -> AppResult<ProviderUserInfo> {
        // access_token is the Steam ID
        let client = reqwest::Client::new();
        let resp = client
            .get("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/")
            .query(&[
                ("key", self.api_key.as_str()),
                ("steamids", access_token),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Steam user info failed: {}", e)))?;

        let player_resp: SteamPlayerResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Steam user parse failed: {}", e)))?;

        let player = player_resp.response.players
            .into_iter()
            .next()
            .ok_or_else(|| AppError::Internal("No player data in Steam response".to_string()))?;

        Ok(ProviderUserInfo {
            id: player.steamid.clone(),
            username: player.steamid,
            display_name: player.personaname,
            email: None, // Steam doesn't provide email via API
            avatar_url: player.avatarfull.or(player.avatar),
            provider_type: "Steam".to_string(),
        })
    }

    fn provider_type(&self) -> &str {
        "Steam"
    }
}
