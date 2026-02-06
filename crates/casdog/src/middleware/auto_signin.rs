use base64::Engine as _;
use base64::engine::general_purpose;
use jsonwebtoken::{DecodingKey, Validation, decode};
use salvo::prelude::*;
use sqlx::{Pool, Postgres};

use crate::config::AppConfig;
use crate::services::auth_service::Claims;

/// Multi-source authentication middleware.
/// Tries multiple auth methods in order:
/// 1. Bearer token (JWT) from Authorization header
/// 2. Access token (JWT) from query parameter
/// 3. Access key + secret (from query params)
/// 4. Client ID + secret (from Basic Auth or query params)
///
/// If no authentication source succeeds, the request continues anyway
/// (the downstream handler may allow anonymous access).
pub struct AutoSigninFilter;

#[async_trait]
impl Handler for AutoSigninFilter {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let config = AppConfig::get();

        // 1. Try Bearer token from Authorization header
        if let Some(token) = extract_bearer_token(req) {
            if let Ok(token_data) = decode::<Claims>(
                &token,
                &DecodingKey::from_secret(config.jwt.secret.as_bytes()),
                &Validation::default(),
            ) {
                set_depot_from_claims(depot, &token_data.claims);
                ctrl.call_next(req, depot, res).await;
                return;
            }
        }

        // 2. Try access_token from query param
        if let Some(token) = req.query::<String>("accessToken") {
            if let Ok(token_data) = decode::<Claims>(
                &token,
                &DecodingKey::from_secret(config.jwt.secret.as_bytes()),
                &Validation::default(),
            ) {
                set_depot_from_claims(depot, &token_data.claims);
                ctrl.call_next(req, depot, res).await;
                return;
            }
        }

        // 3. Try access key + secret from query params
        if let (Some(access_key), Some(access_secret)) = (
            req.query::<String>("accessKey"),
            req.query::<String>("accessSecret"),
        ) {
            if let Ok(pool) = depot.obtain::<Pool<Postgres>>() {
                let pool = pool.clone();
                if let Ok(user) =
                    lookup_user_by_access_key(&pool, &access_key, &access_secret).await
                {
                    depot.insert("user_id", user.0);
                    depot.insert("user_owner", user.1);
                    depot.insert("user_name", user.2);
                    depot.insert("is_admin", user.3);
                    ctrl.call_next(req, depot, res).await;
                    return;
                }
            }
        }

        // 4. Try client_id + client_secret (Basic Auth or query params)
        if let (Some(client_id), Some(client_secret)) = extract_client_credentials(req) {
            if let Ok(pool) = depot.obtain::<Pool<Postgres>>() {
                let pool = pool.clone();
                if let Ok(_app) = lookup_application(&pool, &client_id, &client_secret).await {
                    // Application-level auth (no user context)
                    depot.insert("client_id", client_id);
                    depot.insert("is_admin", false);
                    ctrl.call_next(req, depot, res).await;
                    return;
                }
            }
        }

        // No authentication found - continue anyway (handler may allow anonymous)
        ctrl.call_next(req, depot, res).await;
    }
}

fn extract_bearer_token(req: &Request) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn set_depot_from_claims(depot: &mut Depot, claims: &Claims) {
    depot.insert("user_id", claims.sub.clone());
    depot.insert("user_owner", claims.owner.clone());
    depot.insert("user_name", claims.name.clone());
    depot.insert("is_admin", claims.is_admin);
    depot.insert("claims", claims.clone());
}

async fn lookup_user_by_access_key(
    pool: &Pool<Postgres>,
    access_key: &str,
    access_secret: &str,
) -> Result<(String, String, String, bool), ()> {
    let row: Option<(String, String, String, bool)> = sqlx::query_as(
        "SELECT id, owner, name, is_admin FROM users WHERE access_key = $1 AND access_secret = $2 AND is_deleted = false",
    )
    .bind(access_key)
    .bind(access_secret)
    .fetch_optional(pool)
    .await
    .map_err(|_| ())?;

    row.ok_or(())
}

fn extract_client_credentials(req: &Request) -> (Option<String>, Option<String>) {
    // Try Basic Auth header first
    if let Some(auth) = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Basic "))
    {
        if let Ok(decoded) = general_purpose::STANDARD.decode(auth) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                if let Some((id, secret)) = decoded_str.split_once(':') {
                    return (Some(id.to_string()), Some(secret.to_string()));
                }
            }
        }
    }

    // Fall back to query params
    (
        req.query::<String>("clientId"),
        req.query::<String>("clientSecret"),
    )
}

async fn lookup_application(
    pool: &Pool<Postgres>,
    client_id: &str,
    client_secret: &str,
) -> Result<String, ()> {
    let name: Option<String> = sqlx::query_scalar(
        "SELECT name FROM applications WHERE client_id = $1 AND client_secret = $2",
    )
    .bind(client_id)
    .bind(client_secret)
    .fetch_optional(pool)
    .await
    .map_err(|_| ())?;

    name.ok_or(())
}
