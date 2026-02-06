use jsonwebtoken::{DecodingKey, Validation, decode};
use salvo::prelude::*;

use crate::config::AppConfig;
use crate::error::ErrorResponse;
use crate::services::auth_service::Claims;

pub struct JwtAuth;

#[async_trait]
impl Handler for JwtAuth {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let config = AppConfig::get();

        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));

        match token {
            Some(token) => {
                match decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(config.jwt.secret.as_bytes()),
                    &Validation::default(),
                ) {
                    Ok(token_data) => {
                        depot.insert("user_id", token_data.claims.sub.clone());
                        depot.insert("user_owner", token_data.claims.owner.clone());
                        depot.insert("user_name", token_data.claims.name.clone());
                        depot.insert("is_admin", token_data.claims.is_admin);
                        depot.insert("claims", token_data.claims);
                        ctrl.call_next(req, depot, res).await;
                    }
                    Err(e) => {
                        tracing::warn!("JWT validation failed: {:?}", e);
                        res.status_code(StatusCode::UNAUTHORIZED);
                        res.render(Json(ErrorResponse::new(401, "Invalid or expired token")));
                        ctrl.skip_rest();
                    }
                }
            }
            None => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ErrorResponse::new(
                    401,
                    "Missing authorization header",
                )));
                ctrl.skip_rest();
            }
        }
    }
}

pub struct OptionalJwtAuth;

#[async_trait]
impl Handler for OptionalJwtAuth {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let config = AppConfig::get();

        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));

        if let Some(token) = token {
            if let Ok(token_data) = decode::<Claims>(
                token,
                &DecodingKey::from_secret(config.jwt.secret.as_bytes()),
                &Validation::default(),
            ) {
                depot.insert("user_id", token_data.claims.sub.clone());
                depot.insert("user_owner", token_data.claims.owner.clone());
                depot.insert("user_name", token_data.claims.name.clone());
                depot.insert("is_admin", token_data.claims.is_admin);
                depot.insert("claims", token_data.claims);
            }
        }

        ctrl.call_next(req, depot, res).await;
    }
}
