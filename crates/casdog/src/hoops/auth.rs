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
                        if let Some(impersonator_user_id) =
                            token_data.claims.impersonator_user_id.clone()
                        {
                            depot.insert("impersonator_user_id", impersonator_user_id);
                            depot.insert("is_impersonating", true);
                        }
                        if let Some(impersonator_owner) =
                            token_data.claims.impersonator_owner.clone()
                        {
                            depot.insert("impersonator_owner", impersonator_owner);
                        }
                        if let Some(impersonator_name) = token_data.claims.impersonator_name.clone()
                        {
                            depot.insert("impersonator_name", impersonator_name);
                        }
                        if let Some(impersonation_session_id) =
                            token_data.claims.impersonation_session_id.clone()
                        {
                            depot.insert("impersonation_session_id", impersonation_session_id);
                        }
                        if let Some(impersonation_application) =
                            token_data.claims.impersonation_application.clone()
                        {
                            depot.insert("impersonation_application", impersonation_application);
                        }
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
                if let Some(impersonator_user_id) = token_data.claims.impersonator_user_id.clone() {
                    depot.insert("impersonator_user_id", impersonator_user_id);
                    depot.insert("is_impersonating", true);
                }
                if let Some(impersonator_owner) = token_data.claims.impersonator_owner.clone() {
                    depot.insert("impersonator_owner", impersonator_owner);
                }
                if let Some(impersonator_name) = token_data.claims.impersonator_name.clone() {
                    depot.insert("impersonator_name", impersonator_name);
                }
                if let Some(impersonation_session_id) =
                    token_data.claims.impersonation_session_id.clone()
                {
                    depot.insert("impersonation_session_id", impersonation_session_id);
                }
                if let Some(impersonation_application) =
                    token_data.claims.impersonation_application.clone()
                {
                    depot.insert("impersonation_application", impersonation_application);
                }
                depot.insert("claims", token_data.claims);
            }
        }

        ctrl.call_next(req, depot, res).await;
    }
}
