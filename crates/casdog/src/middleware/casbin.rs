use salvo::prelude::*;

use crate::error::ErrorResponse;
use crate::services::CasbinService;

pub struct CasbinAuth {
    pub obj: String,
    pub act: String,
}

impl CasbinAuth {
    pub fn new(obj: impl Into<String>, act: impl Into<String>) -> Self {
        Self {
            obj: obj.into(),
            act: act.into(),
        }
    }
}

#[async_trait]
impl Handler for CasbinAuth {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let user_name = depot.get::<String>("user_name").cloned().ok();
        let is_admin = depot.get::<bool>("is_admin").copied().ok().unwrap_or(false);

        if is_admin {
            ctrl.call_next(req, depot, res).await;
            return;
        }

        let sub = match user_name {
            Some(name) => name,
            None => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ErrorResponse::new(401, "Not authenticated")));
                ctrl.skip_rest();
                return;
            }
        };

        let casbin_service = match depot.obtain::<CasbinService>() {
            Ok(service) => service.clone(),
            Err(_) => {
                tracing::error!("Casbin service not found in depot");
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(ErrorResponse::new(
                    500,
                    "Authorization system unavailable",
                )));
                ctrl.skip_rest();
                return;
            }
        };

        match casbin_service
            .check_permission(&sub, &self.obj, &self.act)
            .await
        {
            Ok(true) => {
                ctrl.call_next(req, depot, res).await;
            }
            Ok(false) => {
                tracing::warn!(
                    "Permission denied for user '{}' on {}:{}",
                    sub,
                    self.obj,
                    self.act
                );
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(ErrorResponse::new(403, "Permission denied")));
                ctrl.skip_rest();
            }
            Err(e) => {
                tracing::error!("Casbin error: {:?}", e);
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(ErrorResponse::new(500, "Authorization check failed")));
                ctrl.skip_rest();
            }
        }
    }
}

pub struct RequireAdmin;

#[async_trait]
impl Handler for RequireAdmin {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let is_admin = depot.get::<bool>("is_admin").copied().ok().unwrap_or(false);

        if is_admin {
            ctrl.call_next(req, depot, res).await;
        } else {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(ErrorResponse::new(403, "Admin access required")));
            ctrl.skip_rest();
        }
    }
}
