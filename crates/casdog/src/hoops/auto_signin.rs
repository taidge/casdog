use crate::error::ErrorResponse;
use salvo::prelude::*;

/// Optional authentication shares the exact required-auth credential verifier.
/// Only requests with no credential transport may proceed anonymously.
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
        if super::auth::authenticate_request(req, depot).await.is_err() {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ErrorResponse::new(
                401,
                "Invalid or expired credentials",
            )));
            ctrl.skip_rest();
            return;
        }
        if crate::services::key_credentials_service::application_identity(depot) {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(ErrorResponse::new(
                403,
                "Application credentials cannot authenticate an interactive user",
            )));
            ctrl.skip_rest();
            return;
        }
        ctrl.call_next(req, depot, res).await;
    }
}
