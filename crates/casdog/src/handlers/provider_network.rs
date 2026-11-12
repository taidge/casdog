use salvo::{
    oapi::{
        ToSchema,
        extract::{JsonBody, PathParam},
    },
    prelude::*,
};
use serde::Deserialize;
use sqlx::PgPool;

use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    services::provider_network_service::{self, NetworkApproval},
};

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveNetwork {
    allow_private: bool,
}

fn inputs(depot: &Depot, id: String) -> AppResult<(PgPool, Principal, String)> {
    let actor = Principal::from_depot(depot)?;
    if actor.is_application() || !actor.global_admin() {
        return Err(AppError::Authorization(
            "A real global administrator is required".into(),
        ));
    }
    let pool = depot
        .obtain::<PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    if id.is_empty() || id.len() > 200 {
        return Err(AppError::Validation("Provider ID required".into()));
    }
    Ok((pool, actor, id))
}

fn no_store(res: &mut Response) {
    res.headers_mut()
        .insert("cache-control", "no-store".parse().expect("static header"));
}

/// Runs before typed request extraction, so malformed approval bodies receive
/// the same cache policy as successful and authorization-denied requests.
#[handler]
pub async fn no_store_hoop(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    no_store(res);
    ctrl.call_next(req, depot, res).await;
}

#[endpoint(tags("providers"), summary = "Get private provider network approval")]
pub async fn get(
    depot: &mut Depot,
    id: PathParam<String>,
    res: &mut Response,
) -> AppResult<Json<NetworkApproval>> {
    no_store(res);
    let (pool, actor, id) = inputs(depot, id.into_inner())?;
    Ok(Json(
        provider_network_service::get(&pool, &actor, &id).await?,
    ))
}

#[endpoint(
    tags("providers"),
    summary = "Approve current custom provider endpoints for private networks"
)]
pub async fn approve(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<ApproveNetwork>,
    res: &mut Response,
) -> AppResult<Json<NetworkApproval>> {
    no_store(res);
    let (pool, actor, id) = inputs(depot, id.into_inner())?;
    if !body.allow_private {
        return Err(AppError::Validation(
            "Use DELETE to revoke private network approval".into(),
        ));
    }
    Ok(Json(
        provider_network_service::approve(&pool, &actor, &id).await?,
    ))
}

#[endpoint(
    tags("providers"),
    summary = "Revoke private provider network approval"
)]
pub async fn revoke(
    depot: &mut Depot,
    id: PathParam<String>,
    res: &mut Response,
) -> AppResult<Json<NetworkApproval>> {
    no_store(res);
    let (pool, actor, id) = inputs(depot, id.into_inner())?;
    Ok(Json(
        provider_network_service::revoke(&pool, &actor, &id).await?,
    ))
}
