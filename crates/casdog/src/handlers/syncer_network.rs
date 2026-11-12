use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    services::syncer_network_service::{self, SyncerNetworkApproval},
};
use salvo::{
    oapi::{
        ToSchema,
        extract::{JsonBody, PathParam},
    },
    prelude::*,
};
use serde::Deserialize;
use sqlx::PgPool;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveDirectoryNetwork {
    allow_private: bool,
}

fn inputs(depot: &Depot, id: String) -> AppResult<(PgPool, Principal, String)> {
    let actor = Principal::from_depot(depot)?;
    if actor.is_application() || !actor.global_admin() {
        return Err(AppError::Authorization(
            "A real global administrator is required".into(),
        ));
    }
    if id.is_empty() || id.len() > 200 {
        return Err(AppError::Validation("Syncer ID required".into()));
    }
    let pool = depot
        .obtain::<PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database pool unavailable".into()))?;
    Ok((pool, actor, id))
}
fn no_store(res: &mut Response) {
    res.headers_mut()
        .insert("cache-control", "no-store".parse().expect("static header"));
}

#[endpoint(
    tags("Syncers"),
    summary = "Get private cloud-directory network approval"
)]
pub async fn get(
    depot: &mut Depot,
    id: PathParam<String>,
    res: &mut Response,
) -> AppResult<Json<SyncerNetworkApproval>> {
    no_store(res);
    let (pool, actor, id) = inputs(depot, id.into_inner())?;
    Ok(Json(syncer_network_service::get(&pool, &actor, &id).await?))
}
#[endpoint(
    tags("Syncers"),
    summary = "Approve current cloud-directory endpoints for private networks"
)]
pub async fn approve(
    depot: &mut Depot,
    id: PathParam<String>,
    body: JsonBody<ApproveDirectoryNetwork>,
    res: &mut Response,
) -> AppResult<Json<SyncerNetworkApproval>> {
    no_store(res);
    let (pool, actor, id) = inputs(depot, id.into_inner())?;
    if !body.allow_private {
        return Err(AppError::Validation(
            "Use DELETE to revoke directory network approval".into(),
        ));
    }
    Ok(Json(
        syncer_network_service::approve(&pool, &actor, &id).await?,
    ))
}
#[endpoint(
    tags("Syncers"),
    summary = "Revoke private cloud-directory network approval"
)]
pub async fn revoke(
    depot: &mut Depot,
    id: PathParam<String>,
    res: &mut Response,
) -> AppResult<Json<SyncerNetworkApproval>> {
    no_store(res);
    let (pool, actor, id) = inputs(depot, id.into_inner())?;
    Ok(Json(
        syncer_network_service::revoke(&pool, &actor, &id).await?,
    ))
}
