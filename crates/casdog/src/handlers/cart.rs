use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    services::cart_service::{CartService, CheckoutCart, ReplaceCart},
};
use salvo::prelude::*;
use serde_json::{Value, json};
use sqlx::PgPool;
fn actor(depot: &Depot, req: &Request) -> AppResult<Principal> {
    let p = Principal::from_depot(depot)?;
    if p.is_application()
        || req.query::<String>("owner").is_some_and(|o| o != p.owner)
        || req.query::<String>("userName").is_some_and(|n| n != p.name)
        || req.query::<String>("user").is_some_and(|n| n != p.name)
    {
        return Err(AppError::Authorization(
            "Cart operations require the current real user and tenant".into(),
        ));
    }
    Ok(p)
}
fn pool(depot: &Depot) -> AppResult<PgPool> {
    depot
        .obtain::<PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database unavailable".into()))
}
#[handler]
pub async fn get_cart(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = actor(depot, req)?;
    Ok(Json(
        json!({"status":"ok","data":CartService::get(&pool(depot)?,&p).await?}),
    ))
}
#[handler]
pub async fn replace_cart(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = actor(depot, req)?;
    let body: ReplaceCart = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("Invalid cart replacement".into()))?;
    Ok(Json(
        json!({"status":"ok","data":CartService::replace(&pool(depot)?,&p,body).await?}),
    ))
}
#[handler]
pub async fn checkout_cart(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = actor(depot, req)?;
    let body: CheckoutCart = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("Invalid cart checkout confirmation".into()))?;
    Ok(Json(
        json!({"status":"ok","data":CartService::checkout(&pool(depot)?,&p,body).await?}),
    ))
}
#[handler]
pub async fn place_order(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = actor(depot, req)?;
    let body: Value = req
        .parse_json()
        .await
        .map_err(|_| AppError::Validation("Invalid place-order JSON".into()))?;
    let items = body
        .get("productInfos")
        .ok_or_else(|| AppError::Validation("productInfos are required".into()))?;
    let provider = req.query::<String>("providerName");
    let data = CartService::place_order(
        &pool(depot)?,
        &p,
        items,
        provider.as_deref(),
        body["couponCode"].as_str(),
    )
    .await?;
    Ok(Json(
        json!({"status":"ok","data":data["order"],"lines":data["lines"]}),
    ))
}
