use salvo::prelude::*;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
};

fn actor(depot: &Depot, req: &Request) -> AppResult<Principal> {
    let principal = Principal::from_depot(depot)?;
    if principal.is_application()
        || req
            .query::<String>("owner")
            .is_some_and(|owner| owner != principal.owner)
        || req
            .query::<String>("user")
            .is_some_and(|user| user != principal.name)
    {
        return Err(AppError::Authorization(
            "The store belongs to the current user and tenant".into(),
        ));
    }
    Ok(principal)
}

fn page(req: &Request) -> AppResult<(i64, i64)> {
    let parse = |name: &str, default: i64| -> AppResult<i64> {
        req.query::<String>(name)
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| AppError::Validation(format!("Invalid {name}")))
            })
            .unwrap_or(Ok(default))
    };
    let page = parse("page", 1)?;
    let size = parse("page_size", 20)?;
    if !(1..=1_000_000).contains(&page) || !(1..=100).contains(&size) {
        return Err(AppError::Validation("Invalid store pagination".into()));
    }
    Ok((page, size))
}

/// Safe catalog for end users: payment provider credentials and administrator
/// configuration are deliberately absent from this response.
#[handler]
pub async fn catalog(depot: &mut Depot, req: &Request) -> AppResult<Json<Value>> {
    let principal = actor(depot, req)?;
    let (page, size) = page(req)?;
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("Database unavailable".into()))?;
    let products: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(p)-'is_deleted' FROM products p WHERE owner=$1 AND NOT is_deleted AND lower(state) IN ('active','published','on sale') ORDER BY created_at DESC,id LIMIT $2 OFFSET $3",
    ).bind(&principal.owner).bind(size).bind((page-1)*size).fetch_all(pool).await?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM products WHERE owner=$1 AND NOT is_deleted AND lower(state) IN ('active','published','on sale')")
        .bind(&principal.owner).fetch_one(pool).await?;
    let plan_ids: Vec<String> = products
        .iter()
        .filter_map(|p| p["plan_id"].as_str().map(str::to_owned))
        .collect();
    let plans: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(p)-'is_deleted' FROM plans p WHERE owner=$1 AND id=ANY($2) AND NOT is_deleted AND is_enabled ORDER BY name")
        .bind(&principal.owner).bind(&plan_ids).fetch_all(pool).await?;
    let current_user: Value = sqlx::query_scalar("SELECT to_jsonb(u) FROM users u JOIN organizations o ON o.name=u.owner WHERE u.id=$1 AND u.owner=$2 AND NOT u.is_deleted AND NOT u.is_forbidden AND NOT o.is_deleted AND NOT o.disable_signin")
        .bind(&principal.id).bind(&principal.owner).fetch_optional(pool).await?
        .ok_or_else(||AppError::Authorization("The store requires a current user in an active tenant".into()))?;
    let pricing_rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'owner',owner,'name',name,'display_name',display_name,'plans',plans,'is_invite_only',is_invite_only,'users',users) FROM pricings WHERE owner=$1 AND NOT is_deleted AND is_enabled ORDER BY name")
        .bind(&principal.owner).fetch_all(pool).await?;
    let pricings: Vec<Value> = pricing_rows
        .into_iter()
        .filter(|pricing| {
            if !crate::services::pricing_access_service::PricingAccessService::allows_json(
                pricing,
                Some(&current_user),
            ) {
                return false;
            }
            let references: Vec<String> =
                serde_json::from_str(pricing["plans"].as_str().unwrap_or("[]")).unwrap_or_default();
            plans.iter().any(|plan| {
                references.iter().any(|reference| {
                    reference == plan["id"].as_str().unwrap_or("")
                        || reference == plan["name"].as_str().unwrap_or("")
                        || reference
                            == &format!(
                                "{}/{}",
                                principal.owner,
                                plan["name"].as_str().unwrap_or("")
                            )
                })
            })
        })
        .map(|mut pricing| {
            if let Some(object) = pricing.as_object_mut() {
                object.remove("users");
            }
            pricing
        })
        .collect();
    let providers: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'display_name',display_name,'type',type) FROM providers WHERE owner=$1 AND category='Payment' ORDER BY name")
        .bind(&principal.owner).fetch_all(pool).await?;
    Ok(Json(
        json!({"status":"ok","data":products,"plans":plans,"pricings":pricings,"providers":providers,"page":page,"page_size":size,"total":total}),
    ))
}

/// A pinned buyer UUID keeps all purchases scoped to the original account,
/// including ordinary products and histories whose usernames were reused.
#[handler]
pub async fn purchases(depot: &mut Depot, req: &Request) -> AppResult<Json<Value>> {
    let principal = actor(depot, req)?;
    let (page, size) = page(req)?;
    let pool = depot
        .obtain::<PgPool>()
        .map_err(|_| AppError::Internal("Database unavailable".into()))?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM orders o LEFT JOIN order_benefits b ON b.order_id=o.id WHERE o.owner=$1 AND NOT o.is_deleted AND o.buyer_id=$2")
        .bind(&principal.owner).bind(&principal.id).fetch_one(pool).await?;
    let orders: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',o.id,'name',o.name,'display_name',o.display_name,'state',o.state,'price',o.price,'currency',o.currency,'quantity',o.quantity,'created_at',o.created_at,'product_name',o.product_name,'plan_name',o.plan_name,'pricing_name',o.pricing_name,'payment_id',p.id,'payment_state',p.state,'pay_url',p.pay_url,'kind',COALESCE(b.kind,CASE WHEN EXISTS(SELECT 1 FROM order_lines WHERE order_id=o.id) THEN 'cart' END),'lines',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',l.id,'product_name',l.product_name,'display_name',l.display_name,'kind',l.kind,'quantity',l.quantity,'unit_amount_cents',l.unit_amount_cents,'amount_cents',l.amount_cents,'currency',l.currency) ORDER BY l.position) FROM order_lines l WHERE l.order_id=o.id),'[]'::jsonb)) FROM orders o LEFT JOIN order_benefits b ON b.order_id=o.id LEFT JOIN payments p ON p.id=o.payment_id AND p.owner=o.owner AND NOT p.is_deleted WHERE o.owner=$1 AND NOT o.is_deleted AND o.buyer_id=$2 ORDER BY o.created_at DESC,o.id LIMIT $3 OFFSET $4",
    ).bind(&principal.owner).bind(&principal.id).bind(size).bind((page-1)*size).fetch_all(pool).await?;
    let subscriptions: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',s.id,'name',s.name,'display_name',s.display_name,'plan',p.display_name,'state',CASE WHEN lower(s.state) IN ('active','upcoming','expired') THEN CASE WHEN s.end_date<=clock_timestamp() THEN 'expired' WHEN s.start_date>clock_timestamp() THEN 'upcoming' ELSE 'active' END ELSE s.state END,'period',s.period,'start_date',s.start_date,'end_date',s.end_date,'auto_renew',s.auto_renew,'renewal_quote',jsonb_build_object('amount',CASE WHEN lower(s.period)='yearly' THEN p.price_per_year ELSE p.price_per_month END,'currency',COALESCE(p.currency,'USD')),'renewal',jsonb_build_object('enabled',COALESCE(a.enabled AND s.auto_renew,false),'mode',a.mode,'currency',a.currency,'max_amount_cents',a.max_amount_cents,'state',w.state,'order_id',w.order_id,'last_error',w.last_error),'active',lower(s.state)='active' AND s.start_date<=clock_timestamp() AND (s.end_date IS NULL OR s.end_date>clock_timestamp())) FROM subscriptions s LEFT JOIN plans p ON p.id=s.plan_id AND p.owner=s.owner LEFT JOIN subscription_renewal_authorizations a ON a.subscription_id=s.id LEFT JOIN LATERAL(SELECT state,order_id,last_error FROM subscription_renewal_work WHERE subscription_id=s.id ORDER BY due_at DESC LIMIT 1) w ON true WHERE s.owner=$1 AND s.user_id=$2 AND NOT s.is_deleted ORDER BY s.created_at DESC,s.id",
    ).bind(&principal.owner).bind(&principal.id).fetch_all(pool).await?;
    let wallet: Option<Value> = sqlx::query_scalar("SELECT jsonb_build_object('balance',balance,'currency',COALESCE(NULLIF(balance_currency,''),NULLIF(currency,''),'USD')) FROM users WHERE id=$1 AND owner=$2 AND NOT is_deleted AND NOT is_forbidden")
        .bind(&principal.id).bind(&principal.owner).fetch_optional(pool).await?;
    Ok(Json(
        json!({"status":"ok","data":orders,"subscriptions":subscriptions,"wallet":wallet,"page":page,"page_size":size,"total":total}),
    ))
}
