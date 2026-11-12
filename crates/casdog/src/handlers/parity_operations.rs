//! Database-backed operational endpoints. Every endpoint checks its own scope so
//! mounting the compatibility router cannot turn a route-name allowlist into trust.
use crate::error::{AppError, AppResult};
use crate::hoops::authz::Principal;
use crate::services::PaymentFlowService;
use chrono::{DateTime, Utc};
use salvo::prelude::*;
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};

pub fn routes() -> Router {
    Router::new()
        .push(Router::with_path("get-webhook-events").get(get_webhook_events))
        .push(Router::with_path("get-webhook-event-detail").get(get_webhook_event_detail))
        .push(Router::with_path("delete-webhook-event").post(delete_webhook_event))
        .push(Router::with_path("replay-webhook-event").post(replay_webhook_event))
        .push(Router::with_path("get-coupons").get(get_coupons))
        .push(Router::with_path("get-coupon").get(get_coupon))
        .push(Router::with_path("add-coupon").post(add_coupon))
        .push(Router::with_path("update-coupon").post(update_coupon))
        .push(Router::with_path("delete-coupon").post(delete_coupon))
        .push(Router::with_path("validate-coupon").post(validate_coupon))
        .push(Router::with_path("buy-product").post(buy_product))
        .push(Router::with_path("set-subscription-auto-renew").post(set_subscription_auto_renew))
        .push(Router::with_path("get-dashboard-heatmap").get(dashboard_heatmap))
        .push(Router::with_path("get-dashboard-mfa").get(dashboard_mfa))
        .push(Router::with_path("get-dashboard-providers").get(dashboard_providers))
        .push(Router::with_path("get-setting").get(get_setting))
        .push(Router::with_path("update-setting").post(update_setting))
        .push(Router::with_path("get-email-and-phone").get(get_email_and_phone))
        .push(Router::with_path("update-permissions").post(update_permissions))
        .push(Router::with_path("update-cert-domain-expire").post(update_cert_domain_expire))
}
fn db(depot: &Depot) -> AppResult<PgPool> {
    depot
        .obtain::<PgPool>()
        .cloned()
        .map_err(|_| AppError::Internal("Database unavailable".into()))
}
fn admin(depot: &Depot) -> AppResult<Principal> {
    let p = Principal::from_depot(depot)?;
    if !p.admin {
        return Err(denied());
    }
    Ok(p)
}
fn denied() -> AppError {
    AppError::Authorization("Operation is not permitted for this identity".into())
}
fn invalid(s: &str) -> AppError {
    AppError::Validation(s.into())
}
fn string<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}
fn required(v: &Value, key: &str) -> AppResult<String> {
    string(v, key)
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("{key} is required")))
}
async fn body(req: &mut Request) -> AppResult<Value> {
    let bytes = req
        .payload()
        .await
        .map_err(|_| invalid("Cannot read JSON body"))?;
    if bytes.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(bytes).map_err(|_| invalid("Invalid JSON body"))
    }
}
fn ok(data: Value) -> Json<Value> {
    Json(json!({"status":"ok","data":data}))
}
fn scope(p: &Principal, owner: Option<String>) -> AppResult<Option<String>> {
    if p.global_admin() {
        return Ok(owner.filter(|s| !s.is_empty() && s != "All"));
    }
    if owner
        .as_deref()
        .is_some_and(|s| !s.is_empty() && s != p.owner)
    {
        return Err(denied());
    }
    Ok(Some(p.owner.clone()))
}
fn reference(req: &Request, b: &Value) -> AppResult<String> {
    req.query::<String>("id")
        .or_else(|| string(b, "id").map(str::to_owned))
        .or_else(|| Some(format!("{}/{}", string(b, "owner")?, string(b, "name")?)))
        .ok_or_else(|| invalid("id or owner/name is required"))
}
async fn find(
    pool: &PgPool,
    table: &str,
    reference: &str,
    default_owner: &str,
) -> AppResult<Value> {
    let value: Option<Value> = if let Some((owner, name)) = reference.split_once('/') {
        sqlx::query_scalar(&format!("SELECT to_jsonb(t) FROM {table} t WHERE owner=$1 AND name=$2 AND (to_jsonb(t)->>'is_deleted') IS DISTINCT FROM 'true'"))
   .bind(owner).bind(name).fetch_optional(pool).await?
    } else {
        sqlx::query_scalar(&format!("SELECT to_jsonb(t) FROM {table} t WHERE (id=$1 OR (owner=$2 AND name=$1)) AND (to_jsonb(t)->>'is_deleted') IS DISTINCT FROM 'true' ORDER BY(id=$1) DESC LIMIT 1"))
   .bind(reference).bind(default_owner).fetch_optional(pool).await?
    };
    value.ok_or_else(|| AppError::NotFound("Object not found".into()))
}
fn pagination(req: &Request) -> (i64, i64) {
    let size = req
        .query::<i64>("pageSize")
        .or_else(|| req.query("page_size"))
        .unwrap_or(100)
        .clamp(1, 500);
    let page = req
        .query::<i64>("p")
        .or_else(|| req.query("page"))
        .unwrap_or(1)
        .max(1);
    (size, (page - 1).saturating_mul(size))
}
fn coupon_view(row: Value) -> Value {
    let mut data = row.get("data").cloned().unwrap_or_else(|| json!({}));
    for (from, to) in [
        ("id", "id"),
        ("owner", "owner"),
        ("name", "name"),
        ("code", "code"),
        ("used_count", "usedCount"),
        ("created_at", "createdTime"),
        ("updated_at", "updatedTime"),
    ] {
        data[to] = row[from].clone();
    }
    data
}
fn number(v: &Value, key: &str, default: f64) -> AppResult<f64> {
    let n = match v.get(key) {
        None | Some(Value::Null) => default,
        Some(n) => n
            .as_f64()
            .ok_or_else(|| invalid("Numeric coupon field expected"))?,
    };
    if n.is_finite() && n >= 0.0 {
        Ok(n)
    } else {
        Err(invalid("Amounts must be finite and non-negative"))
    }
}
fn integer(v: &Value, key: &str) -> AppResult<i64> {
    let n = match v.get(key) {
        None | Some(Value::Null) => 0,
        Some(n) => n
            .as_i64()
            .ok_or_else(|| invalid("Integer coupon limit expected"))?,
    };
    if n >= 0 {
        Ok(n)
    } else {
        Err(invalid("Coupon limits cannot be negative"))
    }
}
fn date(v: &Value, key: &str) -> AppResult<Option<DateTime<Utc>>> {
    if v.get(key)
        .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        return Err(invalid("Coupon validity must be an RFC3339 string"));
    }
    string(v, key)
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| invalid("Invalid coupon validity timestamp"))
        })
        .transpose()
}
fn coupon_config(mut value: Value) -> AppResult<Value> {
    if !value.is_object() {
        return Err(invalid("Coupon must be an object"));
    }
    for key in ["owner", "name", "code"] {
        let s = required(&value, key)?;
        if s.len() > 100 {
            return Err(invalid("Coupon identity exceeds 100 bytes"));
        }
    }
    let kind = string(&value, "discountType")
        .unwrap_or("percentage")
        .to_owned();
    if !matches!(kind.as_str(), "percentage" | "fixed") {
        return Err(invalid("Unknown discount type"));
    }
    let discount = number(&value, "discount", 0.0)?;
    if kind == "percentage" && discount > 100.0 {
        return Err(invalid("Percentage must not exceed 100"));
    }
    value["discountType"] = json!(kind);
    value["discount"] = json!(discount);
    for key in ["maxDiscount", "minOrderAmount"] {
        value[key] = json!(number(&value, key, 0.0)?);
    }
    for key in ["quantity", "maxUsagePerUser"] {
        value[key] = json!(integer(&value, key)?);
    }
    let scope = string(&value, "scope").unwrap_or("universal").to_owned();
    if !matches!(scope.as_str(), "universal" | "product" | "user") {
        return Err(invalid("Unknown coupon scope"));
    }
    value["scope"] = json!(scope);
    for key in ["products", "users"] {
        if value.get(key).is_none() {
            value[key] = json!([]);
        }
        if !value[key]
            .as_array()
            .is_some_and(|a| a.iter().all(|v| v.as_str().is_some()))
        {
            return Err(invalid("Coupon scope lists must contain strings"));
        }
    }
    let state = string(&value, "state").unwrap_or("Active").to_owned();
    if !matches!(state.as_str(), "Active" | "Inactive" | "Expired") {
        return Err(invalid("Unknown coupon state"));
    }
    value["state"] = json!(state);
    if let (Some(start), Some(end)) = (date(&value, "startTime")?, date(&value, "expireTime")?) {
        if start >= end {
            return Err(invalid("Coupon expiration must follow start time"));
        }
    }
    for key in ["id", "createdTime", "updatedTime", "usedCount"] {
        value.as_object_mut().unwrap().remove(key);
    }
    Ok(value)
}
#[handler]
pub async fn get_coupons(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let pool = db(depot)?;
    let owner = scope(&p, req.query("owner"))?;
    let (limit, offset) = pagination(req);
    let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(t) FROM coupons t WHERE ($1::text IS NULL OR owner=$1) ORDER BY created_at DESC LIMIT $2 OFFSET $3").bind(&owner).bind(limit).bind(offset).fetch_all(&pool).await?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM coupons WHERE ($1::text IS NULL OR owner=$1)")
            .bind(owner)
            .fetch_one(&pool)
            .await?;
    Ok(Json(
        json!({"status":"ok","data":rows.into_iter().map(coupon_view).collect::<Vec<_>>(),"data2":total,"total":total}),
    ))
}
#[handler]
pub async fn get_coupon(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let row = find(
        &db(depot)?,
        "coupons",
        &reference(req, &Value::Null)?,
        &p.owner,
    )
    .await?;
    p.check_owner(&row, "coupons")?;
    Ok(ok(coupon_view(row)))
}
#[handler]
pub async fn add_coupon(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let value = coupon_config(body(req).await?)?;
    p.check_owner(&value, "coupons")?;
    let pool = db(depot)?;
    let row:Value=sqlx::query_scalar("INSERT INTO coupons(id,owner,name,code,data) VALUES($1,$2,$3,$4,$5) RETURNING to_jsonb(coupons)")
 .bind(uuid::Uuid::new_v4().to_string()).bind(required(&value,"owner")?).bind(required(&value,"name")?).bind(required(&value,"code")?).bind(&value).fetch_one(&pool).await?;
    Ok(Json(
        json!({"status":"ok","data":true,"object":coupon_view(row)}),
    ))
}
#[handler]
pub async fn update_coupon(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let b = body(req).await?;
    let pool = db(depot)?;
    let row = find(&pool, "coupons", &reference(req, &b)?, &p.owner).await?;
    p.check_owner(&row, "coupons")?;
    let mut data = coupon_view(row.clone());
    for (k, v) in b
        .as_object()
        .ok_or_else(|| invalid("Coupon must be an object"))?
    {
        data[k] = v.clone();
    }
    let data = coupon_config(data)?;
    if data["owner"] != row["owner"] || data["name"] != row["name"] {
        return Err(invalid("Coupon identity cannot change"));
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT id FROM coupons WHERE id=$1 FOR UPDATE")
        .bind(required(&row, "id")?)
        .fetch_one(&mut *tx)
        .await?;
    let reservations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM coupon_usages WHERE coupon_id=$1")
            .bind(required(&row, "id")?)
            .fetch_one(&mut *tx)
            .await?;
    let quantity = integer(&data, "quantity")?;
    if quantity > 0 && quantity < reservations {
        return Err(invalid(
            "Quantity cannot be lower than redeemed or reserved count",
        ));
    }
    sqlx::query("UPDATE coupons SET code=$2,data=$3,updated_at=NOW() WHERE id=$1")
        .bind(required(&row, "id")?)
        .bind(required(&data, "code")?)
        .bind(&data)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(ok(json!(true)))
}
#[handler]
pub async fn delete_coupon(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let b = body(req).await?;
    let pool = db(depot)?;
    let row = find(&pool, "coupons", &reference(req, &b)?, &p.owner).await?;
    p.check_owner(&row, "coupons")?;
    let result=sqlx::query("DELETE FROM coupons WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM coupon_usages WHERE coupon_id=$1)").bind(required(&row,"id")?).execute(&pool).await?;
    if result.rows_affected() != 1 {
        return Err(AppError::Conflict(
            "Coupon has order history; deactivate it instead".into(),
        ));
    }
    Ok(ok(json!(true)))
}
async fn coupon_discount(
    tx: &mut Transaction<'_, Postgres>,
    owner: &str,
    code: &str,
    user_id: &str,
    user_name: &str,
    products: &[String],
    amount: f64,
    currency: &str,
) -> AppResult<(Value, f64)> {
    let row: Value = sqlx::query_scalar(
        "SELECT to_jsonb(t) FROM coupons t WHERE owner=$1 AND code=$2 FOR UPDATE",
    )
    .bind(owner)
    .bind(code)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| invalid("Coupon code is invalid"))?;
    let coupon = coupon_view(row.clone());
    let now = Utc::now();
    if string(&coupon, "state") != Some("Active")
        || date(&coupon, "startTime")?.is_some_and(|t| t > now)
        || date(&coupon, "expireTime")?.is_some_and(|t| t <= now)
    {
        return Err(invalid("Coupon is not active in this period"));
    }
    let (reserved, mine): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*),COUNT(*) FILTER(WHERE user_id=$2) FROM coupon_usages WHERE coupon_id=$1",
    )
    .bind(required(&row, "id")?)
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    let limit = integer(&coupon, "quantity")?;
    let user_limit = integer(&coupon, "maxUsagePerUser")?;
    if (limit > 0 && reserved >= limit) || (user_limit > 0 && mine >= user_limit) {
        return Err(invalid("Coupon usage limit reached"));
    }
    let matches = |field: &str, needle: &str| {
        coupon[field]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(needle)))
    };
    match string(&coupon, "scope") {
        Some("universal") => {}
        Some("user") if matches("users", user_name) || matches("users", user_id) => {}
        Some("product") if products.iter().any(|p| matches("products", p)) => {}
        _ => return Err(invalid("Coupon does not apply to this user/product")),
    }
    if amount < number(&coupon, "minOrderAmount", 0.0)?
        || string(&coupon, "currency").is_some_and(|c| c != currency)
    {
        return Err(invalid("Coupon currency or minimum amount does not match"));
    }
    let rate = number(&coupon, "discount", 0.0)?;
    let mut discount = if string(&coupon, "discountType") == Some("fixed") {
        rate
    } else {
        amount * rate / 100.0
    };
    let max = number(&coupon, "maxDiscount", 0.0)?;
    if max > 0.0 && string(&coupon, "discountType") == Some("percentage") {
        discount = discount.min(max);
    }
    discount = ((discount.min(amount) * 100.0).round() / 100.0).min(amount);
    Ok((coupon, discount))
}
#[handler]
pub async fn validate_coupon(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = Principal::from_depot(depot)?;
    let b = body(req).await?;
    let owner = required(&b, "owner")?;
    scope(&p, Some(owner.clone()))?;
    let amount = number(&b, "amount", 0.0)?;
    let products = b
        .get("products")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("products is required"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("Invalid product"))
        })
        .collect::<AppResult<Vec<_>>>()?;
    let pool = db(depot)?;
    let mut tx = pool.begin().await?;
    let (coupon, discount) = coupon_discount(
        &mut tx,
        &owner,
        &required(&b, "couponCode")?,
        &p.id,
        &p.name,
        &products,
        amount,
        string(&b, "currency").unwrap_or(""),
    )
    .await?;
    tx.rollback().await?;
    Ok(ok(
        json!({"coupon":{"name":coupon["name"],"displayName":coupon["displayName"],"discountType":coupon["discountType"],"discount":coupon["discount"],"maxDiscount":coupon["maxDiscount"],"scope":coupon["scope"]},"discount":discount}),
    ))
}
// Resolve and lock checkout configuration on the caller's transaction. A second
// pool acquisition here can deadlock a correctly configured single-connection pool.
async fn checkout_configuration(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    reference: &str,
    owner: &str,
) -> AppResult<Value> {
    if !matches!(table, "plans" | "pricings" | "roles") {
        return Err(invalid("Invalid checkout configuration"));
    }
    let value: Option<Value> = if let Some((reference_owner, name)) = reference.split_once('/') {
        sqlx::query_scalar(&format!("SELECT to_jsonb(t) FROM {table} t WHERE owner=$1 AND name=$2 AND is_deleted=false FOR SHARE"))
            .bind(reference_owner).bind(name).fetch_optional(&mut **tx).await?
    } else {
        sqlx::query_scalar(&format!("SELECT to_jsonb(t) FROM {table} t WHERE (id=$1 OR (owner=$2 AND name=$1)) AND is_deleted=false ORDER BY(id=$1) DESC LIMIT 1 FOR SHARE"))
            .bind(reference).bind(owner).fetch_optional(&mut **tx).await?
    };
    value.ok_or_else(|| AppError::NotFound("Checkout configuration not found".into()))
}

#[handler]
pub async fn buy_product(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = Principal::from_depot(depot)?;
    let pool = db(depot)?;
    let environment = req.query::<String>("paymentEnv").unwrap_or_default();
    if !matches!(environment.as_str(), "" | "Web" | "web") {
        return Err(invalid("This provider supports browser checkout only"));
    }
    let custom_price = req
        .query::<String>("customPrice")
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<f64>()
                .map_err(|_| invalid("customPrice must be a valid amount"))
        })
        .transpose()?;
    let pricing_ref = req.query::<String>("pricingName").filter(|s| !s.is_empty());
    let plan_ref = req.query::<String>("planName").filter(|s| !s.is_empty());
    if pricing_ref.is_some() != plan_ref.is_some() {
        return Err(invalid("pricingName and planName are required together"));
    }
    let initial_product = find(&pool, "products", &reference(req, &Value::Null)?, &p.owner).await?;
    p.check_owner(&initial_product, "products")?;
    let owner = required(&initial_product, "owner")?;
    let target = req
        .query::<String>("userName")
        .unwrap_or_else(|| p.name.clone());
    let user = find(&pool, "users", &target, &owner).await?;
    if required(&user, "owner")? != owner || (!p.admin && required(&user, "id")? != p.id) {
        return Err(denied());
    }
    if user["is_forbidden"] == true {
        return Err(invalid("User is disabled"));
    }
    let provider_ref = req
        .query::<String>("providerName")
        .ok_or_else(|| invalid("providerName is required"))?;
    let provider = find(&pool, "providers", &provider_ref, &owner).await?;
    if required(&provider, "owner")? != owner || string(&provider, "category") != Some("Payment") {
        return Err(denied());
    }
    let mut tx = pool.begin().await?;
    let product: Value=sqlx::query_scalar("SELECT to_jsonb(p) FROM products p WHERE id=$1 AND owner=$2 AND is_deleted=false FOR UPDATE")
        .bind(required(&initial_product,"id")?).bind(&owner).fetch_one(&mut *tx).await?;
    let is_recharge = product["is_recharge"] == true;
    let stock = product["quantity"].as_i64().unwrap_or(0);
    if stock == 0 && !is_recharge {
        return Err(invalid("Product is out of stock"));
    }
    if string(&product, "state").is_some_and(|s| {
        !matches!(
            s.to_ascii_lowercase().as_str(),
            "active" | "published" | "on sale"
        )
    }) {
        return Err(invalid("Product is not for sale"));
    }
    let currency = string(&product, "currency").unwrap_or("USD");
    let name = required(&product, "name")?;
    let mut amount = number(&product, "price", 0.0)?;
    let mut plan_id: Option<String> = None;
    let mut pricing_id: Option<String> = None;
    let mut plan_name: Option<String> = None;
    let mut pricing_name: Option<String> = None;
    let mut role_id: Option<String> = None;
    let mut period: Option<String> = None;
    if let (Some(pricing_ref), Some(plan_ref)) = (pricing_ref, plan_ref) {
        if is_recharge || custom_price.is_some_and(|v| v != 0.0) {
            return Err(invalid(
                "Subscription checkout cannot contain a recharge amount",
            ));
        }
        let plan = checkout_configuration(&mut tx, "plans", &plan_ref, &owner).await?;
        let pricing = checkout_configuration(&mut tx, "pricings", &pricing_ref, &owner).await?;
        if required(&plan, "owner")? != owner || required(&pricing, "owner")? != owner {
            return Err(denied());
        }
        if plan["is_enabled"] != true || pricing["is_enabled"] != true {
            return Err(invalid("Plan or pricing is disabled"));
        }
        let pid = required(&plan, "id")?;
        let pname = required(&plan, "name")?;
        if string(&product, "plan_id") != Some(pid.as_str()) {
            return Err(invalid("This product does not sell the selected plan"));
        }
        let allowed: Vec<String> = serde_json::from_str(string(&pricing, "plans").unwrap_or("[]"))
            .map_err(|_| invalid("Pricing plans must be an array of plan references"))?;
        if !allowed
            .iter()
            .any(|r| r == &pid || r == &pname || r == &format!("{owner}/{pname}"))
        {
            return Err(invalid("The selected plan does not belong to this pricing"));
        }
        if !string(&plan, "currency")
            .unwrap_or("USD")
            .eq_ignore_ascii_case(currency)
        {
            return Err(invalid("Plan and product currencies differ"));
        }
        let selected_period = req
            .query::<String>("period")
            .unwrap_or_else(|| "monthly".into())
            .to_ascii_lowercase();
        amount = match selected_period.as_str() {
            "monthly" => number(&plan, "price_per_month", 0.0)?,
            "yearly" => number(&plan, "price_per_year", 0.0)?,
            _ => return Err(invalid("period must be monthly or yearly")),
        };
        if let Some(role_ref) = string(&plan, "role") {
            let role = checkout_configuration(&mut tx, "roles", role_ref, &owner).await?;
            if required(&role, "owner")? != owner {
                return Err(denied());
            }
            if role["is_enabled"] != true {
                return Err(invalid("The plan role is disabled"));
            }
            role_id = Some(required(&role, "id")?);
        }
        let suspended: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM subscriptions WHERE owner=$1 AND user_id=$2 AND plan_id=$3 AND is_deleted=false AND lower(state)='suspended')")
            .bind(&owner).bind(required(&user,"id")?).bind(&pid).fetch_one(&mut *tx).await?;
        if suspended {
            return Err(invalid("This plan subscription is suspended"));
        }
        let lifetime: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM subscriptions WHERE owner=$1 AND user_id=$2 AND plan_id=$3 AND pricing_id=$4 AND is_deleted=false AND lower(state)='active' AND start_date<=clock_timestamp() AND end_date IS NULL)")
            .bind(&owner).bind(required(&user,"id")?).bind(&pid).bind(required(&pricing,"id")?).fetch_one(&mut *tx).await?;
        if lifetime {
            return Err(invalid(
                "An active lifetime subscription already covers this plan",
            ));
        }
        plan_id = Some(pid);
        plan_name = Some(pname);
        pricing_id = Some(required(&pricing, "id")?);
        pricing_name = Some(required(&pricing, "name")?);
        period = Some(selected_period);
    } else if is_recharge {
        if string(&product, "plan_id").is_some() {
            return Err(invalid("A recharge product cannot sell a plan"));
        }
        amount = custom_price.ok_or_else(|| invalid("customPrice is required for recharge"))?;
        let cents = crate::services::ProductService::validate_price(amount, true)?;
        let options: Vec<f64> = serde_json::from_value(product["recharge_options"].clone())
            .map_err(|_| invalid("Invalid recharge options"))?;
        let options = options
            .into_iter()
            .map(|v| crate::services::ProductService::validate_price(v, true))
            .collect::<AppResult<Vec<_>>>()?;
        if product["disable_custom_recharge"] == true && !options.contains(&cents) {
            return Err(invalid("Select one of the configured recharge amounts"));
        }
        if req
            .query::<String>("couponCode")
            .is_some_and(|s| !s.is_empty())
        {
            return Err(invalid("Recharge purchases cannot use coupons"));
        }
        let provider_type = string(&provider, "type")
            .unwrap_or("")
            .to_ascii_lowercase()
            .replace([' ', '-', '_'], "");
        if provider_type == "balance" {
            return Err(invalid("Recharge requires an external payment provider"));
        }
        PaymentFlowService::validate_balance_currency(&user, currency)?;
    } else {
        if string(&product, "plan_id").is_some() {
            return Err(invalid("This product requires pricingName and planName"));
        }
        if custom_price.is_some_and(|v| v != 0.0) {
            return Err(invalid(
                "A custom amount is only supported for recharge products",
            ));
        }
    }
    crate::services::ProductService::validate_price(amount, is_recharge)?;
    let order_id = uuid::Uuid::new_v4().to_string();
    let order_name = format!("buy-{}", &order_id[..12]);
    let discount = if let Some(code) = req.query::<String>("couponCode").filter(|s| !s.is_empty()) {
        Some(
            coupon_discount(
                &mut tx,
                &owner,
                &code,
                &required(&user, "id")?,
                &required(&user, "name")?,
                &[name.clone(), format!("{owner}/{name}")],
                amount,
                currency,
            )
            .await?,
        )
    } else {
        None
    };
    let price = amount - discount.as_ref().map(|(_, d)| *d).unwrap_or(0.0);
    if !price.is_finite() || price < 0.0 {
        return Err(invalid("Invalid checkout amount"));
    }
    let cents = crate::services::ProductService::validate_price(price, is_recharge)?;
    sqlx::query("INSERT INTO orders(id,owner,name,display_name,product_name,product_display_name,quantity,price,currency,state,\"user\",provider,plan_name,pricing_name) VALUES($1,$2,$3,$4,$5,$4,1,$6,$7,'Created',$8,$9,$10,$11)")
 .bind(&order_id).bind(&owner).bind(&order_name).bind(string(&product,"display_name").unwrap_or(&name)).bind(&name).bind(price).bind(currency).bind(required(&user,"name")?).bind(required(&provider,"id")?).bind(&plan_name).bind(&pricing_name).execute(&mut *tx).await?;
    if is_recharge || plan_id.is_some() {
        sqlx::query("INSERT INTO order_benefits(order_id,kind,user_id,amount_cents,plan_id,pricing_id,period,role_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&order_id).bind(if is_recharge {"recharge"} else {"plan"}).bind(required(&user,"id")?).bind(cents)
            .bind(&plan_id).bind(&pricing_id).bind(&period).bind(&role_id).execute(&mut *tx).await?;
    }
    if let Some((coupon, amount)) = &discount {
        sqlx::query("INSERT INTO coupon_usages(id,coupon_id,user_id,order_id,amount) VALUES($1,$2,$3,$4,$5)").bind(uuid::Uuid::new_v4().to_string()).bind(required(coupon,"id")?).bind(required(&user,"id")?).bind(&order_id).bind(amount).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let result = PaymentFlowService::start_order_payment(
        &pool,
        &order_id,
        Some(&required(&provider, "id")?),
        &owner,
        &required(&user, "name")?,
        false,
        None,
    )
    .await;
    match result {
        Ok(result) => Ok(Json(
            json!({"status":"ok","data":result.payment,"data2":result.attach_info,"order":result.order,"payUrl":result.pay_url,"autoPaid":result.auto_paid}),
        )),
        Err(error) => {
            // A remote transport error can leave a durable pending checkout.
            // Its verified notification or explicit cancellation resolves it.
            sqlx::query("UPDATE orders SET state='Failed',error_text=$2,updated_at=NOW() WHERE id=$1 AND state='Created' AND (payment_id IS NULL OR payment_id='')").bind(&order_id).bind(error.to_string()).execute(&pool).await?;
            Err(error)
        }
    }
}
#[handler]
pub async fn set_subscription_auto_renew(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<Value>> {
    let p = Principal::from_depot(depot)?;
    let pool = db(depot)?;
    let row = find(
        &pool,
        "subscriptions",
        &reference(req, &Value::Null)?,
        &p.owner,
    )
    .await?;
    p.check_owner(&row, "subscriptions")?;
    if !p.admin && string(&row, "user_id") != Some(p.id.as_str()) {
        return Err(denied());
    }
    let renew = match req.query::<String>("autoRenew").as_deref() {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(invalid("autoRenew must be true or false")),
    };
    sqlx::query("UPDATE subscriptions SET auto_renew=$2,updated_at=NOW() WHERE id=$1")
        .bind(required(&row, "id")?)
        .bind(renew)
        .execute(&pool)
        .await?;
    Ok(ok(json!(true)))
}
#[handler]
pub async fn dashboard_providers(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let owner = scope(&p, req.query("owner"))?;
    let rows:Vec<(String,i64)>=sqlx::query_as("SELECT COALESCE(NULLIF(type,''),'Unknown'),COUNT(*) FROM providers WHERE ($1::text IS NULL OR owner=$1) GROUP BY type ORDER BY COUNT(*) DESC,type").bind(owner).fetch_all(&db(depot)?).await?;
    Ok(ok(json!(
        rows.into_iter()
            .map(|(t, n)| json!({"type":t,"count":n}))
            .collect::<Vec<_>>()
    )))
}
#[handler]
pub async fn dashboard_mfa(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let owner = scope(&p, req.query("owner"))?;
    let(total,enabled):(i64,i64)=sqlx::query_as("SELECT COUNT(*),COUNT(*) FILTER(WHERE mfa_enabled OR mfa_phone_enabled OR mfa_email_enabled OR EXISTS(SELECT 1 FROM user_mfa m WHERE m.user_id=u.id AND m.is_enabled)) FROM users u WHERE is_deleted=false AND ($1::text IS NULL OR owner=$1)").bind(owner).fetch_one(&db(depot)?).await?;
    Ok(ok(
        json!({"total":total,"enabled":enabled,"disabled":total-enabled}),
    ))
}
#[handler]
pub async fn dashboard_heatmap(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let owner = scope(&p, req.query("owner"))?;
    let rows:Vec<(String,i64)>=sqlx::query_as("SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD'),COUNT(*) FROM records WHERE created_at>=NOW()-INTERVAL '1 year' AND action='login' AND ($1::text IS NULL OR COALESCE(NULLIF(organization,''),owner)=$1) GROUP BY 1 ORDER BY 1").bind(owner).fetch_all(&db(depot)?).await?;
    let max = rows.iter().map(|(_, n)| *n).max().unwrap_or(0);
    let now = Utc::now();
    Ok(ok(
        json!({"data":rows.into_iter().map(|(date,count)|json!({"date":date,"count":count})).collect::<Vec<_>>(),"maxCount":max,"dateRange":[(now-chrono::Duration::days(365)).format("%Y-%m-%d").to_string(),now.format("%Y-%m-%d").to_string()]}),
    ))
}
#[handler]
pub async fn get_setting(depot: &mut Depot) -> AppResult<Json<Value>> {
    if !admin(depot)?.global_admin() {
        return Err(denied());
    }
    let data:Value=sqlx::query_scalar("SELECT data||jsonb_build_object('createdTime',created_at,'updatedTime',updated_at) FROM operation_settings WHERE singleton").fetch_one(&db(depot)?).await?;
    Ok(ok(data))
}
#[handler]
pub async fn update_setting(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    if !admin(depot)?.global_admin() {
        return Err(denied());
    }
    let b = body(req).await?;
    let mut data = json!({"owner":"admin","name":"setting-built-in"});
    for key in [
        "dbMaxOpenConns",
        "dbMaxIdleConns",
        "dbConnMaxLifetime",
        "recordRetentionDays",
    ] {
        data[key] = json!(integer(&b, key)?);
    }
    if integer(&data, "dbMaxOpenConns")? > 0
        && integer(&data, "dbMaxIdleConns")? > integer(&data, "dbMaxOpenConns")?
    {
        return Err(invalid("Max idle connections exceeds max open connections"));
    }
    sqlx::query("UPDATE operation_settings SET data=$1,updated_at=NOW() WHERE singleton")
        .bind(&data)
        .execute(&db(depot)?)
        .await?;
    Ok(Json(
        json!({"status":"ok","data":true,"applied":false,"msg":"Settings saved; runtime pool/retention application requires startup integration"}),
    ))
}
#[handler]
pub async fn get_email_and_phone(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = Principal::from_depot(depot)?;
    let owner = req
        .query::<String>("organization")
        .unwrap_or_else(|| p.owner.clone());
    scope(&p, Some(owner.clone()))?;
    let name = req
        .query::<String>("username")
        .unwrap_or_else(|| p.name.clone());
    let user = find(&db(depot)?, "users", &format!("{owner}/{name}"), &owner).await?;
    if !p.admin && required(&user, "id")? != p.id {
        return Err(denied());
    }
    let email = string(&user, "email").map(|s| {
        let (local, domain) = s.split_once('@').unwrap_or((s, ""));
        format!(
            "{}***@{}",
            local.chars().take(2).collect::<String>(),
            domain
        )
    });
    let phone = string(&user, "phone").map(|s| {
        format!(
            "***{}",
            s.chars()
                .rev()
                .take(4)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
        )
    });
    Ok(ok(json!({"email":email,"phone":phone})))
}
#[handler]
pub async fn update_permissions(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let b = body(req).await?;
    let permissions = b
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 500)
        .ok_or_else(|| invalid("Expected 1 to 500 permissions"))?;
    let pool = db(depot)?;
    let mut changes = Vec::new();
    for item in permissions {
        let id = reference(&Request::new(), item)?;
        let existing = find(&pool, "permissions", &id, &p.owner).await?;
        p.check_owner(&existing, "permissions")?;
        crate::hoops::authz::validate_references(&pool, &p, item).await?;
        let mut merged = existing.clone();
        for (key, val) in item
            .as_object()
            .ok_or_else(|| invalid("Permission must be an object"))?
        {
            let key = match key.as_str() {
                "displayName" => "display_name",
                "resourceType" => "resource_type",
                "isEnabled" => "is_enabled",
                key => key,
            };
            if matches!(
                key,
                "display_name"
                    | "description"
                    | "resource_type"
                    | "resources"
                    | "actions"
                    | "effect"
                    | "is_enabled"
            ) {
                merged[key] = val.clone();
            }
        }
        let effect = string(&merged, "effect")
            .unwrap_or("allow")
            .to_ascii_lowercase();
        if !matches!(effect.as_str(), "allow" | "deny") {
            return Err(invalid("Permission effect must be allow or deny"));
        }
        merged["effect"] = json!(effect);
        changes.push(merged);
    }
    let mut tx = pool.begin().await?;
    for item in changes {
        let text = |key: &str| match item.get(key) {
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
            None => String::new(),
        };
        sqlx::query("UPDATE permissions SET display_name=$2,description=$3,resource_type=$4,resources=$5,actions=$6,effect=$7,is_enabled=$8,updated_at=NOW() WHERE id=$1 AND owner=$9")
 .bind(required(&item,"id")?).bind(text("display_name")).bind(text("description")).bind(text("resource_type")).bind(text("resources")).bind(text("actions")).bind(text("effect")).bind(item["is_enabled"].as_bool().ok_or_else(||invalid("isEnabled must be boolean"))?).bind(required(&item,"owner")?).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(ok(json!(true)))
}
pub fn rdap_expiration(data: &Value) -> AppResult<DateTime<Utc>> {
    data.get("events")
        .and_then(Value::as_array)
        .and_then(|events| {
            events
                .iter()
                .find(|event| string(event, "eventAction") == Some("expiration"))
        })
        .and_then(|event| string(event, "eventDate"))
        .ok_or_else(|| invalid("RDAP returned no expiration date"))
        .and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| invalid("RDAP returned an invalid date"))
        })
}
#[handler]
pub async fn update_cert_domain_expire(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let pool = db(depot)?;
    let cert = find(
        &pool,
        "certificates",
        &reference(req, &Value::Null)?,
        &p.owner,
    )
    .await?;
    p.check_owner(&cert, "certificates")?;
    let domain = required(&cert, "name")?;
    if !domain.contains('.')
        || domain.len() > 253
        || domain.parse::<std::net::IpAddr>().is_ok()
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(invalid("Certificate name must be a DNS domain"));
    }
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .get(format!("https://rdap.org/domain/{domain}"))
        .send()
        .await
        .map_err(|e| AppError::Validation(format!("RDAP lookup failed: {e}")))?
        .error_for_status()
        .map_err(|e| AppError::Validation(format!("RDAP lookup failed: {e}")))?;
    let data: Value = response
        .json()
        .await
        .map_err(|_| invalid("Invalid RDAP response"))?;
    let expires = rdap_expiration(&data)?;
    sqlx::query("UPDATE certificates SET domain_expire_time=$2 WHERE id=$1")
        .bind(required(&cert, "id")?)
        .bind(expires)
        .execute(&pool)
        .await?;
    Ok(Json(
        json!({"status":"ok","data":true,"domainExpireTime":expires}),
    ))
}

fn event_access(p: &Principal, event: &Value) -> AppResult<()> {
    if p.global_admin() || string(event, "organization") == Some(p.owner.as_str()) {
        Ok(())
    } else {
        Err(denied())
    }
}
fn mask_event(mut event: Value) -> Value {
    fn mask(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    let key = key.to_ascii_lowercase();
                    if key.contains("password")
                        || key.contains("secret")
                        || key.contains("token")
                        || key == "authorization"
                        || key == "cookie"
                        || key == "recoverycodes"
                        || key == "recovery_codes"
                    {
                        *value = json!("***");
                    } else {
                        mask(value);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(mask),
            _ => {}
        }
    }
    // Response text is untrusted and may echo request credentials. Keep only the
    // delivery status/error in API views; raw response remains in the audit table.
    if let Some(object) = event.as_object_mut() {
        object.remove("response_body");
    }
    mask(&mut event);
    event
}
#[handler]
pub async fn get_webhook_events(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let pool = db(depot)?;
    let organization = scope(&p, req.query("organization"))?;
    let owner = if p.global_admin() {
        req.query::<String>("owner")
    } else {
        None
    };
    let webhook = if let Some(reference) = req.query::<String>("webhook") {
        let webhook = find(&pool, "webhooks", &reference, &p.owner).await?;
        Some(required(&webhook, "id")?)
    } else {
        None
    };
    let state = req.query::<String>("state");
    let (limit, offset) = pagination(req);
    let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(t) FROM webhook_events t WHERE ($1::text IS NULL OR organization=$1) AND ($2::text IS NULL OR owner=$2) AND ($3::text IS NULL OR webhook_id=$3) AND ($4::text IS NULL OR state=$4) ORDER BY created_at DESC LIMIT $5 OFFSET $6")
        .bind(&organization).bind(&owner).bind(&webhook).bind(&state).bind(limit).bind(offset).fetch_all(&pool).await?;
    let total:i64=sqlx::query_scalar("SELECT COUNT(*) FROM webhook_events WHERE ($1::text IS NULL OR organization=$1) AND ($2::text IS NULL OR owner=$2) AND ($3::text IS NULL OR webhook_id=$3) AND ($4::text IS NULL OR state=$4)")
        .bind(organization).bind(owner).bind(webhook).bind(state).fetch_one(&pool).await?;
    Ok(Json(
        json!({"status":"ok","data":rows.into_iter().map(mask_event).collect::<Vec<_>>(),"data2":total,"total":total}),
    ))
}
#[handler]
pub async fn get_webhook_event_detail(
    depot: &mut Depot,
    req: &mut Request,
) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let event = find(
        &db(depot)?,
        "webhook_events",
        &reference(req, &Value::Null)?,
        &p.owner,
    )
    .await?;
    event_access(&p, &event)?;
    Ok(ok(mask_event(event)))
}
#[handler]
pub async fn delete_webhook_event(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let pool = db(depot)?;
    let b = body(req).await?;
    let event = find(&pool, "webhook_events", &reference(req, &b)?, &p.owner).await?;
    event_access(&p, &event)?;
    let result = sqlx::query("DELETE FROM webhook_events WHERE id=$1 AND state<>'Retrying'")
        .bind(required(&event, "id")?)
        .execute(&pool)
        .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::Conflict("Delivery is in progress".into()));
    }
    Ok(ok(json!(true)))
}
#[handler]
pub async fn replay_webhook_event(depot: &mut Depot, req: &mut Request) -> AppResult<Json<Value>> {
    let p = admin(depot)?;
    let pool = db(depot)?;
    let event = find(
        &pool,
        "webhook_events",
        &reference(req, &Value::Null)?,
        &p.owner,
    )
    .await?;
    event_access(&p, &event)?;
    let result = crate::services::webhook_executor::WebhookExecutor::replay_event(
        &pool,
        &required(&event, "id")?,
    )
    .await?;
    let success = string(&result, "state") == Some("Success");
    Ok(Json(
        json!({"status":if success{"ok"}else{"error"},"data":mask_event(result),"msg":if success{"Webhook delivered"}else{"Webhook delivery failed; see recorded status"}}),
    ))
}
