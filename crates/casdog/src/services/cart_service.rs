//! Server-side cart and immutable multi-line order snapshots. Creating an order
//! never charges the account; normal PaymentFlow settles the one parent payment.
use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    models::{Order, Plan, Pricing, Product, Provider, Role, User},
    services::ProductService,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::collections::HashMap;
use uuid::Uuid;
pub struct CartService;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CartItemInput {
    #[serde(rename = "productId", alias = "product_id", alias = "name")]
    pub product_id: String,
    pub quantity: i32,
    #[serde(default, rename = "pricingName", alias = "pricing_name")]
    pub pricing_name: Option<String>,
    #[serde(default, rename = "planName", alias = "plan_name")]
    pub plan_name: Option<String>,
    #[serde(default)]
    pub period: Option<String>,
    #[serde(
        default,
        rename = "customPrice",
        alias = "custom_price",
        alias = "price"
    )]
    pub custom_price: Option<f64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceCart {
    pub revision: i64,
    pub items: Vec<CartItemInput>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutCart {
    pub revision: i64,
    #[serde(rename = "providerId", alias = "provider_id")]
    pub provider_id: String,
    #[serde(rename = "expectedTotalCents", alias = "expected_total_cents")]
    pub expected_total_cents: i64,
    pub currency: String,
    #[serde(default, rename = "couponCode", alias = "coupon_code")]
    pub coupon_code: Option<String>,
}
#[derive(sqlx::FromRow)]
struct StoredItem {
    id: String,
    product_id: String,
    quantity: i32,
    pricing_id: Option<String>,
    plan_id: Option<String>,
    period: Option<String>,
    custom_amount_cents: Option<i64>,
    currency: String,
}
#[derive(Clone, Debug, sqlx::FromRow)]
pub(crate) struct OrderLine {
    pub id: String,
    pub order_id: String,
    pub product_id: String,
    pub product_name: String,
    pub display_name: String,
    pub kind: String,
    pub user_id: String,
    pub quantity: i32,
    pub unit_amount_cents: i64,
    pub amount_cents: i64,
    pub currency: String,
    pub plan_id: Option<String>,
    pub pricing_id: Option<String>,
    pub period: Option<String>,
    pub role_id: Option<String>,
    pub subscription_id: Option<String>,
    pub fulfilled_at: Option<chrono::DateTime<chrono::Utc>>,
}
struct Quote {
    product: Product,
    kind: String,
    plan: Option<Plan>,
    pricing: Option<Pricing>,
    role_id: Option<String>,
    period: Option<String>,
    unit: i64,
    total: i64,
    currency: String,
    custom: Option<i64>,
}
fn invalid(s: &str) -> AppError {
    AppError::Validation(s.into())
}
fn conflict(s: &str) -> AppError {
    AppError::Conflict(s.into())
}
fn denied() -> AppError {
    AppError::Authorization("The cart belongs to the current real user and tenant".into())
}
fn total(unit: i64, quantity: i32) -> AppResult<i64> {
    unit.checked_mul(quantity as i64)
        .filter(|v| *v <= 900_000_000_000_000)
        .ok_or_else(|| invalid("Cart amount is out of range"))
}
impl CartService {
    async fn actor(conn: &mut PgConnection, p: &Principal, lock: bool) -> AppResult<User> {
        if p.is_application() {
            return Err(denied());
        }
        let query = format!(
            "SELECT u.* FROM users u JOIN organizations o ON o.name=u.owner WHERE u.id=$1 AND u.owner=$2 AND NOT u.is_deleted AND NOT u.is_forbidden AND NOT o.is_deleted AND NOT o.disable_signin{}",
            if lock { " FOR SHARE OF u,o" } else { "" }
        );
        sqlx::query_as(&query)
            .bind(&p.id)
            .bind(&p.owner)
            .fetch_optional(conn)
            .await?
            .ok_or_else(denied)
    }
    async fn lock_cart(conn: &mut PgConnection, p: &Principal) -> AppResult<i64> {
        sqlx::query("INSERT INTO carts(user_id,owner) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(&p.id)
            .bind(&p.owner)
            .execute(&mut *conn)
            .await?;
        let (owner, revision): (String, i64) =
            sqlx::query_as("SELECT owner,revision FROM carts WHERE user_id=$1 FOR UPDATE")
                .bind(&p.id)
                .fetch_one(conn)
                .await?;
        if owner != p.owner {
            return Err(denied());
        }
        Ok(revision)
    }
    async fn product(
        conn: &mut PgConnection,
        owner: &str,
        reference: &str,
        lock: bool,
    ) -> AppResult<Product> {
        let sql = format!(
            "SELECT * FROM products WHERE id=$1 OR (owner=$2 AND (name=$1 OR owner||'/'||name=$1)) ORDER BY (id=$1) DESC LIMIT 1{}",
            if lock { " FOR SHARE" } else { "" }
        );
        let p: Product = sqlx::query_as(&sql)
            .bind(reference)
            .bind(owner)
            .fetch_optional(conn)
            .await?
            .ok_or_else(|| AppError::NotFound("Cart product not found".into()))?;
        if p.owner != owner {
            return Err(denied());
        }
        Ok(p)
    }
    async fn config(
        conn: &mut PgConnection,
        table: &str,
        owner: &str,
        reference: &str,
    ) -> AppResult<Value> {
        let query = format!(
            "SELECT to_jsonb(t) FROM {table} t WHERE id=$1 OR (owner=$2 AND (name=$1 OR owner||'/'||name=$1)) ORDER BY (id=$1) DESC LIMIT 1 FOR SHARE"
        );
        let value: Value = sqlx::query_scalar(&query)
            .bind(reference)
            .bind(owner)
            .fetch_optional(conn)
            .await?
            .ok_or_else(|| invalid("Cart plan, pricing or role is unavailable"))?;
        if value["owner"].as_str() != Some(owner) {
            return Err(denied());
        }
        if value["is_deleted"] == true || value["is_enabled"] != true {
            return Err(invalid("Cart plan, pricing or role is disabled"));
        }
        Ok(value)
    }
    async fn quote(
        conn: &mut PgConnection,
        p: &Principal,
        input: &CartItemInput,
        product: Product,
    ) -> AppResult<Quote> {
        if !(1..=1000).contains(&input.quantity) {
            return Err(invalid("Cart quantity must be between 1 and 1000"));
        }
        if product.is_deleted
            || !matches!(
                product.state.to_ascii_lowercase().as_str(),
                "active" | "published" | "on sale"
            )
        {
            return Err(invalid("Cart product is unavailable"));
        }
        if !product.is_recharge && product.quantity >= 0 && product.quantity < input.quantity {
            return Err(conflict("Cart product does not have enough stock"));
        }
        let currency = product
            .currency
            .clone()
            .unwrap_or_else(|| "USD".into())
            .to_ascii_uppercase();
        let mut quote = Quote {
            kind: "product".into(),
            unit: ProductService::validate_price(product.price, false)?,
            product,
            plan: None,
            pricing: None,
            role_id: None,
            period: None,
            total: 0,
            currency,
            custom: None,
        };
        if let Some(plan_ref) = input.plan_name.as_deref().filter(|v| !v.is_empty()) {
            if input.quantity > 120
                || quote.product.is_recharge
                || input.custom_price.is_some_and(|v| v != 0.0)
            {
                return Err(invalid("Invalid plan cart quantity or recharge amount"));
            }
            let pricing_ref = input
                .pricing_name
                .as_deref()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| invalid("Cart plan requires pricingName"))?;
            let plan: Plan =
                serde_json::from_value(Self::config(conn, "plans", &p.owner, plan_ref).await?)
                    .map_err(|_| invalid("Invalid cart plan"))?;
            let pricing_ref = Self::config(conn, "pricings", &p.owner, pricing_ref).await?;
            let pricing_id = pricing_ref["id"]
                .as_str()
                .ok_or_else(|| invalid("Invalid cart pricing"))?;
            let pricing = super::pricing_access_service::PricingAccessService::ensure_allowed_conn(
                conn, pricing_id, &p.id, &p.owner,
            )
            .await?;
            if quote.product.plan_id.as_deref() != Some(&plan.id)
                || !plan
                    .currency
                    .as_deref()
                    .unwrap_or("USD")
                    .eq_ignore_ascii_case(&quote.currency)
            {
                return Err(invalid("Cart plan does not match product or currency"));
            }
            let members: Vec<String> =
                serde_json::from_str(pricing.plans.as_deref().unwrap_or("[]"))
                    .map_err(|_| invalid("Invalid cart pricing plans"))?;
            if !members.iter().any(|v| {
                v == &plan.id || v == &plan.name || v == &format!("{}/{}", p.owner, plan.name)
            }) {
                return Err(invalid("Cart plan does not belong to this pricing"));
            }
            if let Some(reference) = plan.role.as_deref().filter(|v| !v.is_empty()) {
                let role: Role =
                    serde_json::from_value(Self::config(conn, "roles", &p.owner, reference).await?)
                        .map_err(|_| invalid("Invalid cart role"))?;
                quote.role_id = Some(role.id);
            }
            let period = input
                .period
                .as_deref()
                .unwrap_or("monthly")
                .to_ascii_lowercase();
            quote.unit = ProductService::validate_price(
                match period.as_str() {
                    "monthly" => plan.price_per_month,
                    "yearly" => plan.price_per_year,
                    _ => return Err(invalid("Cart plan period must be monthly or yearly")),
                },
                false,
            )?;
            let unavailable:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM subscriptions WHERE owner=$1 AND user_id=$2 AND plan_id=$3 AND NOT is_deleted AND (lower(state)='suspended' OR (pricing_id=$4 AND lower(state)='active' AND end_date IS NULL)))").bind(&p.owner).bind(&p.id).bind(&plan.id).bind(&pricing.id).fetch_one(&mut *conn).await?;
            if unavailable {
                return Err(conflict("Cart plan subscription is suspended or lifetime"));
            }
            quote.kind = "plan".into();
            quote.period = Some(period);
            quote.plan = Some(plan);
            quote.pricing = Some(pricing);
        } else if quote.product.is_recharge {
            if input.pricing_name.as_deref().is_some_and(|s| !s.is_empty())
                || quote.product.plan_id.is_some()
            {
                return Err(invalid("Recharge cannot contain plan configuration"));
            }
            let amount = input
                .custom_price
                .ok_or_else(|| invalid("Recharge cart item requires customPrice"))?;
            quote.unit = ProductService::validate_price(amount, true)?;
            if quote.product.disable_custom_recharge {
                let options: Vec<f64> =
                    serde_json::from_value(quote.product.recharge_options.clone())
                        .map_err(|_| invalid("Invalid recharge options"))?;
                let mut found = false;
                for option in options {
                    if ProductService::validate_price(option, true)? == quote.unit {
                        found = true;
                    }
                }
                if !found {
                    return Err(invalid("Select a configured recharge amount"));
                }
            }
            quote.custom = Some(quote.unit);
            quote.kind = "recharge".into();
        } else if quote.product.plan_id.is_some()
            || input.pricing_name.as_deref().is_some_and(|s| !s.is_empty())
            || input.custom_price.is_some_and(|v| v != 0.0)
        {
            return Err(invalid("Cart item has incompatible plan or custom price"));
        }
        quote.total = total(quote.unit, input.quantity)?;
        Ok(quote)
    }
    fn key(q: &Quote) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            q.product.id,
            q.plan.as_ref().map(|v| v.id.as_str()).unwrap_or(""),
            q.pricing.as_ref().map(|v| v.id.as_str()).unwrap_or(""),
            q.period.as_deref().unwrap_or(""),
            q.custom.unwrap_or(0)
        )
    }
    async fn stored(conn: &mut PgConnection, p: &Principal) -> AppResult<Vec<StoredItem>> {
        Ok(
            sqlx::query_as("SELECT * FROM cart_items WHERE user_id=$1 ORDER BY position")
                .bind(&p.id)
                .fetch_all(conn)
                .await?,
        )
    }
    fn input(item: &StoredItem) -> CartItemInput {
        CartItemInput {
            product_id: item.product_id.clone(),
            quantity: item.quantity,
            pricing_name: item.pricing_id.clone(),
            plan_name: item.plan_id.clone(),
            period: item.period.clone(),
            custom_price: item.custom_amount_cents.map(|c| c as f64 / 100.0),
        }
    }
    pub async fn get(pool: &PgPool, p: &Principal) -> AppResult<Value> {
        let mut tx = pool.begin().await?;
        Self::actor(&mut tx, p, false).await?;
        let revision = Self::lock_cart(&mut tx, p).await?;
        let items = Self::stored(&mut tx, p).await?;
        let mut response = vec![];
        let mut sum = 0i64;
        let mut currency = None;
        let mut valid = true;
        for item in items {
            let current = Self::product(&mut tx, &p.owner, &item.product_id, false).await;
            let fallback = current
                .as_ref()
                .ok()
                .map(|p| (p.name.clone(), p.display_name.clone(), p.image.clone()));
            let quote = match current {
                Ok(product) => Self::quote(&mut tx, p, &Self::input(&item), product).await,
                Err(e) => Err(e),
            };
            match quote {
                Ok(q) => {
                    let error = if item.currency != q.currency {
                        Some("Cart product currency changed")
                    } else if currency.as_ref().is_some_and(|c| c != &q.currency) {
                        Some("Cart contains multiple currencies")
                    } else {
                        None
                    };
                    if currency.is_none() {
                        currency = Some(q.currency.clone());
                    }
                    if error.is_some() {
                        valid = false;
                    }
                    sum = sum
                        .checked_add(q.total)
                        .filter(|v| *v <= 900_000_000_000_000)
                        .ok_or_else(|| invalid("Cart total is out of range"))?;
                    response.push(json!({"id":item.id,"product_id":q.product.id,"name":q.product.name,"display_name":q.product.display_name,"image":q.product.image,"quantity":item.quantity,"pricing_name":q.pricing.as_ref().map(|p|&p.name),"plan_name":q.plan.as_ref().map(|p|&p.name),"period":q.period,"custom_price":item.custom_amount_cents.map(|c|c as f64/100.0),"unit_amount_cents":q.unit,"total_amount_cents":q.total,"currency":q.currency,"valid":error.is_none(),"error":error}));
                }
                Err(error) => {
                    valid = false;
                    response.push(json!({"id":item.id,"product_id":item.product_id,"name":fallback.as_ref().map(|p|p.0.as_str()).unwrap_or("Unavailable product"),"display_name":fallback.as_ref().map(|p|p.1.as_str()),"image":fallback.as_ref().and_then(|p|p.2.as_deref()),"quantity":item.quantity,"pricing_name":item.pricing_id,"plan_name":item.plan_id,"period":item.period,"custom_price":item.custom_amount_cents.map(|c|c as f64/100.0),"currency":item.currency,"valid":false,"error":error.to_string()}));
                }
            }
        }
        tx.commit().await?;
        Ok(
            json!({"revision":revision,"items":response,"total_amount_cents":sum,"currency":currency,"valid":valid}),
        )
    }
    async fn reference_id(
        conn: &mut PgConnection,
        table: &str,
        owner: &str,
        reference: &str,
    ) -> AppResult<Option<String>> {
        let query = format!(
            "SELECT id,owner FROM {table} WHERE id=$1 OR (owner=$2 AND (name=$1 OR owner||'/'||name=$1)) ORDER BY (id=$1) DESC LIMIT 1"
        );
        let row: Option<(String, String)> = sqlx::query_as(&query)
            .bind(reference)
            .bind(owner)
            .fetch_optional(conn)
            .await?;
        match row {
            Some((id, tenant)) if tenant == owner => Ok(Some(id)),
            Some(_) => Err(denied()),
            None => Ok(None),
        }
    }
    /// An existing invalid row can always be removed without re-accepting other
    /// invalid rows. Only exact existing variants with equal/reduced quantities
    /// qualify; additions, increases and checkout take the full validation path.
    async fn only_reduce(
        conn: &mut PgConnection,
        p: &Principal,
        existing: &[StoredItem],
        inputs: &[CartItemInput],
    ) -> AppResult<Option<Vec<(String, i32)>>> {
        let key = |product: &str,
                   plan: &Option<String>,
                   pricing: &Option<String>,
                   period: &Option<String>,
                   custom: Option<i64>| {
            json!([product, plan, pricing, period, custom]).to_string()
        };
        let available: HashMap<String, &StoredItem> = existing
            .iter()
            .map(|i| {
                (
                    key(
                        &i.product_id,
                        &i.plan_id,
                        &i.pricing_id,
                        &i.period,
                        i.custom_amount_cents,
                    ),
                    i,
                )
            })
            .collect();
        let mut requested = HashMap::<String, i32>::new();
        for input in inputs {
            if !(1..=1000).contains(&input.quantity) {
                return Err(invalid("Invalid cart quantity"));
            }
            let Some(product) =
                Self::reference_id(conn, "products", &p.owner, &input.product_id).await?
            else {
                return Ok(None);
            };
            let plan = if let Some(reference) = input.plan_name.as_deref().filter(|s| !s.is_empty())
            {
                let Some(id) = Self::reference_id(conn, "plans", &p.owner, reference).await? else {
                    return Ok(None);
                };
                Some(id)
            } else {
                None
            };
            let pricing = if let Some(reference) =
                input.pricing_name.as_deref().filter(|s| !s.is_empty())
            {
                let Some(id) = Self::reference_id(conn, "pricings", &p.owner, reference).await?
                else {
                    return Ok(None);
                };
                Some(id)
            } else {
                None
            };
            let period = plan.as_ref().map(|_| {
                input
                    .period
                    .as_deref()
                    .unwrap_or("monthly")
                    .to_ascii_lowercase()
            });
            let custom = match input.custom_price {
                Some(price) if price != 0.0 => Some(ProductService::validate_price(price, true)?),
                _ => None,
            };
            let variant = key(&product, &plan, &pricing, &period, custom);
            let Some(previous) = available.get(&variant) else {
                return Ok(None);
            };
            let quantity = requested.entry(variant).or_default();
            *quantity = quantity
                .checked_add(input.quantity)
                .ok_or_else(|| invalid("Cart quantity overflow"))?;
            if *quantity > previous.quantity {
                return Ok(None);
            }
        }
        Ok(Some(
            requested
                .into_iter()
                .map(|(key, quantity)| (available[&key].id.clone(), quantity))
                .collect(),
        ))
    }

    pub async fn replace(pool: &PgPool, p: &Principal, request: ReplaceCart) -> AppResult<Value> {
        if request.revision < 0 || request.items.len() > 100 {
            return Err(invalid("Invalid cart revision or size"));
        }
        let mut tx = pool.begin().await?;
        Self::actor(&mut tx, p, false).await?;
        let revision = Self::lock_cart(&mut tx, p).await?;
        if revision != request.revision {
            return Err(conflict("Cart changed; reload before editing"));
        }
        let existing = Self::stored(&mut tx, p).await?;
        if let Some(reduced) = Self::only_reduce(&mut tx, p, &existing, &request.items).await? {
            Self::actor(&mut tx, p, true).await?;
            let ids: Vec<String> = reduced.iter().map(|(id, _)| id.clone()).collect();
            sqlx::query("DELETE FROM cart_items WHERE user_id=$1 AND NOT(id=ANY($2))")
                .bind(&p.id)
                .bind(&ids)
                .execute(&mut *tx)
                .await?;
            for (id, quantity) in reduced {
                sqlx::query("UPDATE cart_items SET quantity=$2 WHERE id=$1 AND user_id=$3")
                    .bind(id)
                    .bind(quantity)
                    .bind(&p.id)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("UPDATE carts SET revision=revision+1,updated_at=NOW() WHERE user_id=$1")
                .bind(&p.id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Self::get(pool, p).await;
        }
        let mut quotes = Vec::<(i32, Quote)>::new();
        let mut variants = HashMap::new();
        let mut currency = None;
        let mut resolved = Vec::new();
        for input in request.items {
            let product = Self::product(&mut tx, &p.owner, &input.product_id, false).await?;
            resolved.push((input, product.id));
        }
        let ids: Vec<String> = resolved.iter().map(|(_, id)| id.clone()).collect();
        let products: Vec<Product> =
            sqlx::query_as("SELECT * FROM products WHERE id=ANY($1) ORDER BY id FOR SHARE")
                .bind(&ids)
                .fetch_all(&mut *tx)
                .await?;
        let products: HashMap<String, Product> =
            products.into_iter().map(|p| (p.id.clone(), p)).collect();
        for (input, id) in resolved {
            let product = products
                .get(&id)
                .cloned()
                .ok_or_else(|| invalid("Cart product is unavailable"))?;
            let q = Self::quote(&mut tx, p, &input, product).await?;
            if currency.as_ref().is_some_and(|c| c != &q.currency) {
                return Err(invalid("Cart products must use one currency"));
            }
            currency = Some(q.currency.clone());
            let key = Self::key(&q);
            if let Some(index) = variants.get(&key).copied() {
                let (quantity, _): &mut (i32, Quote) = &mut quotes[index];
                *quantity = quantity
                    .checked_add(input.quantity)
                    .filter(|q| *q <= 1000)
                    .ok_or_else(|| invalid("Cart quantity exceeds limit"))?;
            } else {
                variants.insert(key, quotes.len());
                quotes.push((input.quantity, q));
            }
        }
        // Validate combined variants of one SKU, not each row independently.
        let mut demand = HashMap::<String, i32>::new();
        for (quantity, q) in &quotes {
            if q.kind != "recharge" {
                let entry = demand.entry(q.product.id.clone()).or_default();
                *entry = entry
                    .checked_add(*quantity)
                    .ok_or_else(|| invalid("Cart quantity overflow"))?;
                if q.product.quantity >= 0 && *entry > q.product.quantity {
                    return Err(conflict("Cart product does not have enough stock"));
                }
            }
            if q.kind == "plan" && *quantity > 120 {
                return Err(invalid("Plan quantity exceeds limit"));
            }
        }
        Self::actor(&mut tx, p, true).await?;
        sqlx::query("DELETE FROM cart_items WHERE user_id=$1")
            .bind(&p.id)
            .execute(&mut *tx)
            .await?;
        for (position, (quantity, q)) in quotes.into_iter().enumerate() {
            sqlx::query("INSERT INTO cart_items(id,user_id,position,product_id,quantity,plan_id,pricing_id,period,custom_amount_cents,currency) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(Uuid::new_v4().to_string()).bind(&p.id).bind(position as i32).bind(&q.product.id).bind(quantity).bind(q.plan.as_ref().map(|v|&v.id)).bind(q.pricing.as_ref().map(|v|&v.id)).bind(q.period).bind(q.custom).bind(q.currency).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE carts SET revision=revision+1,updated_at=NOW() WHERE user_id=$1")
            .bind(&p.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Self::get(pool, p).await
    }
    pub async fn checkout(pool: &PgPool, p: &Principal, request: CheckoutCart) -> AppResult<Value> {
        if request.revision < 0 || request.expected_total_cents < 0 || request.currency.len() != 3 {
            return Err(invalid("Invalid cart checkout confirmation"));
        }
        let hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&request).unwrap())
        );
        let mut tx = pool.begin().await?;
        Self::actor(&mut tx, p, false).await?;
        let revision = Self::lock_cart(&mut tx, p).await?;
        let previous: Option<(String, String)> = sqlx::query_as(
            "SELECT order_id,request_hash FROM cart_checkouts WHERE user_id=$1 AND revision=$2",
        )
        .bind(&p.id)
        .bind(request.revision)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((id, saved)) = previous {
            if hash != saved {
                return Err(conflict(
                    "This cart revision already created a different checkout",
                ));
            }
            tx.commit().await?;
            return Self::order_result(pool, p, &id).await;
        }
        if revision != request.revision {
            return Err(conflict("Cart changed; reload before checkout"));
        }
        let items = Self::stored(&mut tx, p).await?;
        if items.is_empty() {
            return Err(invalid("The cart is empty"));
        }
        // Lock all SKUs in one global order before taking the beneficiary lock.
        let ids: Vec<String> = items.iter().map(|v| v.product_id.clone()).collect();
        let products: Vec<Product> =
            sqlx::query_as("SELECT * FROM products WHERE id=ANY($1) ORDER BY id FOR UPDATE")
                .bind(&ids)
                .fetch_all(&mut *tx)
                .await?;
        let products: HashMap<String, Product> =
            products.into_iter().map(|v| (v.id.clone(), v)).collect();
        let mut quotes = Vec::new();
        let mut sum = 0i64;
        let mut demand = HashMap::<String, i32>::new();
        for item in &items {
            let product = products
                .get(&item.product_id)
                .filter(|v| v.owner == p.owner)
                .cloned()
                .ok_or_else(denied)?;
            let q = Self::quote(&mut tx, p, &Self::input(item), product).await?;
            if item.currency != q.currency || !request.currency.eq_ignore_ascii_case(&q.currency) {
                return Err(conflict("Cart currency changed; review the cart"));
            }
            if q.kind != "recharge" {
                let count = demand.entry(q.product.id.clone()).or_default();
                *count += item.quantity;
                if q.product.quantity >= 0 && *count > q.product.quantity {
                    return Err(conflict("Cart inventory changed; review the cart"));
                }
            }
            sum = sum
                .checked_add(q.total)
                .filter(|v| *v <= 900_000_000_000_000)
                .ok_or_else(|| invalid("Cart total is out of range"))?;
            quotes.push(q);
        }
        if sum != request.expected_total_cents {
            return Err(conflict(
                "Cart price changed; review the current total before checkout",
            ));
        }
        if request.provider_id.is_empty() {
            return Err(invalid("Cart providerId is required"));
        }
        let order_id = Self::create_snapshot(
            &mut tx,
            p,
            Some(&request.provider_id),
            &request.currency,
            request.coupon_code.as_deref(),
            &items,
            &quotes,
            sum,
        )
        .await?;
        sqlx::query("INSERT INTO cart_checkouts(user_id,revision,order_id,request_hash) VALUES($1,$2,$3,$4)").bind(&p.id).bind(revision).bind(&order_id).bind(hash).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM cart_items WHERE user_id=$1")
            .bind(&p.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE carts SET revision=revision+1,updated_at=NOW() WHERE user_id=$1")
            .bind(&p.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Self::order_result(pool, p, &order_id).await
    }
    async fn create_snapshot(
        tx: &mut Transaction<'_, Postgres>,
        p: &Principal,
        provider_id: Option<&str>,
        currency: &str,
        coupon_code: Option<&str>,
        items: &[StoredItem],
        quotes: &[Quote],
        sum: i64,
    ) -> AppResult<String> {
        let provider: Option<Provider> = if let Some(reference) =
            provider_id.filter(|s| !s.is_empty())
        {
            let provider:Provider=sqlx::query_as("SELECT * FROM providers WHERE id=$1 OR (owner=$2 AND (name=$1 OR owner||'/'||name=$1)) ORDER BY (id=$1) DESC LIMIT 1 FOR SHARE").bind(reference).bind(&p.owner).fetch_optional(&mut **tx).await?.ok_or_else(||invalid("Cart payment provider is unavailable"))?;
            if provider.owner != p.owner || !provider.category.eq_ignore_ascii_case("payment") {
                return Err(denied());
            }
            Some(provider)
        } else {
            None
        };
        let recharge = quotes.iter().any(|q| q.kind == "recharge");
        if recharge
            && provider
                .as_ref()
                .is_some_and(|p| p.provider_type.eq_ignore_ascii_case("balance"))
        {
            return Err(invalid(
                "A cart containing recharge requires an external provider",
            ));
        }
        let user = Self::actor(tx, p, true).await?;
        if recharge {
            crate::services::PaymentFlowService::validate_balance_currency(
                &json!({"balance_currency":user.balance_currency,"currency":user.currency}),
                &currency,
            )?;
        }
        let order_id = Uuid::new_v4().to_string();
        let coupon = if let Some(code) = coupon_code.filter(|s| !s.is_empty()) {
            if recharge {
                return Err(invalid("A cart containing recharge cannot use coupons"));
            }
            Some(
                crate::handlers::parity_operations::coupon_discount(
                    tx,
                    &p.owner,
                    code,
                    &p.id,
                    &user.name,
                    &quotes
                        .iter()
                        .flat_map(|q| {
                            [
                                q.product.name.clone(),
                                format!("{}/{}", p.owner, q.product.name),
                            ]
                        })
                        .collect::<Vec<_>>(),
                    sum as f64 / 100.0,
                    &currency,
                )
                .await?,
            )
        } else {
            None
        };
        let discount = if let Some((_, discount)) = &coupon {
            ProductService::validate_price(*discount, false)?
        } else {
            0
        };
        let net = sum
            .checked_sub(discount)
            .filter(|v| *v >= 0)
            .ok_or_else(|| invalid("Invalid cart discount"))?;
        sqlx::query("INSERT INTO orders(id,owner,name,display_name,provider,quantity,price,currency,\"user\",state) VALUES($1,$2,$3,'Cart order',$4,1,$5,$6,$7,'Created')").bind(&order_id).bind(&p.owner).bind(format!("cart-{order_id}")).bind(provider.as_ref().map(|p|&p.id)).bind(net as f64/100.0).bind(&currency.to_ascii_uppercase()).bind(&p.id).execute(&mut **tx).await?;
        let mut cumulative = 0i64;
        let mut previous_reduction = 0i64;
        for (position, (item, q)) in items.iter().zip(quotes.iter()).enumerate() {
            cumulative += q.total;
            let prefix = if sum == 0 {
                0
            } else {
                ((discount as i128 * cumulative as i128) / sum as i128) as i64
            };
            let reduction = prefix - previous_reduction;
            previous_reduction = prefix;
            let amount = q.total - reduction;
            sqlx::query("INSERT INTO order_lines(id,order_id,position,product_id,product_name,display_name,kind,user_id,quantity,unit_amount_cents,amount_cents,currency,plan_id,pricing_id,period,role_id,plan_name,pricing_name) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)").bind(Uuid::new_v4().to_string()).bind(&order_id).bind(position as i32).bind(&q.product.id).bind(&q.product.name).bind(&q.product.display_name).bind(&q.kind).bind(&p.id).bind(item.quantity).bind(q.unit).bind(amount).bind(&q.currency).bind(q.plan.as_ref().map(|v|&v.id)).bind(q.pricing.as_ref().map(|v|&v.id)).bind(&q.period).bind(&q.role_id).bind(q.plan.as_ref().map(|v|&v.name)).bind(q.pricing.as_ref().map(|v|&v.name)).execute(&mut **tx).await?;
        }
        if let Some((coupon, amount)) = coupon {
            sqlx::query("INSERT INTO coupon_usages(id,coupon_id,user_id,order_id,amount) VALUES($1,$2,$3,$4,$5)").bind(Uuid::new_v4().to_string()).bind(coupon["id"].as_str().ok_or_else(||invalid("Invalid cart coupon"))?).bind(&p.id).bind(&order_id).bind(amount).execute(&mut **tx).await?;
        }
        Ok(order_id)
    }

    async fn order_result(pool: &PgPool, p: &Principal, id: &str) -> AppResult<Value> {
        let order: Value = sqlx::query_scalar(
            "SELECT to_jsonb(o) FROM orders o WHERE id=$1 AND owner=$2 AND buyer_id=$3",
        )
        .bind(id)
        .bind(&p.owner)
        .bind(&p.id)
        .fetch_one(pool)
        .await?;
        let lines: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(l) FROM order_lines l WHERE order_id=$1 ORDER BY position",
        )
        .bind(id)
        .fetch_all(pool)
        .await?;
        let revision: i64 = sqlx::query_scalar("SELECT revision FROM carts WHERE user_id=$1")
            .bind(&p.id)
            .fetch_optional(pool)
            .await?
            .unwrap_or(0);
        Ok(
            json!({"total_amount_cents":ProductService::validate_price(order["price"].as_f64().unwrap_or(0.0),false)?,"currency":order["currency"],"order":order,"lines":lines,"cart_revision":revision}),
        )
    }
}

impl CartService {
    pub(crate) async fn lines(
        conn: &mut PgConnection,
        order_id: &str,
    ) -> AppResult<Vec<OrderLine>> {
        Ok(
            sqlx::query_as("SELECT * FROM order_lines WHERE order_id=$1 ORDER BY position,id")
                .bind(order_id)
                .fetch_all(conn)
                .await?,
        )
    }
    pub(crate) async fn verify_lines(
        conn: &mut PgConnection,
        order: &Order,
        lines: &[OrderLine],
    ) -> AppResult<()> {
        let buyer: Option<String> = sqlx::query_scalar("SELECT buyer_id FROM orders WHERE id=$1")
            .bind(&order.id)
            .fetch_one(&mut *conn)
            .await?;
        let mut amount = 0i64;
        for line in lines {
            if buyer.as_deref() != Some(&line.user_id)
                || !order
                    .currency
                    .as_deref()
                    .unwrap_or("USD")
                    .eq_ignore_ascii_case(&line.currency)
            {
                return Err(conflict(
                    "Cart line beneficiary or currency does not match its parent order",
                ));
            }
            amount = amount
                .checked_add(line.amount_cents)
                .filter(|v| *v <= 900_000_000_000_000)
                .ok_or_else(|| invalid("Cart order amount overflow"))?;
        }
        if order.quantity != 1 || amount != ProductService::validate_price(order.price, false)? {
            return Err(conflict("Cart line amounts do not match the parent order"));
        }
        Ok(())
    }
    pub(crate) async fn validate_checkout(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
        provider: &Provider,
    ) -> AppResult<bool> {
        let lines = Self::lines(tx, &order.id).await?;
        if lines.is_empty() {
            return Ok(false);
        }
        Self::verify_lines(tx, order, &lines).await?;
        let buyer:User=sqlx::query_as("SELECT u.* FROM users u JOIN orders o ON o.buyer_id=u.id AND o.owner=u.owner WHERE o.id=$1 AND NOT u.is_deleted AND NOT u.is_forbidden").bind(&order.id).fetch_optional(&mut **tx).await?.ok_or_else(denied)?;
        for line in &lines {
            if line.kind == "plan" {
                let unavailable:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM subscriptions WHERE owner=$1 AND user_id=$2 AND plan_id=$3 AND NOT is_deleted AND (lower(state)='suspended' OR (pricing_id=$4 AND lower(state)='active' AND end_date IS NULL)))").bind(&order.owner).bind(&buyer.id).bind(&line.plan_id).bind(&line.pricing_id).fetch_one(&mut **tx).await?;
                if unavailable {
                    return Err(conflict(
                        "Cart plan subscription became suspended or lifetime before payment",
                    ));
                }
            }
        }
        if lines.iter().any(|l| l.kind == "recharge") {
            if provider.provider_type.eq_ignore_ascii_case("balance") {
                return Err(invalid(
                    "A cart containing recharge requires an external provider",
                ));
            }
            crate::services::PaymentFlowService::validate_balance_currency(
                &json!({"balance_currency":buyer.balance_currency,"currency":buyer.currency}),
                order.currency.as_deref().unwrap_or("USD"),
            )?;
        }
        Ok(true)
    }
    pub(crate) async fn reserve_stock(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
    ) -> AppResult<bool> {
        let lines = Self::lines(tx, &order.id).await?;
        if lines.is_empty() {
            return Ok(false);
        }
        Self::verify_lines(tx, order, &lines).await?;
        let states: Vec<String> =
            sqlx::query_scalar("SELECT state FROM order_line_stock_reservations WHERE order_id=$1")
                .bind(&order.id)
                .fetch_all(&mut **tx)
                .await?;
        if !states.is_empty() {
            if states.len() == lines.len() && states.iter().all(|s| s == "reserved") {
                return Ok(true);
            }
            return Err(conflict(
                "Cart inventory reservation is already finalized or incomplete",
            ));
        }
        let ids: Vec<String> = lines.iter().map(|l| l.product_id.clone()).collect();
        let products: Vec<Product> =
            sqlx::query_as("SELECT * FROM products WHERE id=ANY($1) ORDER BY id FOR UPDATE")
                .bind(&ids)
                .fetch_all(&mut **tx)
                .await?;
        let mut products: HashMap<String, Product> =
            products.into_iter().map(|p| (p.id.clone(), p)).collect();
        for line in lines {
            let product = products
                .get_mut(&line.product_id)
                .filter(|p| {
                    p.owner == order.owner
                        && !p.is_deleted
                        && matches!(
                            p.state.to_ascii_lowercase().as_str(),
                            "active" | "published" | "on sale"
                        )
                })
                .ok_or_else(|| invalid("Cart product is no longer available for checkout"))?;
            let finite = product.quantity >= 0 && line.kind != "recharge";
            if finite {
                if product.quantity < line.quantity {
                    return Err(conflict("Cart inventory changed; payment was not started"));
                }
                product.quantity -= line.quantity;
                sqlx::query(
                    "UPDATE products SET quantity=quantity-$2,updated_at=NOW() WHERE id=$1",
                )
                .bind(&product.id)
                .bind(line.quantity)
                .execute(&mut **tx)
                .await?;
            }
            sqlx::query("INSERT INTO order_line_stock_reservations(line_id,order_id,product_id,quantity,finite_stock) VALUES($1,$2,$3,$4,$5)").bind(&line.id).bind(&order.id).bind(&line.product_id).bind(line.quantity).bind(finite).execute(&mut **tx).await?;
        }
        Ok(true)
    }
    async fn lock_stock_products(conn: &mut PgConnection, order_id: &str) -> AppResult<()> {
        let _:Vec<String>=sqlx::query_scalar("SELECT id FROM products WHERE id IN(SELECT product_id FROM order_line_stock_reservations WHERE order_id=$1) ORDER BY id FOR UPDATE").bind(order_id).fetch_all(conn).await?;
        Ok(())
    }
    pub(crate) async fn release_stock(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
    ) -> AppResult<bool> {
        let has: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM order_lines WHERE order_id=$1)")
                .bind(&order.id)
                .fetch_one(&mut **tx)
                .await?;
        if !has {
            return Ok(false);
        }
        Self::lock_stock_products(tx, &order.id).await?;
        let released:Vec<(String,i32,bool)>=sqlx::query_as("UPDATE order_line_stock_reservations SET state='released',updated_at=NOW() WHERE order_id=$1 AND state='reserved' RETURNING product_id,quantity,finite_stock").bind(&order.id).fetch_all(&mut **tx).await?;
        for (product, quantity, finite) in released {
            if finite {
                sqlx::query(
                    "UPDATE products SET quantity=quantity+$2,updated_at=NOW() WHERE id=$1",
                )
                .bind(product)
                .bind(quantity)
                .execute(&mut **tx)
                .await?;
            }
        }
        Ok(true)
    }
    pub(crate) async fn consume_stock(
        tx: &mut Transaction<'_, Postgres>,
        order: &Order,
    ) -> AppResult<bool> {
        let lines = Self::lines(tx, &order.id).await?;
        if lines.is_empty() {
            return Ok(false);
        }
        let states: Vec<String> =
            sqlx::query_scalar("SELECT state FROM order_line_stock_reservations WHERE order_id=$1")
                .bind(&order.id)
                .fetch_all(&mut **tx)
                .await?;
        if states.is_empty() {
            Self::reserve_stock(tx, order).await?;
        } else if states.iter().any(|s| s == "released") || states.len() != lines.len() {
            return Err(conflict("Cart reservation was released or is incomplete"));
        }
        Self::lock_stock_products(tx, &order.id).await?;
        let consumed:Vec<(String,i32)>=sqlx::query_as("UPDATE order_line_stock_reservations SET state='consumed',updated_at=NOW() WHERE order_id=$1 AND state='reserved' RETURNING product_id,quantity").bind(&order.id).fetch_all(&mut **tx).await?;
        for (product, quantity) in consumed {
            sqlx::query("UPDATE products SET sold=sold+$2,updated_at=NOW() WHERE id=$1")
                .bind(product)
                .bind(quantity)
                .execute(&mut **tx)
                .await?;
        }
        Ok(true)
    }
}
impl CartService {
    pub fn legacy_inputs(p: &Principal, value: &Value) -> AppResult<Vec<CartItemInput>> {
        let values = value
            .as_array()
            .ok_or_else(|| invalid("cart/productInfos must be an array"))?;
        if values.len() > 100 {
            return Err(invalid("Cart supports at most 100 lines"));
        }
        values
            .iter()
            .map(|v| {
                if v.get("owner")
                    .and_then(Value::as_str)
                    .is_some_and(|owner| owner != p.owner)
                {
                    return Err(denied());
                }
                let reference = v
                    .get("productId")
                    .or_else(|| v.get("name"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("Cart product name is required"))?;
                let quantity = v
                    .get("quantity")
                    .and_then(Value::as_i64)
                    .and_then(|n| i32::try_from(n).ok())
                    .ok_or_else(|| invalid("Cart quantity must be an integer"))?;
                let string = |name: &str| {
                    v.get(name)
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                };
                let custom_price =
                    if let Some(price) = v.get("customPrice").or_else(|| v.get("price")) {
                        Some(
                            price
                                .as_f64()
                                .ok_or_else(|| invalid("Cart price must be a number"))?,
                        )
                    } else {
                        None
                    };
                Ok(CartItemInput {
                    product_id: reference.into(),
                    quantity,
                    pricing_name: string("pricingName"),
                    plan_name: string("planName"),
                    period: string("period"),
                    custom_price,
                })
            })
            .collect()
    }
    pub async fn replace_legacy(
        pool: &PgPool,
        p: &Principal,
        revision: i64,
        value: &Value,
    ) -> AppResult<Value> {
        let mut items = Self::legacy_inputs(p, value)?;
        for item in &mut items {
            let product = Self::product(
                &mut *pool.acquire().await?,
                &p.owner,
                &item.product_id,
                false,
            )
            .await?;
            if !product.is_recharge {
                item.custom_price = None;
            }
        }
        Self::replace(pool, p, ReplaceCart { revision, items }).await
    }
    pub fn legacy_projection(p: &Principal, cart: &Value) -> Value {
        let items=cart["items"].as_array().into_iter().flatten().map(|v|json!({"owner":p.owner,"productId":v["product_id"],"name":v["name"],"displayName":v["display_name"],"image":v["image"],"quantity":v["quantity"],"pricingName":v["pricing_name"],"planName":v["plan_name"],"period":v["period"],"price":v["unit_amount_cents"].as_i64().unwrap_or(0) as f64/100.0,"currency":v["currency"],"isInvalid":v["valid"]!=true})).collect::<Vec<_>>();
        json!({"cart":items,"cartRevision":cart["revision"]})
    }
    /// Upstream place-order creates one pending multi-line order without mutating
    /// User.cart. Its caller explicitly selects a provider later at pay-order.
    pub async fn place_order(
        pool: &PgPool,
        p: &Principal,
        value: &Value,
        provider: Option<&str>,
        coupon: Option<&str>,
    ) -> AppResult<Value> {
        let mut inputs = Self::legacy_inputs(p, value)?;
        if inputs.is_empty() {
            return Err(invalid("Order has no products"));
        }
        let mut tx = pool.begin().await?;
        Self::actor(&mut tx, p, false).await?;
        for input in &mut inputs {
            let product = Self::product(&mut tx, &p.owner, &input.product_id, false).await?;
            input.product_id = product.id;
            if !product.is_recharge {
                input.custom_price = None;
            }
        }
        let ids: Vec<String> = inputs.iter().map(|i| i.product_id.clone()).collect();
        let products: Vec<Product> =
            sqlx::query_as("SELECT * FROM products WHERE id=ANY($1) ORDER BY id FOR UPDATE")
                .bind(&ids)
                .fetch_all(&mut *tx)
                .await?;
        let products: HashMap<String, Product> =
            products.into_iter().map(|p| (p.id.clone(), p)).collect();
        let mut quotes = vec![];
        let mut items = vec![];
        let mut currency = None;
        let mut sum = 0i64;
        let mut demand = HashMap::<String, i32>::new();
        for input in inputs {
            let product = products
                .get(&input.product_id)
                .cloned()
                .ok_or_else(denied)?;
            let q = Self::quote(&mut tx, p, &input, product).await?;
            if currency.as_ref().is_some_and(|c| c != &q.currency) {
                return Err(invalid("Order products must use one currency"));
            }
            currency = Some(q.currency.clone());
            sum = sum
                .checked_add(q.total)
                .filter(|n| *n <= 900_000_000_000_000)
                .ok_or_else(|| invalid("Order total out of range"))?;
            if q.kind != "recharge" {
                let count = demand.entry(q.product.id.clone()).or_default();
                *count += input.quantity;
                if q.product.quantity >= 0 && *count > q.product.quantity {
                    return Err(conflict("Order stock is insufficient"));
                }
            }
            items.push(StoredItem {
                id: Uuid::new_v4().to_string(),
                product_id: q.product.id.clone(),
                quantity: input.quantity,
                pricing_id: q.pricing.as_ref().map(|p| p.id.clone()),
                plan_id: q.plan.as_ref().map(|p| p.id.clone()),
                period: q.period.clone(),
                custom_amount_cents: q.custom,
                currency: q.currency.clone(),
            });
            quotes.push(q);
        }
        let id = Self::create_snapshot(
            &mut tx,
            p,
            provider,
            currency.as_deref().unwrap(),
            coupon,
            &items,
            &quotes,
            sum,
        )
        .await?;
        tx.commit().await?;
        Self::order_result(pool, p, &id).await
    }
}

impl CartService {
    /// Call only after authorizing the parent order. No current catalogue join
    /// can rewrite historical SKU, plan, pricing, price or quantity snapshots.
    pub async fn legacy_order_projection(
        pool: &PgPool,
        order_id: &str,
    ) -> AppResult<Option<Value>> {
        let lines:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(l)||jsonb_build_object('owner',o.owner) FROM order_lines l JOIN orders o ON o.id=l.order_id WHERE l.order_id=$1 ORDER BY l.position,l.id").bind(order_id).fetch_all(pool).await?;
        if lines.is_empty() {
            return Ok(None);
        }
        let products: Vec<Value> = lines.iter().map(|v| v["product_name"].clone()).collect();
        let infos:Vec<Value>=lines.iter().map(|v|json!({"owner":v["owner"],"name":v["product_name"],"displayName":v["display_name"],"price":v["unit_amount_cents"].as_i64().unwrap_or(0) as f64/100.0,"currency":v["currency"],"quantity":v["quantity"],"isRecharge":v["kind"]=="recharge","planName":v["plan_name"],"pricingName":v["pricing_name"],"period":v["period"],"createdTime":v["created_at"]})).collect();
        Ok(Some(json!({"productInfos":infos,"products":products})))
    }
}
