use crate::{AppState, ui::*};
use glory::prelude::*;
use serde_json::{Value, json};

fn entries(cart: &Value) -> Vec<Value> {
    cart["items"].as_array().cloned().unwrap_or_default()
}

fn input(item: &Value) -> Value {
    json!({
        "productId": item["product_id"], "quantity": item["quantity"],
        "pricingName": item["pricing_name"], "planName": item["plan_name"],
        "period": item["period"], "customPrice": item["custom_price"]
    })
}

fn money(cents: &Value, currency: &Value) -> String {
    format!(
        "{:.2} {}",
        cents.as_i64().unwrap_or_default() as f64 / 100.0,
        currency.as_str().unwrap_or("")
    )
}

pub async fn add(app: AppState, item: Value) -> std::result::Result<String, String> {
    let current = app.request("GET", "/api/store/cart", None).await?;
    let cart = &current["data"];
    let revision = cart["revision"]
        .as_i64()
        .ok_or("Cart could not be loaded.")?;
    let mut items: Vec<_> = entries(cart).iter().map(input).collect();
    items.push(item);
    app.request(
        "PUT",
        "/api/store/cart",
        Some(json!({"revision":revision,"items":items})),
    )
    .await?;
    Ok("Added to your cart. Open Shopping cart to review and place one order.".into())
}

pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        stack((
            heading("Shopping cart"),
            when(scope.bond(move || app.token.get().is_none()), || {
                label("Sign in to manage your shopping cart.")
            }),
            when(scope.bond(move || app.token.get().is_some()), move || {
                signed_in(app)
            }),
        ))
        .build(scope)
    }))
}

fn signed_in(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let cart = scope.cage(Value::Null);
        let providers = scope.cage(Vec::<Value>::new());
        let provider = scope.cage(String::new());
        let coupon = scope.cage(String::new());
        let busy = scope.cage(false);
        let loading = scope.cage(true);
        let message = scope.cage(String::new());
        let revision = scope.cage(0u64);
        let tasks = scope.clone();
        scope.effect(move || {
            let version = revision.get();
            loading.set(true);
            let _ = tasks.spawn(async move {
                let result = async {
                    let current = app.request("GET", "/api/store/cart", None).await?;
                    let catalog = app.request("GET", "/api/store/catalog", None).await?;
                    Ok::<_, String>((
                        current["data"].clone(),
                        catalog["providers"].as_array().cloned().unwrap_or_default(),
                    ))
                }
                .await;
                if revision.get() != version {
                    return;
                }
                match result {
                    Ok((current, available)) => {
                        if !available
                            .iter()
                            .any(|p| p["id"].as_str() == Some(provider.get().as_str()))
                        {
                            provider.set(
                                available
                                    .first()
                                    .and_then(|p| p["id"].as_str())
                                    .unwrap_or_default()
                                    .to_string(),
                            );
                        }
                        cart.set(current);
                        providers.set(available);
                    }
                    Err(error) => {
                        cart.set(Value::Null);
                        message.set(error);
                    }
                }
                loading.set(false);
            });
        });
        let rows = each(scope.bond(move || entries(&cart.get())))
            .key(|item| item["id"].as_str().unwrap_or_default().to_string())
            .seed(move |item| {
                widget(move |scope| {
                    let item = item.clone();
                    let id = item["id"].as_str().unwrap_or_default().to_string();
                    let title = item["display_name"].as_str().or(item["name"].as_str()).unwrap_or("Unavailable product").to_string();
                    let quantity = scope.cage(item["quantity"].as_i64().unwrap_or(1).to_string());
                    let save_id = id.clone();
                    let remove_id = id;
                    let invalid = item["valid"] != true;
                    let error = item["error"].as_str().unwrap_or("This item is unavailable. Remove it before checkout.").to_string();
                    stack((
                        heading(&title),
                        label(&format!("Unit price: {} · Line total: {}", money(&item["unit_amount_cents"], &item["currency"]), money(&item["total_amount_cents"], &item["currency"]))),
                        when(scope.bond(move || invalid), move || label(&error)),
                        field(scope, &format!("Quantity for {title}"), quantity),
                        action(scope, &format!("Update quantity for {title}"), busy, message, move || {
                            let id = save_id.clone();
                            async move {
                                if loading.get() { return Err("Wait for the cart to finish loading.".into()); }
                                let count: i64 = quantity.get().parse().map_err(|_| "Enter a whole quantity of at least 1.")?;
                                if !(1..=1000).contains(&count) { return Err("Enter a whole quantity between 1 and 1000.".into()); }
                                let current = cart.get();
                                let items: Vec<Value> = entries(&current).iter().map(|row| {
                                    let mut value = input(row);
                                    if row["id"].as_str() == Some(id.as_str()) { value["quantity"] = json!(count); }
                                    value
                                }).collect();
                                let saved = app.request("PUT", "/api/store/cart", Some(json!({"revision":current["revision"],"items":items}))).await?;
                                cart.set(saved["data"].clone());
                                Ok("Cart quantity updated.".into())
                            }
                        }),
                        action(scope, &format!("Remove {title}"), busy, message, move || {
                            let id = remove_id.clone();
                            async move {
                                if loading.get() { return Err("Wait for the cart to finish loading.".into()); }
                                let current = cart.get();
                                let items: Vec<Value> = entries(&current).iter().filter(|row| row["id"].as_str() != Some(id.as_str())).map(input).collect();
                                let saved = app.request("PUT", "/api/store/cart", Some(json!({"revision":current["revision"],"items":items}))).await?;
                                cart.set(saved["data"].clone());
                                Ok("Item removed from your cart.".into())
                            }
                        }),
                    )).build(scope)
                })
            });
        let choices = scope.bond(move || {
            vec![Value::Array(
                providers
                    .get()
                    .into_iter()
                    .filter(|p| {
                        let recharge = entries(&cart.get())
                            .iter()
                            .any(|row| row["custom_price"].is_number());
                        !(recharge
                            && p["type"]
                                .as_str()
                                .is_some_and(|kind| kind.eq_ignore_ascii_case("balance")))
                    })
                    .collect(),
            )]
        });
        let payment_select =
            each(choices)
                .key(|choices| choices.to_string())
                .seed(move |choices| {
                    widget(move |scope| {
                        let available = choices.as_array().cloned().unwrap_or_default();
                        let initial = if available
                            .iter()
                            .any(|p| p["id"].as_str() == Some(provider.get().as_str()))
                        {
                            provider.get()
                        } else {
                            available
                                .first()
                                .and_then(|p| p["id"].as_str())
                                .unwrap_or_default()
                                .to_string()
                        };
                        let selected_provider = scope.cage(initial.clone());
                        provider.set(initial);
                        sapid::native_select("cart-payment-provider")
                            .name("Cart payment provider")
                            .value(scope.bond(move || {
                                let value = selected_provider.get();
                                if value.is_empty() { None } else { Some(value) }
                            }))
                            .options(available.iter().map(|p| {
                                sapid::select_option(
                                    p["id"].as_str().unwrap_or_default(),
                                    p["display_name"]
                                        .as_str()
                                        .or(p["name"].as_str())
                                        .unwrap_or("Payment provider"),
                                )
                            }))
                            .enabled(scope.bond(move || !busy.get() && !loading.get()))
                            .on_value_change(move |next| {
                                let next = next.unwrap_or_default();
                                selected_provider.set(next.clone());
                                provider.set(next);
                            })
                            .build(scope)
                    })
                });
        stack((
            label("Your cart is saved to your account. Review current prices before placing one order for all items."),
            action(scope, "Refresh cart", busy, message, move || async move { revision.set(revision.get() + 1); Ok(String::new()) }),
            when(scope.bond(move || loading.get()), || label("Loading cart…")),
            when(scope.bond(move || !loading.get() && !cart.get().is_null() && entries(&cart.get()).is_empty()), || label("Your cart is empty.")),
            rows,
            text().content_fn(move || format!("Cart total: {}", money(&cart.get()["total_amount_cents"], &cart.get()["currency"]))),
            payment_select,
            field(scope, "Cart coupon (optional)", coupon),
            label("A price or stock change can reject checkout. Refresh the cart and review it again before retrying."),
            stack((action(scope, "Place cart order", busy, message, move || async move {
                let current = cart.get();
                if loading.get() || current["valid"] != true || entries(&current).is_empty() { return Err("Load a valid, nonempty cart before placing an order.".into()); }
                if provider.get().is_empty() { return Err("Select a payment provider.".into()); }
                let response = app.request("POST", "/api/store/cart/checkout", Some(json!({"revision":current["revision"],"providerId":provider.get(),"expectedTotalCents":current["total_amount_cents"],"currency":current["currency"],"couponCode":coupon.get()}))).await?;
                let id = response["data"]["order"]["id"].as_str().filter(|id| !id.is_empty()).ok_or("Checkout returned no order. Review Your purchases before retrying.")?.to_string();
                revision.set(revision.get() + 1);
                match app.request("POST", &format!("/api/pay-order?id={}", query_component(&id)), None).await {
                    Ok(value) if value["autoPaid"] == true => Ok("Cart order paid. Open Store to view your purchase and benefits.".into()),
                    Ok(_) => Ok("Cart order created. Open Store to continue its single payment.".into()),
                    Err(error) => Err(format!("Order {id} was created. {error}\nOpen Store to continue or cancel it; do not place another order.")),
                }
            }),
            action(scope, "Clear cart", busy, message, move || async move {
                let current = cart.get();
                if loading.get() || current["revision"].as_i64().is_none() { return Err("Load the cart before clearing it.".into()); }
                let saved = app.request("PUT", "/api/store/cart", Some(json!({"revision":current["revision"],"items":[]}))).await?;
                cart.set(saved["data"].clone());
                Ok("Cart cleared.".into())
            }),
            action(scope, "View purchases", busy, message, move || async move { app.panel.set("store-page".into()); Ok(String::new()) }),
            notice(message))),
        )).build(scope)
    }))
}
