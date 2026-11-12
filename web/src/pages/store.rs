use crate::{AppState, api, ui::*};
use glory::prelude::*;
use serde_json::Value;

fn values(value: &Value, key: &str) -> Vec<Value> {
    value[key].as_array().cloned().unwrap_or_default()
}

fn reference_matches(reference: &str, owner: &str, plan: &Value) -> bool {
    reference == plan["id"].as_str().unwrap_or("")
        || reference == plan["name"].as_str().unwrap_or("")
        || reference == format!("{owner}/{}", plan["name"].as_str().unwrap_or(""))
}

fn payment_url(value: &str) -> std::result::Result<String, String> {
    let parsed = url::Url::parse(value).map_err(|_| "Payment URL unavailable".to_string())?;
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !(parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback))
    {
        return Err("Payment URL must use HTTPS".into());
    }
    Ok(parsed.into())
}

pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        stack((
            heading("Store and subscriptions"),
            when(scope.bond(move || app.token.get().is_none()), || {
                label("Sign in to browse your tenant's products and purchases.")
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
        let catalogue = scope.cage(Value::Null);
        let purchases = scope.cage(Value::Null);
        let selected = scope.cage(Vec::<Value>::new());
        let page = scope.cage(1i64);
        let history_page = scope.cage(1i64);
        let revision = scope.cage(0u64);
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let tasks = scope.clone();
        scope.effect(move || {
            let current = page.get();
            let history = history_page.get();
            let version = revision.get();
            catalogue.set(Value::Null);
            purchases.set(Value::Null);
            selected.set(Vec::new());
            let _ = tasks.spawn(async move {
                let result = async {
                    let catalog = app
                        .request("GET", &format!("/api/store/catalog?page={current}"), None)
                        .await?;
                    let owned = app
                        .request("GET", &format!("/api/store/purchases?page={history}"), None)
                        .await?;
                    Ok::<_, String>((catalog, owned))
                }
                .await;
                if page.get() != current
                    || history_page.get() != history
                    || revision.get() != version
                {
                    return;
                }
                match result {
                    Ok((catalog, owned)) => {
                        catalogue.set(catalog);
                        purchases.set(owned);
                    }
                    Err(error) => message.set(error),
                }
            });
        });
        let product_rows = each(scope.bond(move || values(&catalogue.get(), "data")))
            .key(|product| api::item_id(product).unwrap_or_default())
            .seed(move |product| {
                widget(move |scope| {
                    let product = product.clone();
                    let title = api::item_title(&product);
                    let subtitle = if product["is_recharge"] == true {
                        "Wallet recharge".to_string()
                    } else if product["plan_id"].is_string() {
                        "Subscription plan".to_string()
                    } else {
                        format!(
                            "{} {}",
                            product["price"],
                            product["currency"].as_str().unwrap_or("USD")
                        )
                    };
                    let out = product["quantity"] == 0 && product["is_recharge"] != true;
                    stack((
                        heading(&title),
                        label(&subtitle),
                        label(product["description"].as_str().unwrap_or("")),
                        action(
                            scope,
                            &format!("Select {title}"),
                            busy,
                            message,
                            move || {
                                let product = product.clone();
                                async move {
                                    if out {
                                        return Err("This product is out of stock.".into());
                                    }
                                    selected.set(vec![product]);
                                    Ok(String::new())
                                }
                            },
                        ),
                    ))
                    .build(scope)
                })
            });
        let checkout = each(selected)
            .key(|product| api::item_id(product).unwrap_or_default())
            .seed(move |product| checkout(app, product, catalogue.get(), busy, message, revision));
        let order_rows = each(scope.bond(move || values(&purchases.get(), "data")))
            .key(|order| api::item_id(order).unwrap_or_default())
            .seed(move |order| {
                widget(move |scope| {
                    let id = order["id"].as_str().unwrap_or_default().to_string();
                    let state = order["state"].as_str().unwrap_or_default().to_string();
                    let pending = matches!(
                        state.to_ascii_lowercase().as_str(),
                        "created" | "pending" | "paying"
                    );
                    let title = api::item_title(&order);
                    let refresh = id.clone();
                    let cancel = id.clone();
                    let pay_url = order["pay_url"].as_str().unwrap_or_default().to_string();
                    let summary = format!(
                        "{title} · {} {} · {state}",
                        order["price"],
                        order["currency"].as_str().unwrap_or("USD")
                    );
                    let line_rows = each(scope.cage(values(&order,"lines")))
                        .key(|line| line["id"].as_str().unwrap_or_default().to_string())
                        .seed(|line| label(&format!("{} × {} · {:.2} {}",
                            line["quantity"].as_i64().unwrap_or(1),
                            line["display_name"].as_str().or(line["product_name"].as_str()).unwrap_or("Product"),
                            line["amount_cents"].as_i64().unwrap_or_default() as f64/100.0,
                            line["currency"].as_str().unwrap_or("USD"))));
                    stack((
                        label(&summary),
                        line_rows,
                        label(&format!("Order {}", order["name"].as_str().unwrap_or(&id))),
                        when(scope.bond(move || pending), move || {
                            let refresh = refresh.clone();
                            let cancel = cancel.clone();
                            let pay_url = pay_url.clone();
                            let id = id.clone();
                            widget(move |scope| {
                                let refresh = refresh.clone();
                                let cancel = cancel.clone();
                                let url = pay_url.clone();
                                let continue_order=id.clone();
                                stack((
                                    action(
                                        scope,
                                        &format!("Refresh payment {id}"),
                                        busy,
                                        message,
                                        move || {
                                            let id = refresh.clone();
                                            async move {
                                                app.request(
                                                    "POST",
                                                    &format!(
                                                        "/api/reconcile-order?id={}",
                                                        query_component(&id)
                                                    ),
                                                    None,
                                                )
                                                .await?;
                                                revision.set(revision.get() + 1);
                                                Ok("Payment refreshed.".into())
                                            }
                                        },
                                    ),
                                    action(scope, "Continue payment", busy, message, move || {
                                        let target = url.clone();let order=continue_order.clone();
                                        async move {
                                            if target.is_empty() {
                                                let response=app.request("POST",&format!("/api/pay-order?id={}",query_component(&order)),None).await?;
                                                revision.set(revision.get()+1);
                                                return Ok(if response["autoPaid"]==true {"Purchase paid."}else{"Checkout started. Continue payment from your purchase."}.into());
                                            }
                                            redirect(&payment_url(&target)?)?;
                                            Ok(String::new())
                                        }
                                    }),
                                    action(scope, "Cancel purchase", busy, message, move || {
                                        let id = cancel.clone();
                                        async move {
                                            app.request(
                                                "POST",
                                                &format!(
                                                    "/api/cancel-order?id={}",
                                                    query_component(&id)
                                                ),
                                                None,
                                            )
                                            .await?;
                                            revision.set(revision.get() + 1);
                                            Ok("Purchase canceled.".into())
                                        }
                                    }),
                                ))
                                .build(scope)
                            })
                        }),
                    ))
                    .build(scope)
                })
            });
        let subscription_rows = each(scope.bond(move || values(&purchases.get(), "subscriptions")))
            .key(|subscription| api::item_id(subscription).unwrap_or_default())
            .seed(move |subscription| renewal(app, subscription, busy, message, revision));
        stack((
            text().content_fn(move || {
                let owned = purchases.get();
                format!(
                    "Wallet balance: {} {}",
                    owned["wallet"]["balance"],
                    owned["wallet"]["currency"].as_str().unwrap_or("")
                )
            }),
            action(scope, "Refresh store", busy, message, move || async move {
                revision.set(revision.get() + 1);
                Ok(String::new())
            }),
            stack((
                heading("Products"),
                product_rows,
                text().content_fn(move || {
                    format!(
                        "Catalog page {} · {} products",
                        page.get(),
                        catalogue.get()["total"]
                    )
                }),
                action(
                    scope,
                    "Previous products",
                    busy,
                    message,
                    move || async move {
                        page.set((page.get() - 1).max(1));
                        Ok(String::new())
                    },
                ),
                action(scope, "Next products", busy, message, move || async move {
                    if page.get() * 20 < catalogue.get()["total"].as_i64().unwrap_or(0) {
                        page.set(page.get() + 1);
                    }
                    Ok(String::new())
                }),
                checkout,
            )),
            stack((
                heading("Your purchases"),
                order_rows,
                text().content_fn(move || {
                    format!(
                        "Purchase page {} · {} purchases",
                        history_page.get(),
                        purchases.get()["total"]
                    )
                }),
                action(
                    scope,
                    "Previous purchases",
                    busy,
                    message,
                    move || async move {
                        history_page.set((history_page.get() - 1).max(1));
                        Ok(String::new())
                    },
                ),
                action(scope, "Next purchases", busy, message, move || async move {
                    if history_page.get() * 20 < purchases.get()["total"].as_i64().unwrap_or(0) {
                        history_page.set(history_page.get() + 1);
                    }
                    Ok(String::new())
                }),
            )),
            stack((heading("Your subscriptions"), subscription_rows)),
            notice(message),
        ))
        .build(scope)
    }))
}

fn checkout(
    app: AppState,
    product: Value,
    catalog: Value,
    busy: Cage<bool>,
    message: Cage<String>,
    revision: Cage<u64>,
) -> Element {
    boxed(widget(move |scope| {
        let product = product.clone();
        let allow_custom = product["disable_custom_recharge"] != true;
        let recharge = product["is_recharge"] == true;
        let plan = values(&catalog, "plans")
            .into_iter()
            .find(|plan| plan["id"] == product["plan_id"]);
        let owner = app
            .account
            .get()
            .map(|account| account.owner)
            .unwrap_or_default();
        let pricing_options: Vec<(String, String)> = values(&catalog, "pricings")
            .into_iter()
            .filter(|pricing| {
                let references: Vec<String> =
                    serde_json::from_str(pricing["plans"].as_str().unwrap_or("[]"))
                        .unwrap_or_default();
                plan.as_ref().is_some_and(|plan| {
                    references
                        .iter()
                        .any(|reference| reference_matches(reference, &owner, plan))
                })
            })
            .map(|pricing| {
                (
                    pricing["id"].as_str().unwrap_or_default().to_string(),
                    api::item_title(&pricing),
                )
            })
            .collect();
        let providers: Vec<(String, String)> = values(&catalog, "providers")
            .into_iter()
            .filter(|provider| {
                !(recharge
                    && provider["type"]
                        .as_str()
                        .is_some_and(|kind| kind.eq_ignore_ascii_case("balance")))
            })
            .map(|provider| {
                (
                    provider["id"].as_str().unwrap_or_default().to_string(),
                    api::item_title(&provider),
                )
            })
            .collect();
        let provider = scope.cage(providers.first().map(|p| p.0.clone()).unwrap_or_default());
        let pricing = scope.cage(
            pricing_options
                .first()
                .map(|p| p.0.clone())
                .unwrap_or_default(),
        );
        let period = scope.cage("monthly".to_string());
        let amounts: Vec<(String, String)> = values(&product, "recharge_options")
            .iter()
            .filter_map(|value| value.as_f64())
            .map(|amount| (amount.to_string(), amount.to_string()))
            .collect();
        let amount = scope.cage(amounts.first().map(|a| a.0.clone()).unwrap_or_default());
        let coupon = scope.cage(String::new());
        let title = api::item_title(&product);
        let plan_ref = plan
            .as_ref()
            .and_then(|p| p["id"].as_str())
            .map(str::to_owned);
        let monthly = plan
            .as_ref()
            .map(|p| format!("{:.2}", p["price_per_month"].as_f64().unwrap_or(0.0)))
            .unwrap_or_default();
        let yearly = plan
            .as_ref()
            .map(|p| format!("{:.2}", p["price_per_year"].as_f64().unwrap_or(0.0)))
            .unwrap_or_default();
        let currency = product["currency"].as_str().unwrap_or("USD").to_string();
        let cart_product = product.clone();
        let cart_plan = plan.clone();
        let cart_quantity = scope.cage("1".to_string());
        stack((
            heading(&format!("Checkout: {title}")),
            select(scope,"Payment provider",provider,providers),
            when(scope.bond(move || plan_ref.is_some()),move || {
                let pricing_options=pricing_options.clone();let monthly=monthly.clone();let yearly=yearly.clone();let currency=currency.clone();
                widget(move |scope| {
                stack((select(scope,"Plan pricing",pricing,pricing_options.clone()),select(scope,"Billing period",period,vec![("monthly".into(),"Monthly".into()),("yearly".into(),"Yearly".into())]),
                    text().content_fn({let monthly=monthly.clone();let yearly=yearly.clone();let currency=currency.clone();move ||format!("Plan price: {} {currency}",if period.get()=="yearly" {&yearly} else {&monthly})}),
                )).build(scope)
            })}),
            when(scope.bond(move || recharge),move || {let amounts=amounts.clone();widget(move |scope| {
                stack((
                    select(scope,"Recharge option",amount,amounts.clone()),
                    when(scope.bond(move || allow_custom),move ||widget(move |scope|field(scope,"Recharge amount",amount).build(scope))),
                )).build(scope)
            })}),
            when(scope.bond(move || !recharge),move ||widget(move |scope|field(scope,"Coupon code (optional)",coupon).build(scope))),
            label("Review the amount and provider before confirming. External checkout may require continuing from your purchases."),
            action(scope,"Confirm purchase",busy,message,move || {
                let product=product.clone();let plan=plan.clone();async move {
                    if provider.get().is_empty() { return Err("Select an available payment provider.".into()); }
                    let mut parameters=vec![("id".to_string(),product["id"].as_str().unwrap_or_default().to_string()),("providerName".into(),provider.get()),("paymentEnv".into(),"Web".into())];
                    if let Some(plan)=plan {
                        if pricing.get().is_empty() { return Err("No enabled pricing is available for this plan.".into()); }
                        parameters.extend([("planName".into(),plan["id"].as_str().unwrap_or_default().to_string()),("pricingName".into(),pricing.get()),("period".into(),period.get())]);
                    }
                    if recharge { parameters.push(("customPrice".into(),amount.get())); }
                    if !coupon.get().is_empty() {parameters.push(("couponCode".into(),coupon.get()));}
                    let query=parameters.iter().map(|(key,value)|format!("{}={}",query_component(key),query_component(value))).collect::<Vec<_>>().join("&");
                    let result=app.request("POST",&format!("/api/buy-product?{query}"),None).await;
                    revision.set(revision.get()+1);
                    match result {
                        Ok(value) if value["autoPaid"]==true =>Ok("Purchase paid. Your balance and subscriptions have been refreshed.".into()),
                        Ok(_) =>Ok("Purchase created. Continue payment or refresh its status in Your purchases.".into()),
                        Err(error) =>Err(format!("{error}\nReview Your purchases before starting another checkout.")),
                    }
                }
            }),
            field(scope,"Cart quantity",cart_quantity),
            action(scope,"Add to cart",busy,message,move || {
                let product=cart_product.clone();let plan=cart_plan.clone();async move {
                    let quantity: i64 = cart_quantity.get().parse().map_err(|_|"Enter a whole quantity of at least 1.")?;
                    if !(1..=1000).contains(&quantity) {return Err("Enter a whole quantity between 1 and 1000.".into());}
                    let mut item=serde_json::json!({"productId":product["id"],"quantity":quantity,"period":period.get()});
                    if let Some(plan)=plan {
                        if pricing.get().is_empty() {return Err("No enabled pricing is available for this plan.".into());}
                        item["planName"]=plan["id"].clone();item["pricingName"]=serde_json::json!(pricing.get());
                    }
                    if recharge {
                        let price: f64=amount.get().parse().map_err(|_|"Select a valid recharge amount.")?;
                        if !price.is_finite() || price<=0.0 {return Err("Select a valid recharge amount.".into());}
                        item["customPrice"]=serde_json::json!(price);
                    }
                    crate::pages::cart::add(app,item).await
                }
            }),
            action(scope,"Open shopping cart",busy,message,move ||async move {app.panel.set("cart-page".into());Ok(String::new())}),
        )).build(scope)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payment_navigation_accepts_only_web_checkout_urls() {
        for value in [
            "javascript:alert(1)",
            "data:text/html,test",
            "//example.test/pay",
            "http://example.test/pay",
            "https://user:secret@example.test/pay",
        ] {
            assert!(payment_url(value).is_err(), "{value}");
        }
        assert!(payment_url("https://checkout.stripe.com/c/pay/test").is_ok());
        assert!(payment_url("http://localhost:18085/pay").is_ok());
    }
}

fn renewal(
    app: AppState,
    subscription: Value,
    busy: Cage<bool>,
    message: Cage<String>,
    revision: Cage<u64>,
) -> Element {
    boxed(widget(move |scope| {
        let consent = scope.cage(false);
        let id = subscription["id"].as_str().unwrap_or_default().to_string();
        let stop = id.clone();
        let enabled = subscription["renewal"]["enabled"] == true;
        let quoted = subscription["renewal_quote"]["amount"].as_f64();
        let quote = quoted
            .filter(|value| value.is_finite() && *value >= 0.0 && *value <= 9_000_000_000_000.0)
            .and_then(|value| {
                let cents = value * 100.0;
                (cents - cents.round())
                    .abs()
                    .le(&0.00001)
                    .then_some(cents.round() as i64)
            });
        let currency = subscription["renewal_quote"]["currency"]
            .as_str()
            .unwrap_or("USD")
            .to_string();
        let title = format!(
            "{} · {} · {} → {}",
            subscription["plan"].as_str().unwrap_or("Subscription"),
            subscription["state"].as_str().unwrap_or(""),
            subscription["start_date"].as_str().unwrap_or(""),
            subscription["end_date"].as_str().unwrap_or("No expiry")
        );
        let cap = subscription["renewal"]["max_amount_cents"]
            .as_i64()
            .map(|value| format!("{:.2}", value as f64 / 100.0))
            .unwrap_or_default();
        let status = if enabled {
            format!(
                "Renewal enabled · {} · limit {cap} {} · {}",
                subscription["renewal"]["mode"].as_str().unwrap_or(""),
                subscription["renewal"]["currency"].as_str().unwrap_or(""),
                subscription["renewal"]["state"]
                    .as_str()
                    .unwrap_or("scheduled")
            )
        } else {
            "Renewal disabled".to_string()
        };
        stack((
            label(&title),label(&status),label(subscription["renewal"]["last_error"].as_str().unwrap_or("")),
            when(scope.bond(move ||!enabled),move ||{
                let id=id.clone();let currency=currency.clone();widget(move |scope| {
                    let id=id.clone();let currency=currency.clone();
                    stack((
                        label(&format!("Current renewal price: {} {currency}",quote.map(|value|format!("{:.2}",value as f64/100.0)).unwrap_or("Unavailable".into()))),
                        label("Balance renewals charge your wallet up to this agreed price each period. Other gateways require you to complete checkout. You can disable future renewals here."),
                        sapid::checkbox().name("I authorize renewal at this price").checked(consent).on_checked_change(move |value|consent.set(value)),
                        action(scope,"Enable renewal",busy,message,move || {let id=id.clone();let currency=currency.clone();async move {
                            if !consent.get() {return Err("Confirm renewal authorization before enabling.".into());}
                            let cap=quote.ok_or("The current plan price is unavailable.")?;
                            app.request("POST",&format!("/api/set-subscription-auto-renew?id={}&autoRenew=true&maxAmountCents={cap}&currency={}",query_component(&id),query_component(&currency)),None).await?;
                            revision.set(revision.get()+1);Ok("Renewal authorization saved.".into())
                        }}),
                    )).build(scope)
                })
            }),
            when(scope.bond(move ||enabled),move ||{let stop=stop.clone();widget(move |scope| {let stop=stop.clone();
                action(scope,"Disable renewal",busy,message,move ||{let id=stop.clone();async move {
                    app.request("POST",&format!("/api/set-subscription-auto-renew?id={}&autoRenew=false",query_component(&id)),None).await?;
                    revision.set(revision.get()+1);Ok("Future renewals disabled.".into())
                }}).build(scope)
            })}),
        )).build(scope)
    }))
}
