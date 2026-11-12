use crate::{AppState, api, ui::*};
use glory::prelude::*;
use serde_json::{Value, json};

pub fn page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        stack((
            heading("Marketplace integrations"),
            when(
                scope.bond(move || {
                    app.token.get().is_none() || !app.account.get().is_some_and(|a| a.is_admin)
                }),
                || label("Sign in as a tenant administrator to manage integrations."),
            ),
            when(
                scope.bond(move || {
                    app.token.get().is_some() && app.account.get().is_some_and(|a| a.is_admin)
                }),
                move || administrator_page(app),
            ),
        ))
        .build(scope)
    }))
}

fn administrator_page(app: AppState) -> Element {
    boxed(widget(move |scope| {
        let owner = scope.cage(
            app.account
                .get()
                .map(|account| account.owner)
                .unwrap_or_default(),
        );
        let name = scope.cage(String::new());
        let catalogue = scope.cage(Vec::<Value>::new());
        let installed = scope.cage(Vec::<Value>::new());
        let selected = scope.cage(Value::Null);
        let bundle = scope.cage(Value::Null);
        let variables = scope.cage(json!({}));
        let busy = scope.cage(false);
        let message = scope.cage(String::new());
        let revision = scope.cage(0u64);
        let preview_revision = scope.cage(0u64);
        let client_id = scope.cage(String::new());
        let client_secret = scope.cage(String::new());
        let application = scope.cage(String::new());
        let tasks = scope.clone();
        scope.effect(move || {
            let _ = revision.get();
            let namespace = owner.get();
            installed.set(Vec::new());
            if namespace.trim().is_empty() {
                return;
            }
            let _ = tasks.spawn(async move {
                let result = app
                    .request(
                        "GET",
                        &format!(
                            "/api/get-integrations?owner={}",
                            query_component(&namespace)
                        ),
                        None,
                    )
                    .await;
                if owner.get() != namespace {
                    return;
                }
                match result {
                    Ok(value) => installed.set(api::extract_collection(value)),
                    Err(error) => message.set(error),
                }
            });
        });
        let choices = each(catalogue)
            .key(|item| item["id"].as_str().unwrap_or_default().to_string())
            .seed(move |item| {
                widget(move |scope| {
                    let item = item.clone();
                    let id = item["id"].as_str().unwrap_or_default().to_string();
                    let title = format!("Preview {}", item["name"]["en"].as_str().unwrap_or(&id));
                    action(scope, &title, busy, message, move || {
                        let item = item.clone();
                        let id = id.clone();
                        async move {
                            let version = item["latest"].as_str().unwrap_or_default();
                            let response = app
                                .request(
                                    "GET",
                                    &format!(
                                        "/api/get-marketplace-bundle?integrationId={}&version={}",
                                        query_component(&id),
                                        query_component(version)
                                    ),
                                    None,
                                )
                                .await?;
                            bundle.set(response["data"].clone());
                            selected.set(item);
                            variables.set(json!({}));
                            client_id.set(String::new());
                            client_secret.set(String::new());
                            application.set(String::new());
                            preview_revision.set(preview_revision.get() + 1);
                            name.set(id);
                            Ok(String::new())
                        }
                    })
                    .build(scope)
                })
            });
        let fields = each(scope.bond(move || {
            let generation = preview_revision.get();
            bundle.get()["manifest"]["variables"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|field| (generation, field))
                .collect::<Vec<_>>()
        }))
        .key(|(generation, field)| {
            (
                *generation,
                field["name"].as_str().unwrap_or_default().to_string(),
            )
        })
        .seed(move |(_, definition)| {
            widget(move |scope| {
                let key = definition["name"].as_str().unwrap_or_default().to_string();
                let title = definition["label"]["en"]
                    .as_str()
                    .or_else(|| definition["label"].as_str())
                    .unwrap_or(&key)
                    .to_string();
                let value = scope.cage(String::new());
                let change = move |next: String| {
                    value.set(next.clone());
                    let mut data = variables.get();
                    data[&key] = json!(next);
                    variables.set(data);
                };
                let input = if definition["type"] == "password" || definition["secret"] == true {
                    boxed(
                        sapid::password_input()
                            .name(title.clone())
                            .value(value)
                            .on_value_change(change),
                    )
                } else {
                    boxed(
                        sapid::text_field()
                            .name(title.clone())
                            .value(value)
                            .on_value_change(change),
                    )
                };
                stack((
                    label(&title),
                    input,
                    label(if definition["required"] == true {
                        "Required"
                    } else {
                        "Optional"
                    }),
                ))
                .build(scope)
            })
        });
        let installed_rows = each(installed)
            .key(|item| format!("{}/{}", item["owner"], item["name"]))
            .seed(move |item| {
                widget(move |scope| {
                    let namespace = item["owner"].as_str().unwrap_or_default().to_string();
                    let instance = item["name"].as_str().unwrap_or_default().to_string();
                    let title = format!("Uninstall {namespace}/{instance}");
                    action(scope, &title, busy, message, move || {
                        let body = json!({"owner":namespace,"name":instance});
                        async move {
                            app.request("POST", "/api/delete-integration", Some(body))
                                .await?;
                            revision.set(revision.get() + 1);
                            Ok("Integration uninstalled.".into())
                        }
                    })
                    .build(scope)
                })
            });
        stack((
            label("Install application, provider and theme templates into your tenant."),
            field(scope, "Integration owner", owner),
            action(
                scope,
                "Load marketplace",
                busy,
                message,
                move || async move {
                    let response = app
                        .request("GET", "/api/get-marketplace-index", None)
                        .await?;
                    catalogue.set(
                        response["data"]["integrations"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default(),
                    );
                    Ok(String::new())
                },
            ),
            choices,
            text().content_fn(move || {
                bundle.get()["manifest"]["description"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            }),
            field(scope, "Installation name", name),
            stack((fields,
            when(scope.bond(move || bundle.get()["manifest"]["type"] == "theme"), move || {
                widget(move |scope| {
                    stack((
                        label("Apply to an existing application. Uninstalling restores its previous theme."),
                        field(scope, "Theme application", application),
                    )).build(scope)
                })
            }))),
            when(scope.bond(move || bundle.get()["manifest"]["type"] == "provider"), move || {
                widget(move |scope| {
                    stack((
                        field(scope, "Provider client ID", client_id),
                        password("Provider client secret", client_secret),
                        field(scope, "Link to application (optional)", application),
                    )).build(scope)
                })
            }),
            action(
                scope,
                "Install integration",
                busy,
                message,
                move || async move {
                    let item = selected.get();
                    let id = item["id"].as_str().ok_or("Preview an integration first.")?;
                    if owner.get().trim().is_empty() || name.get().trim().is_empty() {
                        return Err("Enter an owner and installation name.".into());
                    }
                    if bundle.get()["manifest"]["type"] == "theme" && application.get().trim().is_empty() {
                        return Err("Choose an application for the theme.".into());
                    }
                    if bundle.get()["manifest"]["type"] == "provider" && (client_id.get().trim().is_empty() || client_secret.get().is_empty()) {
                        return Err("Enter the provider client ID and secret.".into());
                    }
                    app.request("POST", "/api/install-integration", Some(json!({
                    "owner":owner.get(), "name":name.get(), "integrationId":id,
                    "version":bundle.get()["manifest"]["version"], "variables":variables.get(),
                    "clientId":client_id.get(), "clientSecret":client_secret.get(), "application":application.get()
                }))).await?;
                    variables.set(json!({}));
                    bundle.set(Value::Null);
                    selected.set(Value::Null);
                    client_id.set(String::new());
                    client_secret.set(String::new());
                    application.set(String::new());
                    revision.set(revision.get() + 1);
                    Ok("Integration installed.".into())
                },
            ),
            heading("Installed integrations"),
            installed_rows,
            notice(message),
        ))
        .build(scope)
    }))
}
